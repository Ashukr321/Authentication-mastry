const express = require("express");
const crypto = require("crypto");

// Two servers in one file:
//   - the API GATEWAY on PORT (the only thing the internet should reach)
//   - the INTERNAL services (orders, payroll) on PORT + 1, "behind" the gateway
const PORT = Number(process.env.PORT) || 3000;
const INTERNAL_PORT = PORT + 1;
const BASE_URL = `http://localhost:${PORT}`;
const INTERNAL_URL = `http://127.0.0.1:${INTERNAL_PORT}`;
const GATEWAY_ISS = "https://gateway.corp.example"; // the "iss" every internal token must carry
const ACCESS_TOKEN_TTL_MS = 15 * 60 * 1000;          // the client's opaque token: 15 min
const INTERNAL_TOKEN_TTL_S = 60;                     // the gateway-to-service token: 60 s
// shortcut: a fixed API key for the MDM (device management) webhook. A real one comes from a secrets manager (topic 54).
const MDM_API_KEY = "mdm-demo-key-2026";

// ---------- "Database" ----------
// shortcut: in-memory Maps, lost on restart. A real app uses database tables (or Redis for tokens).
const users = new Map();        // email -> { email, roles, salt, passwordHash }
const accessTokens = new Map(); // sha256(opaque token) -> { email, deviceId, expiresAt }
// The device inventory, kept up to date by the MDM (Intune, Jamf, Kandji…). The gateway reads it on EVERY request.
const devices = new Map([
  ["rahul-laptop", { owner: "rahul@corp.com", compliant: true, reason: null }],
  ["priya-mbp", { owner: "priya@corp.com", compliant: true, reason: null }],
]);
const orders = new Map([
  ["rahul@corp.com", [{ id: "ORD-101", item: "Laptop stand", amount: "₹1,499" }]],
  ["priya@corp.com", [{ id: "ORD-102", item: "Noise-cancelling headphones", amount: "₹8,990" }]],
]);
const payroll = [{ name: "Rahul", salary: "₹18,00,000" }, { name: "Priya", salary: "₹24,00,000" }];

// ---------- Helpers ----------
const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");
const randomToken = () => crypto.randomBytes(32).toString("base64url");
const str = (v) => (typeof v === "string" ? v : undefined);
const b64json = (obj) => Buffer.from(JSON.stringify(obj)).toString("base64url");
const safeEqual = (a, b) => crypto.timingSafeEqual(Buffer.from(sha256(a)), Buffer.from(sha256(b)));

const DUMMY_SALT = crypto.randomBytes(16);
// shortcut: test accounts with known passwords. In a real company these come from the IdP (topics 57-63).
for (const [email, password, roles] of [
  ["rahul@corp.com", "chai-and-code-42", ["employee"]],
  ["priya@corp.com", "filter-coffee-77", ["employee", "hr"]],
]) {
  const salt = crypto.randomBytes(16);
  users.set(email, { email, roles, salt, passwordHash: crypto.scryptSync(password, salt, 64) });
}

function checkPassword(email, password) {
  const user = email ? users.get(email) : undefined;
  // Hash even for unknown emails so the response time doesn't reveal who has an account (topic 51)
  const hash = crypto.scryptSync(password ?? "", user?.salt ?? DUMMY_SALT, 64);
  return user && crypto.timingSafeEqual(hash, user.passwordHash) ? user : null;
}

// ---------- Internal tokens: signed by the gateway, verified by every service ----------
// Ed25519 is asymmetric: the gateway holds the PRIVATE key (can sign), services only get the PUBLIC key (can verify).
// So a hacked service can check tokens but can never mint one.
// shortcut: the key pair lives in memory and is shared through a variable. Real services fetch the gateway's
// public keys from its JWKS URL and the gateway rotates them (topics 22, 54).
const { privateKey: gatewayPrivateKey, publicKey: gatewayPublicKey } = crypto.generateKeyPairSync("ed25519");

function mintInternalToken(claims) {
  const data = `${b64json({ alg: "EdDSA", typ: "JWT" })}.${b64json(claims)}`;
  return `${data}.${crypto.sign(null, Buffer.from(data), gatewayPrivateKey).toString("base64url")}`;
}

// Returns { claims } or { error }. Every check here is one the SERVICE does itself, it trusts nobody.
function verifyInternalToken(token, expectedAud) {
  const parts = token.split(".");
  if (parts.length !== 3) return { error: "malformed token" };
  let header, claims;
  try {
    header = JSON.parse(Buffer.from(parts[0], "base64url"));
    claims = JSON.parse(Buffer.from(parts[1], "base64url"));
  } catch {
    return { error: "malformed token" };
  }
  if (!claims || typeof claims !== "object") return { error: "malformed token" };
  // Pin the algorithm. Never let the token choose it ("alg": "none", HS256-with-the-public-key, topic 53).
  if (header?.alg !== "EdDSA") return { error: "unexpected alg" };
  let validSig = false;
  try {
    validSig = crypto.verify(null, Buffer.from(`${parts[0]}.${parts[1]}`), gatewayPublicKey, Buffer.from(parts[2], "base64url"));
  } catch {} // a garbage signature can throw instead of returning false
  if (!validSig) return { error: "bad signature" };
  if (claims.iss !== GATEWAY_ISS) return { error: "wrong issuer" };
  // The audience check is what stops a token made for orders-service being replayed at payroll-service
  if (claims.aud !== expectedAud) return { error: `wrong audience (made for ${claims.aud}, this is ${expectedAud})` };
  if (typeof claims.exp !== "number" || claims.exp < Math.floor(Date.now() / 1000)) return { error: "expired" };
  return { claims };
}

// ---------- Shared middleware ----------
const noStore = (req, res, next) => {
  res.set("Cache-Control", "no-store");
  next();
};
const notFound = (req, res) => res.status(404).json({ error: "Not found" });
// Errors (bad JSON, body too big, bugs) come here. Never send the stack trace to the client.
const onError = (err, req, res, next) => {
  if (err.type === "entity.parse.failed") return res.status(400).json({ error: "Body must be valid JSON" });
  if (err.type === "entity.too.large") return res.status(413).json({ error: "Request body too large" });
  console.error(err);
  res.status(500).json({ error: "Something went wrong" });
};

// ============================================================================================
//  API GATEWAY (the Policy Enforcement Point): every request from outside goes through here
// ============================================================================================

// The route table IS the policy: which service, which audience, which role, and whether a managed device is required.
// Least privilege + risk-based: reading your own orders is fine from any device; payroll needs HR AND a healthy laptop.
const ROUTES = new Map([
  ["orders", { path: "/orders", aud: "orders-service", role: "employee", managedDevice: false }],
  ["payroll", { path: "/payroll", aud: "payroll-service", role: "hr", managedDevice: true }],
]);

// Identity headers a client must NEVER be able to set. Only the gateway speaks for "who is this".
const IDENTITY_HEADER = /^x-(user|email|roles?|internal|forwarded-user|auth)/;

function authenticate(req) {
  const m = /^Bearer ([\w-]{20,100})$/.exec(req.get("authorization") ?? "");
  const key = m && sha256(m[1]);
  const t = key && accessTokens.get(key);
  if (!t) return null;
  if (Date.now() > t.expiresAt) {
    accessTokens.delete(key);
    return null;
  }
  return { ...t, user: users.get(t.email) };
}

// Device posture, looked up FRESH on every request: a laptop that went non-compliant five minutes ago is blocked now.
// shortcut: the device id comes from the login body. Real zero trust proves the device with a certificate in its
// TPM / Secure Enclave (mTLS, topic 68) or a signed MDM attestation, so a stolen token can't claim a good laptop.
function devicePosture(email, deviceId) {
  const d = devices.get(deviceId);
  if (!d || d.owner !== email) return { ok: false, reason: "unknown or unmanaged device" };
  if (!d.compliant) return { ok: false, reason: `device not compliant: ${d.reason}` };
  return { ok: true };
}

// One audit line per decision: who, from which device, which route, allowed or not, and why (topic 55)
function audit(decision, rid, req, who, why = "") {
  const icon = decision === "ALLOW" ? "🛡️  ALLOW" : "⛔ DENY ";
  console.log(`${icon} ${req.method} ${req.path} user=${who?.email ?? "-"} device=${who?.deviceId ?? "-"} rid=${rid.slice(0, 8)}${why ? ` reason="${why}"` : ""}`);
}

const gateway = express();
gateway.use(express.json({ limit: "10kb" }));
gateway.use(noStore);

// Login gives the client an OPAQUE token (random bytes, means nothing on its own). Only the gateway can look it up.
// This is the "phantom token" pattern: opaque outside, short-lived signed JWT inside. Revoking it is instant.
gateway.post("/login", (req, res) => {
  const user = checkPassword(str(req.body?.email)?.trim().toLowerCase(), str(req.body?.password));
  if (!user) return res.status(401).json({ error: "Wrong email or password" });
  const deviceId = str(req.body?.deviceId)?.trim();
  if (!deviceId || !/^[\w-]{1,64}$/.test(deviceId)) return res.status(400).json({ error: "deviceId is required" });

  const token = randomToken();
  accessTokens.set(sha256(token), { email: user.email, deviceId, expiresAt: Date.now() + ACCESS_TOKEN_TTL_MS });
  res.json({ access_token: token, token_type: "Bearer", expires_in: ACCESS_TOKEN_TTL_MS / 1000 });
});

gateway.post("/logout", (req, res) => {
  const m = /^Bearer ([\w-]{20,100})$/.exec(req.get("authorization") ?? "");
  if (m) accessTokens.delete(sha256(m[1]));
  res.json({ message: "Logged out: this token is dead at the gateway right now" });
});

// The MDM tells the gateway when a device's health changes (disk encryption off, OS out of date, jailbroken…)
gateway.post("/mdm/devices/:id", (req, res) => {
  if (!safeEqual(req.get("x-mdm-key") ?? "", MDM_API_KEY)) return res.status(401).json({ error: "Bad MDM key" });
  const d = devices.get(req.params.id);
  if (!d) return res.status(404).json({ error: "Unknown device" });
  if (typeof req.body?.compliant !== "boolean") return res.status(400).json({ error: "compliant must be true or false" });
  d.compliant = req.body.compliant;
  d.reason = d.compliant ? null : str(req.body.reason)?.slice(0, 100) || "failed a health check";
  console.log(`📱 MDM: ${req.params.id} is now ${d.compliant ? "compliant ✅" : `NOT compliant ❌ (${d.reason})`}`);
  res.json({ device: req.params.id, compliant: d.compliant, reason: d.reason });
});

// ✅ ZERO TRUST pipeline: verify explicitly, least privilege, assume breach. Runs on EVERY request.
gateway.get("/api/:service", async (req, res) => {
  const rid = crypto.randomUUID(); // a request id that follows the call through every service and log
  res.set("X-Request-Id", rid);
  const route = ROUTES.get(req.params.service);
  if (!route) return notFound(req, res);

  // STEP 1: never trust identity headers from the client. We build the upstream headers from scratch below,
  // so they are dropped anyway; we log them because someone sending X-User is probably probing you.
  const spoofed = Object.keys(req.headers).filter((h) => IDENTITY_HEADER.test(h));
  if (spoofed.length) console.log(`🧹 Ignored client-supplied identity header(s): ${spoofed.join(", ")} (rid=${rid.slice(0, 8)})`);

  // STEP 2: authenticate (who are you?)
  const who = authenticate(req);
  if (!who) {
    audit("DENY", rid, req, null, "no valid access token");
    return res.status(401).json({ error: "Missing, expired or revoked access token", requestId: rid });
  }

  // STEP 3: authorize with identity AND context (are you allowed, from this device, right now?)
  if (!who.user.roles.includes(route.role)) {
    audit("DENY", rid, req, who, `needs role ${route.role}`);
    return res.status(403).json({ error: `This API needs the "${route.role}" role`, requestId: rid });
  }
  if (route.managedDevice) {
    const posture = devicePosture(who.email, who.deviceId);
    if (!posture.ok) {
      audit("DENY", rid, req, who, posture.reason);
      return res.status(403).json({ error: `This API needs a healthy company device (${posture.reason})`, requestId: rid });
    }
  }

  // STEP 4: mint a short-lived token for THIS service only (aud), signed by the gateway
  const now = Math.floor(Date.now() / 1000);
  const internalToken = mintInternalToken({
    iss: GATEWAY_ISS, sub: who.email, aud: route.aud, roles: who.user.roles, device: who.deviceId,
    iat: now, exp: now + INTERNAL_TOKEN_TTL_S, jti: crypto.randomUUID(),
  });

  // STEP 5: forward. Only the headers WE chose go upstream.
  try {
    const upstream = await fetch(INTERNAL_URL + route.path, {
      headers: { authorization: `Bearer ${internalToken}`, "x-request-id": rid },
      signal: AbortSignal.timeout(5000),
    });
    audit("ALLOW", rid, req, who);
    res.status(upstream.status).json(await upstream.json());
  } catch {
    res.status(502).json({ error: "Upstream service unavailable", requestId: rid });
  }
});

// ❌ VULNERABLE "perimeter" gateway: it only checks "logged in", then passes the user's email in X-User
// and leaves authorization to the backend, which believes X-User because "only the gateway can reach us".
gateway.get("/vulnerable/api/:service", async (req, res) => {
  const route = ROUTES.get(req.params.service);
  if (!route) return notFound(req, res);
  const who = authenticate(req);
  if (!who) return res.status(401).json({ error: "Missing, expired or revoked access token" });

  const clientXHeaders = Object.fromEntries(Object.entries(req.headers).filter(([k]) => k.startsWith("x-")));
  try {
    const upstream = await fetch(`${INTERNAL_URL}/legacy${route.path}`, {
      // ❌ BUG: the client's x-* headers are spread AFTER ours, so a client-sent X-User overwrites the real one
      headers: { "x-user": who.email, ...clientXHeaders },
      signal: AbortSignal.timeout(5000),
    });
    res.status(upstream.status).json(await upstream.json());
  } catch {
    res.status(502).json({ error: "Upstream service unavailable" });
  }
});

gateway.use(notFound);
gateway.use(onError);

// ============================================================================================
//  INTERNAL SERVICES: in zero trust, "it came from inside the network" proves nothing
// ============================================================================================
const internal = express();
internal.use(noStore);

// ✅ Every service checks the gateway's token ITSELF: signature, issuer, audience = me, not expired
function requireInternalToken(aud) {
  return (req, res, next) => {
    const m = /^Bearer (\S+)$/.exec(req.get("authorization") ?? "");
    const result = m ? verifyInternalToken(m[1], aud) : { error: "no token" };
    if (result.error) {
      console.log(`🔒 ${aud} rejected a request: ${result.error}`);
      return res.status(401).json({ error: `${aud}: ${result.error}` });
    }
    req.claims = result.claims;
    next();
  };
}

internal.get("/orders", requireInternalToken("orders-service"), (req, res) => {
  const { sub, aud, roles, device, exp } = req.claims;
  res.json({
    service: "orders-service",
    orders: orders.get(sub) ?? [],          // only YOUR orders: the user comes from the verified token
    tokenSeen: { sub, aud, roles, device, expiresIn: `${exp - Math.floor(Date.now() / 1000)}s` },
    requestId: req.get("x-request-id"),
    // DEMO ONLY: hands you the token this service received, so you can play an attacker who has hacked
    // orders-service and tries to reuse the token elsewhere. Never return or log real tokens.
    demoStolenToken: req.get("authorization").slice(7),
  });
});

internal.get("/payroll", requireInternalToken("payroll-service"), (req, res) => {
  // Defense in depth: the service checks the role AGAIN. It doesn't assume the gateway got it right.
  if (!req.claims.roles?.includes("hr")) return res.status(403).json({ error: "payroll-service: HR only" });
  res.json({ service: "payroll-service", viewer: req.claims.sub, payroll });
});

// ❌ VULNERABLE legacy service: "we're behind the firewall, so X-User must be true". No token, no signature.
internal.get("/legacy/payroll", (req, res) => {
  const user = users.get(req.get("x-user") ?? "");
  if (!user?.roles.includes("hr")) return res.status(403).json({ error: "payroll (legacy): HR only" });
  res.json({ service: "payroll-service (legacy)", viewer: user.email, payroll });
});
internal.get("/legacy/orders", (req, res) => {
  const email = req.get("x-user") ?? "";
  res.json({ service: "orders-service (legacy)", viewer: email, orders: orders.get(email) ?? [] });
});

internal.use(notFound);
internal.use(onError);

// Express 5 passes a listen error (like "port already in use") to this callback instead of crashing
gateway.listen(PORT, (err) => {
  if (err) throw err;
  console.log(`🚪 API gateway on ${BASE_URL}`);
});
// shortcut: 127.0.0.1 stands in for "the private network". Calling it directly with curl plays the attacker
// who is already inside (a hacked pod, a stolen VPN account). In production it would also need mTLS (topic 68).
internal.listen(INTERNAL_PORT, "127.0.0.1", (err) => {
  if (err) throw err;
  console.log(`🏢 Internal services (orders, payroll) on ${INTERNAL_URL}`);
});

// Sweep expired access tokens so the Map doesn't grow forever
setInterval(() => {
  const now = Date.now();
  for (const [k, t] of accessTokens) if (now > t.expiresAt) accessTokens.delete(k);
}, 60_000).unref();
