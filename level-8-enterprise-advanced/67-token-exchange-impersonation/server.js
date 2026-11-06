const express = require("express");
const crypto = require("crypto");

const PORT = Number(process.env.PORT) || 3000;
const BASE_URL = `http://localhost:${PORT}`;
const ISSUER = `${BASE_URL}/auth`;
// The names RFC 8693 (OAuth 2.0 Token Exchange) gives to the grant and to "this is an access token"
const TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange";
const ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token";

// shortcut: client secrets in code. A real app loads them from a secrets manager (topic 54)
// and services often prove who they are with mTLS or a signed JWT instead of a secret (topic 68).
const ORDERS_API_SECRET = process.env.ORDERS_API_SECRET || "orders-api-secret-123";
const SUPPORT_CONSOLE_SECRET = process.env.SUPPORT_CONSOLE_SECRET || "support-console-secret-456";

// ---------- Helpers ----------
const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");
const str = (v) => (typeof v === "string" ? v : undefined);
const b64json = (obj) => Buffer.from(JSON.stringify(obj)).toString("base64url");
const now = () => Math.floor(Date.now() / 1000);

// ---------- Signing tokens (RS256 JWTs, topic 18) ----------
// shortcut: a new key pair on every start, so restarting the server kills every token.
// A real authorization server keeps its keys and publishes the public ones at a JWKS URL (topic 66).
const { privateKey, publicKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });

function signJwt(claims, ttlSeconds) {
  const payload = { iss: ISSUER, iat: now(), exp: now() + ttlSeconds, jti: crypto.randomUUID(), ...claims };
  const data = `${b64json({ alg: "RS256", typ: "at+jwt" })}.${b64json(payload)}`;
  return `${data}.${crypto.sign("sha256", Buffer.from(data), privateKey).toString("base64url")}`;
}

// Signature, algorithm, issuer and expiry. The AUDIENCE is checked by whoever uses the token,
// because only they know their own name (topic 27).
function verifyJwt(token) {
  const parts = typeof token === "string" ? token.split(".") : [];
  if (parts.length !== 3) return null;
  try {
    if (JSON.parse(Buffer.from(parts[0], "base64url")).alg !== "RS256") return null; // never let the token pick the algorithm (topic 53)
    const signed = Buffer.from(`${parts[0]}.${parts[1]}`);
    if (!crypto.verify("sha256", signed, publicKey, Buffer.from(parts[2], "base64url"))) return null;
    const claims = JSON.parse(Buffer.from(parts[1], "base64url"));
    if (claims.iss !== ISSUER || typeof claims.exp !== "number" || claims.exp <= now()) return null;
    return claims;
  } catch {
    return null;
  }
}

// The `act` claim can be nested: { sub: "orders-api", act: { sub: "priya@..." } }. Flatten it for logs.
const actorChain = (act) => (act ? [act.sub, ...actorChain(act.act)] : []);

// ---------- "Database" ----------
// shortcut: in-memory Maps, lost on restart. A real app uses database tables.
const users = new Map();   // email -> { email, role, salt, passwordHash }
const orders = new Map();  // id -> { id, owner, item, amount, status }
const charges = [];        // what payments-api has charged
const activity = [];       // the audit log (topic 55): what happened on whose account, done by whom

const DUMMY_SALT = crypto.randomBytes(16);
// shortcut: test accounts with known passwords. A real app has a signup (topic 06).
for (const [email, password, role] of [
  ["rahul@mail.com", "chai-and-code-42", "customer"],
  ["priya@chaicart.in", "support-desk-2026", "support"],
  ["anita@chaicart.in", "admin-only-7788", "admin"],
]) {
  const salt = crypto.randomBytes(16);
  users.set(email, { email, role, salt, passwordHash: crypto.scryptSync(password, salt, 64) });
}
orders.set("ORD-1", { id: "ORD-1", owner: "rahul@mail.com", item: "Assam tea box", amount: 450, status: "unpaid" });
orders.set("ORD-2", { id: "ORD-2", owner: "rahul@mail.com", item: "Darjeeling first flush", amount: 1200, status: "paid" });

function checkPassword(email, password) {
  const user = email ? users.get(email) : undefined;
  // Hash even for unknown emails so the response time doesn't reveal who has an account (topic 51)
  const hash = crypto.scryptSync(password ?? "", user?.salt ?? DUMMY_SALT, 64);
  return user && crypto.timingSafeEqual(hash, user.passwordHash) ? user : null;
}

function logActivity(token, action) {
  const doneBy = token.act ? actorChain(token.act).join(" via ") : token.sub;
  activity.push({ at: new Date().toISOString(), account: token.sub, doneBy, action });
}

// ---------- Clients of the authorization server ----------
// Each client may exchange tokens only for certain audiences and scopes. This table IS the exchange policy.
const clients = new Map([
  // A backend service that calls another API on the user's behalf (delegation down a chain)
  ["orders-api", { secretHash: sha256(ORDERS_API_SECRET), mode: "delegate", ttl: 60, audiences: ["payments-api"], scopes: ["payments:charge"] }],
  // The internal support tool: a staff member acts for a customer (impersonation done right)
  ["support-console", { secretHash: sha256(SUPPORT_CONSOLE_SECRET), mode: "support", ttl: 300, audiences: ["orders-api"], scopes: ["orders:read"] }],
]);

// Clients log in with HTTP Basic (topic 08): Authorization: Basic base64(client_id:secret)
function authenticateClient(req) {
  const m = /^Basic ([A-Za-z0-9+/=]+)$/.exec(req.get("authorization") ?? "");
  if (!m) return null;
  const decoded = Buffer.from(m[1], "base64").toString();
  const i = decoded.indexOf(":");
  const client = i > 0 ? clients.get(decoded.slice(0, i)) : undefined;
  // Compare hashes in constant time so the response time doesn't leak the secret (topic 51)
  const given = Buffer.from(sha256(decoded.slice(i + 1)), "hex");
  const ok = client && crypto.timingSafeEqual(given, Buffer.from(client.secretHash, "hex"));
  return ok ? { id: decoded.slice(0, i), ...client } : null;
}

// What a normal login gives each kind of user: customers use the shop (orders-api), staff use the support console
function loginToken(user, ttlSeconds) {
  const shop = user.role === "customer";
  return signJwt({
    sub: user.email,
    role: user.role,
    aud: shop ? "orders-api" : "support-console",
    scope: shop ? "orders:read orders:write payments:charge" : "support:console",
  }, ttlSeconds);
}

// ---------- App ----------
const app = express();
app.use(express.json({ limit: "10kb" }));
app.use((req, res, next) => {
  res.set("Cache-Control", "no-store"); // responses carry tokens and private data: never cache them
  next();
});

const oauthError = (res, status, error, error_description) => res.status(status).json({ error, error_description });

// ================= Authorization server =================

// shortcut: password login straight to a token, to keep the demo short. A real app uses the
// authorization code flow with PKCE (topic 34); what matters here is what happens AFTER.
app.post("/auth/login", (req, res) => {
  const user = checkPassword(str(req.body?.email)?.trim().toLowerCase(), str(req.body?.password));
  if (!user) return res.status(401).json({ error: "Wrong email or password" });
  res.json({ access_token: loginToken(user, 15 * 60), token_type: "Bearer", expires_in: 15 * 60 });
});

// STEP 2-4: the token exchange endpoint (RFC 8693). OAuth token endpoints take form bodies, not JSON.
app.post("/auth/token", express.urlencoded({ extended: false, limit: "10kb" }), (req, res) => {
  // STEP 2a: WHO is asking? Only registered clients can exchange tokens.
  const client = authenticateClient(req);
  if (!client) {
    res.set("WWW-Authenticate", 'Basic realm="ChaiCart auth"');
    return oauthError(res, 401, "invalid_client", "Unknown client or wrong secret");
  }
  const body = req.body ?? {};
  if (body.grant_type !== TOKEN_EXCHANGE) return oauthError(res, 400, "unsupported_grant_type", `Use grant_type=${TOKEN_EXCHANGE}`);
  if (body.requested_token_type && body.requested_token_type !== ACCESS_TOKEN_TYPE) {
    return oauthError(res, 400, "invalid_request", "Only access tokens can be requested");
  }

  // STEP 2b: FOR WHICH API? A client may only get tokens for the APIs on its list.
  const audience = str(body.audience);
  if (!audience || !client.audiences.includes(audience)) {
    return oauthError(res, 400, "invalid_target", `${client.id} may not get tokens for "${audience ?? ""}"`);
  }
  // STEP 2c: WHICH permissions? Ask for exactly what the next call needs (least privilege).
  const requested = [...new Set((str(body.scope) ?? "").split(" ").filter(Boolean))];
  if (!requested.length) return oauthError(res, 400, "invalid_scope", "Ask for the scopes you need");

  let sub, role, act;
  if (client.mode === "delegate") {
    // STEP 3: DELEGATION down a service chain. orders-api trades the user's token it RECEIVED
    // for a narrower one for payments-api. The user stays `sub`; the service is recorded in `act`.
    if (body.subject_token_type !== ACCESS_TOKEN_TYPE) return oauthError(res, 400, "invalid_request", "subject_token_type must be an access token");
    const subject = verifyJwt(str(body.subject_token));
    if (!subject) return oauthError(res, 400, "invalid_grant", "subject_token is invalid or expired");
    // You can only swap tokens that were sent TO you. Otherwise any service could swap any token it found.
    if (subject.aud !== client.id) return oauthError(res, 400, "invalid_grant", `subject_token was issued for "${subject.aud}", not for ${client.id}`);
    // Never MORE than the user gave, and never more than this client's policy allows. Down-scoping only.
    const have = subject.scope.split(" ");
    const denied = requested.filter((s) => !have.includes(s) || !client.scopes.includes(s));
    if (denied.length) return oauthError(res, 400, "invalid_scope", `Not allowed: ${denied.join(" ")}`);
    sub = subject.sub;
    role = subject.role;
    // Keep the whole chain: if the user's token was already delegated, nest the earlier actor inside
    act = subject.act ? { sub: client.id, act: subject.act } : { sub: client.id };
  } else {
    // STEP 4: SUPPORT "ACT AS". Priya (the actor) gets a token to act for Rahul (the subject).
    // RFC 8693 has no parameter for "the user whose token I don't have"; `requested_subject` is the
    // name Keycloak uses for it. The actor proves who SHE is with her own token.
    if (body.actor_token_type !== ACCESS_TOKEN_TYPE) return oauthError(res, 400, "invalid_request", "actor_token_type must be an access token");
    const actor = verifyJwt(str(body.actor_token));
    if (!actor || actor.aud !== client.id) return oauthError(res, 400, "invalid_grant", `actor_token is invalid, expired or not for ${client.id}`);
    if (actor.role !== "support") return oauthError(res, 403, "access_denied", "Only support staff can act for customers");
    const target = users.get(str(body.requested_subject)?.trim().toLowerCase());
    if (!target) return oauthError(res, 400, "invalid_request", "Unknown requested_subject");
    // No escalation: acting as an admin would give Priya powers she doesn't have herself
    if (target.role !== "customer") return oauthError(res, 403, "access_denied", "Support can act only for customers, never for staff or admins");
    const denied = requested.filter((s) => !client.scopes.includes(s));
    if (denied.length) return oauthError(res, 400, "invalid_scope", `Not allowed: ${denied.join(" ")}`);
    sub = target.email;
    role = target.role;
    act = { sub: actor.sub }; // Priya's name is IN the token, so every API and log knows who really did it
  }

  // STEP 2d: a NEW token: different audience, fewer scopes, short life, and who-acted-for-whom.
  const token = signJwt({ sub, role, aud: audience, scope: requested.join(" "), act, client_id: client.id }, client.ttl);
  console.log(`🔁 Exchange by ${client.id}: sub=${sub} act=${actorChain(act).join(" via ")} aud=${audience} scope="${requested.join(" ")}" ttl=${client.ttl}s`);
  res.json({ access_token: token, issued_token_type: ACCESS_TOKEN_TYPE, token_type: "Bearer", expires_in: client.ttl, scope: requested.join(" ") });
});

// ❌ VULNERABLE "log in as user": a staff member gets the customer's FULL normal token for an hour.
// No `act` claim, so every API and every log thinks the customer did it. It doesn't even block admins.
app.post("/vulnerable/support/login-as", (req, res) => {
  const staff = verifyJwt(/^Bearer (\S+)$/.exec(req.get("authorization") ?? "")?.[1]);
  if (!staff || staff.aud !== "support-console") return res.status(401).json({ error: "Support staff only" });
  if (staff.role === "customer") return res.status(403).json({ error: "Support staff only" });
  const target = users.get(str(req.body?.email)?.trim().toLowerCase());
  if (!target) return res.status(404).json({ error: "No such user" });
  console.log(`⚠️  ${staff.sub} logged in AS ${target.email} (nothing in the token says so)`);
  res.json({ access_token: loginToken(target, 60 * 60), token_type: "Bearer", expires_in: 60 * 60 });
});

// ================= Resource servers (two APIs) =================

// Every API checks: valid signature + not expired, addressed to ME (aud), and has the scope this route needs
const requireToken = (audience, scope) => (req, res, next) => {
  const raw = /^Bearer (\S+)$/.exec(req.get("authorization") ?? "")?.[1];
  const claims = verifyJwt(raw);
  if (!claims) return res.status(401).set("WWW-Authenticate", 'Bearer error="invalid_token"').json({ error: "invalid_token", error_description: "Missing, invalid or expired token" });
  if (claims.aud !== audience) {
    return res.status(401).set("WWW-Authenticate", 'Bearer error="invalid_token"').json({ error: "invalid_token", error_description: `This token is for "${claims.aud}", not for ${audience}` });
  }
  if (!claims.scope.split(" ").includes(scope)) {
    return res.status(403).set("WWW-Authenticate", `Bearer error="insufficient_scope", scope="${scope}"`).json({ error: "insufficient_scope", error_description: `Needs scope ${scope}` });
  }
  req.token = claims;
  req.rawToken = raw;
  next();
};

// ---- orders-api ----
app.get("/orders-api/me", requireToken("orders-api", "orders:read"), (req, res) => {
  const t = req.token;
  res.json({ sub: t.sub, act: t.act ?? null, aud: t.aud, scope: t.scope, expiresIn: t.exp - now() });
});

app.get("/orders-api/orders", requireToken("orders-api", "orders:read"), (req, res) => {
  // Someone ELSE looking at your account is always logged, so the customer can see it later
  if (req.token.act) logActivity(req.token, "viewed your orders");
  res.json([...orders.values()].filter((o) => o.owner === req.token.sub)); // only YOUR orders (topic 31)
});

// STEP 3 in action: orders-api must call payments-api for the user
app.post("/orders-api/orders/:id/pay", requireToken("orders-api", "orders:write"), async (req, res) => {
  const order = orders.get(req.params.id);
  if (!order || order.owner !== req.token.sub) return res.status(404).json({ error: "Order not found" });
  if (order.status !== "unpaid") return res.status(409).json({ error: `Order is ${order.status}` });

  // ❌ Don't forward the user's token (token passthrough): payments-api would get a token meant for us,
  // with ALL the user's scopes. ✅ Exchange it for one made for payments-api with just payments:charge.
  const ex = await fetch(`${BASE_URL}/auth/token`, {
    method: "POST",
    headers: { authorization: `Basic ${Buffer.from(`orders-api:${ORDERS_API_SECRET}`).toString("base64")}` },
    body: new URLSearchParams({
      grant_type: TOKEN_EXCHANGE,
      subject_token: req.rawToken,
      subject_token_type: ACCESS_TOKEN_TYPE,
      audience: "payments-api",
      scope: "payments:charge",
    }),
  });
  const exchanged = await ex.json();
  if (!ex.ok) return res.status(502).json({ error: "Could not get a token for payments-api", details: exchanged });

  const pay = await fetch(`${BASE_URL}/payments-api/charges`, {
    method: "POST",
    headers: { authorization: `Bearer ${exchanged.access_token}`, "content-type": "application/json" },
    body: JSON.stringify({ orderId: order.id, amount: order.amount }),
  });
  const payment = await pay.json();
  if (!pay.ok) return res.status(502).json({ error: "Payment failed", details: payment });

  order.status = "paid";
  logActivity(req.token, `paid ${order.id}`);
  // For learning only: show what was inside the token we sent to payments-api. Never return tokens in real APIs.
  const c = JSON.parse(Buffer.from(exchanged.access_token.split(".")[1], "base64url"));
  res.json({ order, payment, tokenSentToPayments: { sub: c.sub, act: c.act, aud: c.aud, scope: c.scope, expiresIn: c.exp - now() } });
});

app.post("/orders-api/orders/:id/cancel", requireToken("orders-api", "orders:write"), (req, res) => {
  const order = orders.get(req.params.id);
  if (!order || order.owner !== req.token.sub) return res.status(404).json({ error: "Order not found" });
  if (order.status === "cancelled") return res.status(409).json({ error: "Order is already cancelled" });
  order.status = "cancelled";
  logActivity(req.token, `cancelled ${order.id}`);
  res.json({ order });
});

// The customer's own "recent activity" page: what happened on my account and WHO did it
app.get("/orders-api/activity", requireToken("orders-api", "orders:read"), (req, res) => {
  res.json(activity.filter((a) => a.account === req.token.sub).map(({ doneBy, action }) => ({ doneBy, action })));
});

// ---- payments-api ----
app.post("/payments-api/charges", requireToken("payments-api", "payments:charge"), (req, res) => {
  const orderId = str(req.body?.orderId);
  const amount = req.body?.amount;
  if (!orderId || !Number.isInteger(amount) || amount < 1 || amount > 100000) return res.status(400).json({ error: "orderId and amount (₹1 to ₹1,00,000) are required" });
  // The token says BOTH who is paying (sub) and which service asked (act). Both go in the log.
  const charge = { chargeId: `ch_${crypto.randomBytes(6).toString("hex")}`, orderId, amount, chargedTo: req.token.sub, requestedBy: actorChain(req.token.act) };
  charges.push(charge);
  logActivity(req.token, `charged ₹${amount} for ${orderId}`);
  console.log(`💳 payments-api: ₹${amount} charged to ${charge.chargedTo}, requested by ${charge.requestedBy.join(" via ") || "the user directly"}`);
  res.status(201).json(charge);
});

app.use((req, res) => res.status(404).json({ error: "Not found" }));

// Errors (bad JSON, body too big, bugs) come here. Never send the stack trace to the client.
app.use((err, req, res, next) => {
  if (err.type === "entity.parse.failed") return res.status(400).json({ error: "Body must be valid JSON" });
  if (err.type === "entity.too.large") return res.status(413).json({ error: "Request body too large" });
  console.error(err);
  res.status(500).json({ error: "Something went wrong" });
});

// Express 5 passes a listen error (like "port already in use") to this callback instead of crashing
app.listen(PORT, (err) => {
  if (err) throw err;
  console.log(`☕ ChaiCart auth server + orders-api + payments-api on ${BASE_URL}`);
});
