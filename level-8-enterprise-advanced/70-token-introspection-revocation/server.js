const express = require("express");
const crypto = require("crypto");

const PORT = Number(process.env.PORT) || 3000;
const BASE_URL = `http://localhost:${PORT}`;
const ACCESS_TTL_S = 5 * 60;              // access tokens live 5 minutes
const REFRESH_TTL_S = 30 * 24 * 60 * 60;  // refresh tokens live 30 days (or until revoked)

// This one file plays THREE services so you can run everything with one `node server.js`:
//   ChaiPay authorization server (AS)  → /oauth/token, /oauth/introspect, /oauth/revoke
//   Orders API (resource server)       → GET  /api/orders    caches introspection results for 10 s
//   Payments API (resource server)     → POST /api/payments  never caches (money moves here)
// The two APIs really call /oauth/introspect over HTTP, exactly like separate services would.

// ---------- "Database" of the authorization server ----------
// shortcut: in-memory Maps, lost on restart. A real AS uses database tables (and often Redis for token lookups).
const users = new Map();         // email -> { id, email, salt, passwordHash }
const clients = new Map();       // client_id -> { id, secretHash, kind: "app" | "api" }
const grants = new Map();        // grantId -> one login: { sub, username, clientId, scope, aud, refreshHash, refreshExp }
const accessTokens = new Map();  // sha256(access token) -> { jti, grantId, iat, exp }
const refreshTokens = new Map(); // sha256(refresh token) -> grantId

// ---------- Helpers ----------
const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");
const randomToken = () => crypto.randomBytes(32).toString("base64url");
const str = (v) => (typeof v === "string" ? v : undefined);
const nowS = () => Math.floor(Date.now() / 1000);
const short = (token) => sha256(token).slice(0, 8); // harmless label for logs. Never log the real token.

// Each scope belongs to one API. A token's audience (aud) = the APIs its scopes are for.
const SCOPE_AUDIENCE = { "orders:read": "orders-api", "payments:write": "payments-api" };

const DUMMY_SALT = crypto.randomBytes(16);
const DUMMY_SECRET_HASH = Buffer.from(sha256("no-such-client"), "hex");

// shortcut: a test user with a known password. A real app has a signup (topic 06).
{
  const salt = crypto.randomBytes(16);
  users.set("rahul@mail.com", { id: "user_1", email: "rahul@mail.com", salt, passwordHash: crypto.scryptSync("chai-and-code-42", salt, 64) });
}

function checkPassword(email, password) {
  const user = email ? users.get(email) : undefined;
  // Hash even for unknown emails so the response time doesn't reveal who has an account (topic 51)
  const hash = crypto.scryptSync(password ?? "", user?.salt ?? DUMMY_SALT, 64);
  return user && crypto.timingSafeEqual(hash, user.passwordHash) ? user : null;
}

// ---------- Registered clients ----------
// "app" clients get tokens for users and may revoke their own tokens.
// "api" clients are resource servers: they never get user tokens, but they may introspect.
// shortcut: secrets are written here so the demo runs. Real services read them from a vault (topic 54).
const ORDERS_API = { id: "orders-api", secret: "orders-api-secret-456", cacheMs: 10_000, cache: new Map() };
const PAYMENTS_API = { id: "payments-api", secret: "payments-api-secret-321", cacheMs: 0, cache: new Map() };
for (const [id, secret, kind] of [
  ["chai-app", "chai-app-secret-123", "app"],   // Rahul's ChaiPay app (the token owner)
  ["quiz-app", "quiz-app-secret-789", "app"],   // some other registered app
  [ORDERS_API.id, ORDERS_API.secret, "api"],
  [PAYMENTS_API.id, PAYMENTS_API.secret, "api"],
]) {
  // Client secrets are long and random, so a plain sha256 is enough (no scrypt needed)
  clients.set(id, { id, kind, secretHash: Buffer.from(sha256(secret), "hex") });
}

// STEP 1: every /oauth endpoint knows WHO is calling. HTTP Basic with client_id:client_secret ("client_secret_basic").
function authenticateClient(req) {
  const [scheme, b64] = (req.get("authorization") ?? "").split(" ");
  if (scheme !== "Basic" || !b64) return null;
  const decoded = Buffer.from(b64, "base64").toString();
  const i = decoded.indexOf(":");
  if (i < 1) return null;
  const client = clients.get(decoded.slice(0, i));
  // Compare hashes in constant time, and do the compare even for unknown clients (topic 51)
  const ok = crypto.timingSafeEqual(Buffer.from(sha256(decoded.slice(i + 1)), "hex"), client?.secretHash ?? DUMMY_SECRET_HASH);
  return client && ok ? client : null;
}

function requireClient(req, res) {
  const client = authenticateClient(req);
  if (!client) res.set("WWW-Authenticate", 'Basic realm="chaipay"').status(401).json({ error: "invalid_client" });
  return client;
}

function issueAccessToken(grantId) {
  // Opaque token: just random bytes. It means nothing on its own, so an API MUST ask the AS about it.
  // The prefix helps secret scanners (GitHub, gitleaks) spot a leaked token.
  const token = `chai_at_${randomToken()}`;
  const iat = nowS();
  accessTokens.set(sha256(token), { jti: crypto.randomUUID(), grantId, iat, exp: iat + ACCESS_TTL_S });
  return token;
}

// Revoking a grant = the whole login is gone: its refresh token AND every access token made from it.
function revokeGrant(grantId) {
  const g = grants.get(grantId);
  if (!g) return 0;
  grants.delete(grantId);
  refreshTokens.delete(g.refreshHash);
  let ended = 0;
  for (const [k, t] of accessTokens) if (t.grantId === grantId) { accessTokens.delete(k); ended++; }
  return ended;
}

// ---------- App ----------
const app = express();
app.use(express.json({ limit: "10kb" }));
// RFC 6749 / 7662 / 7009 all send form bodies: token=...&token_type_hint=...
app.use(express.urlencoded({ extended: false, limit: "10kb" }));
app.use((req, res, next) => {
  res.set("Cache-Control", "no-store"); // token responses must never be cached by a proxy
  next();
});

// ===================== AUTHORIZATION SERVER =====================

app.post("/oauth/token", (req, res) => {
  const client = requireClient(req, res);
  if (!client) return;
  if (client.kind !== "app") return res.status(400).json({ error: "unauthorized_client" }); // APIs don't log users in

  const grantType = str(req.body?.grant_type);

  // shortcut: the Resource Owner Password grant, removed in OAuth 2.1. A real AS uses
  // authorization code + PKCE (topics 34, 66). It's here only so curl gets tokens in one line.
  if (grantType === "password") {
    const user = checkPassword(str(req.body.username)?.trim().toLowerCase(), str(req.body.password));
    if (!user) return res.status(400).json({ error: "invalid_grant" });
    const scopes = [...new Set((str(req.body.scope) ?? "").split(" ").filter(Boolean))];
    if (!scopes.length || !scopes.every((s) => s in SCOPE_AUDIENCE)) return res.status(400).json({ error: "invalid_scope" });

    const grantId = crypto.randomUUID();
    const refresh = `chai_rt_${randomToken()}`;
    grants.set(grantId, {
      sub: user.id,
      username: user.email,
      clientId: client.id,
      scope: scopes.join(" "),
      aud: [...new Set(scopes.map((s) => SCOPE_AUDIENCE[s]))],
      refreshHash: sha256(refresh),
      refreshExp: nowS() + REFRESH_TTL_S,
    });
    refreshTokens.set(sha256(refresh), grantId);
    return res.json({ access_token: issueAccessToken(grantId), token_type: "Bearer", expires_in: ACCESS_TTL_S, refresh_token: refresh, scope: scopes.join(" ") });
  }

  // shortcut: no refresh-token rotation here, to keep the demo about revocation. Real apps rotate (topic 23).
  if (grantType === "refresh_token") {
    const grantId = refreshTokens.get(sha256(str(req.body.refresh_token) ?? ""));
    const g = grantId && grants.get(grantId);
    if (!g || g.clientId !== client.id || g.refreshExp <= nowS()) return res.status(400).json({ error: "invalid_grant" });
    return res.json({ access_token: issueAccessToken(grantId), token_type: "Bearer", expires_in: ACCESS_TTL_S, scope: g.scope });
  }

  res.status(400).json({ error: "unsupported_grant_type" });
});

// STEP 2: TOKEN INTROSPECTION (RFC 7662). An API sends a token, the AS answers "active or not, and what's in it".
app.post("/oauth/introspect", (req, res) => {
  // The caller MUST authenticate. Otherwise anyone could use this endpoint to test stolen or guessed tokens.
  const caller = requireClient(req, res);
  if (!caller) return;
  if (caller.kind !== "api") return res.status(403).json({ error: "Only resource servers may introspect tokens" });

  const token = str(req.body?.token);
  if (!token) return res.status(400).json({ error: "invalid_request" });

  // token_type_hint is only a hint about which table to search first. We only introspect access tokens:
  // a refresh token is never sent to an API, so for anything else the answer is simply "not active".
  const t = accessTokens.get(sha256(token));
  const g = t && grants.get(t.grantId);
  const reason = !t ? "unknown or revoked" : !g ? "login revoked" : t.exp <= nowS() ? "expired" : !g.aud.includes(caller.id) ? `not meant for ${caller.id}` : null;

  if (reason) {
    // The reason stays in OUR log. The caller only ever hears {"active":false}: no hints for an attacker.
    console.log(`🔎 introspect by ${caller.id}: token ${short(token)} inactive (${reason})`);
    return res.json({ active: false });
  }
  console.log(`🔎 introspect by ${caller.id}: token ${short(token)} active`);
  res.json({
    active: true,
    scope: g.scope,
    client_id: g.clientId,
    username: g.username,
    token_type: "Bearer",
    exp: t.exp,
    iat: t.iat,
    sub: g.sub,
    aud: g.aud,
    iss: BASE_URL,
    jti: t.jti,
  });
});

// STEP 3: TOKEN REVOCATION (RFC 7009). The app says "I'm done with this token" (logout, uninstall, lost phone).
app.post("/oauth/revoke", (req, res) => {
  const client = requireClient(req, res);
  if (!client) return;
  const token = str(req.body?.token);
  if (!token) return res.status(400).json({ error: "invalid_request" });

  // Search both tables whatever token_type_hint says: a wrong hint must still work.
  const key = sha256(token);
  const at = accessTokens.get(key);
  const grantId = refreshTokens.get(key) ?? at?.grantId;
  const owner = grantId && grants.get(grantId)?.clientId;

  // A client may only revoke tokens issued TO IT. Otherwise quiz-app could log Rahul out of chai-app.
  if (owner && owner !== client.id) return res.status(400).json({ error: "unauthorized_client" });

  if (refreshTokens.has(key)) {
    // Refresh token revoked → the whole login ends: its access tokens die too (RFC 7009 says the AS SHOULD).
    const ended = revokeGrant(grantId);
    console.log(`🗑️  ${client.id} revoked refresh token ${short(token)}: login ended, ${ended} access token(s) with it`);
  } else if (at) {
    accessTokens.delete(key); // just this one access token. The refresh token keeps working.
    console.log(`🗑️  ${client.id} revoked access token ${short(token)}`);
  }
  // 200 even for an unknown or already-revoked token: the goal ("this token doesn't work") is reached,
  // and an attacker can't use this endpoint to learn which tokens exist.
  res.status(200).end();
});

// ===================== RESOURCE SERVERS (the APIs) =====================

async function introspect(token, api) {
  const r = await fetch(`${BASE_URL}/oauth/introspect`, {
    method: "POST",
    headers: {
      Authorization: `Basic ${Buffer.from(`${api.id}:${api.secret}`).toString("base64")}`,
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: new URLSearchParams({ token, token_type_hint: "access_token" }),
    signal: AbortSignal.timeout(2000), // a slow AS must not hang every API request
  });
  if (!r.ok) throw new Error(`introspection answered HTTP ${r.status}`);
  return r.json();
}

// STEP 4: the API's middleware. Bearer token in → introspect (or use the cache) → check active + scope.
function requireToken(api, scope) {
  return async (req, res, next) => {
    const m = /^Bearer (\S+)$/.exec(req.get("authorization") ?? "");
    if (!m) return res.set("WWW-Authenticate", `Bearer realm="${api.id}"`).status(401).json({ error: "Missing bearer token" });

    const key = sha256(m[1]);
    let info;
    let checkedBy = "cache";
    const hit = api.cache.get(key);
    if (hit && hit.until > Date.now()) {
      info = hit.info; // ⚠️ no call to the AS: a token revoked in the last few seconds still works here
    } else {
      checkedBy = "auth server";
      try {
        info = await introspect(m[1], api);
      } catch (err) {
        // FAIL CLOSED: if we can't ask, the answer is "no". Never "let it through, the AS is down".
        console.error(`⚠️  ${api.id}: ${err.message}`);
        return res.status(503).json({ error: "Can't check your token right now, try again" });
      }
      // Cache only "active" answers, and never past the token's own expiry
      if (info.active && api.cacheMs) api.cache.set(key, { info, until: Math.min(Date.now() + api.cacheMs, info.exp * 1000) });
    }

    if (!info.active) return res.set("WWW-Authenticate", 'Bearer error="invalid_token"').status(401).json({ error: "Token is not active" });
    if (!info.scope.split(" ").includes(scope)) {
      return res.set("WWW-Authenticate", `Bearer error="insufficient_scope", scope="${scope}"`).status(403).json({ error: `Needs scope ${scope}` });
    }
    req.token = info;
    req.checkedBy = checkedBy;
    next();
  };
}

// Orders: read-only, low risk → a 10 s cache saves a network call on every request.
app.get("/api/orders", requireToken(ORDERS_API, "orders:read"), (req, res) => {
  res.json({ api: "orders-api", user: req.token.username, orders: ["Masala chai x2 (₹40)", "Samosa x3 (₹45)"], checkedBy: req.checkedBy });
});

// Payments: moves money → asks the AS EVERY time, so a revoked token stops working at once.
app.post("/api/payments", requireToken(PAYMENTS_API, "payments:write"), (req, res) => {
  res.json({ api: "payments-api", user: req.token.username, message: "Paid ₹120 to Sharma Tea Stall", checkedBy: req.checkedBy });
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
  console.log(`🔐 ChaiPay auth server + Orders API + Payments API on ${BASE_URL}`);
});

// Sweep expired tokens, logins and cache entries so the Maps don't grow forever
setInterval(() => {
  const now = nowS();
  for (const [k, t] of accessTokens) if (t.exp <= now) accessTokens.delete(k);
  for (const [id, g] of grants) if (g.refreshExp <= now) revokeGrant(id);
  for (const api of [ORDERS_API, PAYMENTS_API]) for (const [k, c] of api.cache) if (c.until <= Date.now()) api.cache.delete(k);
}, 60_000).unref();
