const express = require("express");
const crypto = require("crypto");
const assert = require("assert");
const jwt = require("jsonwebtoken");

const PORT = Number(process.env.PORT) || 3000;
// The resource server (the API that USES our tokens) runs from this same file on the next port
const API_PORT = PORT + 1;
// The issuer is our own fixed URL. It goes into every token and the discovery document, so it never comes from the Host header.
const ISSUER = `http://localhost:${PORT}`;
const API_URL = `http://localhost:${API_PORT}`;
const API_AUDIENCE = "chaicart-api";
const USERINFO_AUDIENCE = `${ISSUER}/userinfo`;
const ACCESS_TTL = 10 * 60; // seconds. Short: a JWT access token can't be recalled once issued.
const CODE_TTL_MS = 60 * 1000; // an authorization code lives for 1 minute and works once
const REFRESH_TTL_MS = 30 * 24 * 60 * 60 * 1000;

// ---------- Signing key (step 1) ----------
// We sign with the PRIVATE key. APIs verify with the PUBLIC key from /jwks.json, so they never hold anything that can sign.
// shortcut: a new key pair on every start. A real AS keeps keys in a KMS/HSM and rotates them by kid (topic 54).
const { privateKey: PRIVATE_KEY, publicKey: PUBLIC_KEY } = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
const KID = "chaicart-2026-11";

// ---------- Registered clients (step 2) ----------
// Every app that may ask for tokens is registered here first. Nobody can just show up with a random client_id.
const REPORTS_JOB_SECRET = "rj_s3cr3t_8f2b1c9d4e7a6"; // test value. A real AS shows it once at registration and stores only the hash.
const sha256 = (s) => crypto.createHash("sha256").update(s).digest("base64url");
const clients = new Map([
  ["chaicart-spa", {
    id: "chaicart-spa", name: "ChaiCart Web", type: "public", // a browser app can't keep a secret, so PKCE protects it
    redirectUris: ["http://localhost:5173/callback"], // exact strings. No wildcards, no "starts with".
    grants: ["authorization_code", "refresh_token"],
    scopes: ["openid", "profile", "email", "orders:read", "offline_access"],
  }],
  ["reports-job", {
    id: "reports-job", name: "Nightly reports job", type: "confidential", // a backend: it CAN keep a secret
    secretHash: sha256(REPORTS_JOB_SECRET), // sha256 is fine for a long random secret (it's not a human password)
    redirectUris: [], grants: ["client_credentials"], scopes: ["orders:read"],
  }],
]);
const SCOPE_TEXT = {
  openid: "Know who you are", profile: "See your name", email: "See your email address",
  "orders:read": "See your ChaiCart orders", offline_access: "Stay signed in (refresh token)",
};

// ---------- "Database" ----------
// shortcut: in-memory Maps, lost on restart. A real AS uses tables (users, clients, codes, refresh_tokens) and a cleanup job.
const users = new Map(); // email -> { id, email, name, salt, passwordHash }
for (const [id, email, name, password] of [["u_1", "rahul@mail.com", "Rahul Sharma", "rahul-pass-123"], ["u_2", "priya@mail.com", "Priya Nair", "priya-pass-456"]]) {
  const salt = crypto.randomBytes(16);
  users.set(email, { id, email, name, salt, passwordHash: crypto.scryptSync(password, salt, 64) });
}
const userById = (id) => [...users.values()].find((u) => u.id === id);
const DUMMY_SALT = crypto.randomBytes(16);
const codes = new Map(); // sha256(code) -> { clientId, userId, redirectUri, scopes, codeChallenge, nonce, authTime, expiresAt, used, familyId }
const refreshTokens = new Map(); // sha256(refresh token) -> { familyId, clientId, userId, scopes, authTime, expiresAt, used }
const revokedFamilies = new Set(); // familyId of every refresh-token chain we killed (topic 23)
const orders = [
  { id: "ord_101", userId: "u_1", item: "Assam chai 500g", total: "₹240" },
  { id: "ord_102", userId: "u_1", item: "Masala chai 250g", total: "₹180" },
  { id: "ord_201", userId: "u_2", item: "Darjeeling green 100g", total: "₹320" },
];

// ---------- Helpers ----------
const str = (v) => (typeof v === "string" ? v : undefined); // repeated params (?state=a&state=b) arrive as arrays: treat as missing
const newSecret = () => crypto.randomBytes(32).toString("base64url");
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
const safeEqual = (a, b) => { const x = Buffer.from(a), y = Buffer.from(b); return x.length === y.length && crypto.timingSafeEqual(x, y); };
const bearer = (req) => req.get("authorization")?.match(/^Bearer (\S+)$/)?.[1];
const oauthError = (res, status, error, description) => res.status(status).json({ error, error_description: description });

function checkPassword(email, password) {
  const user = users.get(str(email)?.trim().toLowerCase() ?? "");
  // Hash even for unknown emails so the response time doesn't reveal who has an account (topic 51)
  const hash = crypto.scryptSync(str(password) ?? "", user?.salt ?? DUMMY_SALT, 64);
  return user && crypto.timingSafeEqual(hash, user.passwordHash) ? user : null;
}

// ======================================================================
// THE AUTHORIZATION SERVER ("ChaiCart ID")
// ======================================================================
const app = express();
app.use(express.json({ limit: "10kb" }));
app.use(express.urlencoded({ extended: false, limit: "10kb" })); // OAuth forms and /token use application/x-www-form-urlencoded
app.use((req, res, next) => {
  res.set("Cache-Control", "no-store"); // tokens and codes must never sit in a cache
  // The login/consent page must not be framed by another site, or it can trick Rahul into clicking "Allow" (clickjacking)
  res.set("X-Frame-Options", "DENY").set("Content-Security-Policy", "frame-ancestors 'none'");
  next();
});

// ---------- Step 3: discovery + JWKS. Clients and APIs configure themselves from these two URLs. ----------
app.get("/.well-known/openid-configuration", (req, res) => res.json({
  issuer: ISSUER,
  authorization_endpoint: `${ISSUER}/authorize`,
  token_endpoint: `${ISSUER}/token`,
  userinfo_endpoint: `${ISSUER}/userinfo`,
  revocation_endpoint: `${ISSUER}/revoke`,
  jwks_uri: `${ISSUER}/jwks.json`,
  response_types_supported: ["code"],
  grant_types_supported: ["authorization_code", "refresh_token", "client_credentials"],
  code_challenge_methods_supported: ["S256"],
  scopes_supported: Object.keys(SCOPE_TEXT),
  token_endpoint_auth_methods_supported: ["client_secret_basic", "none"],
  subject_types_supported: ["public"],
  id_token_signing_alg_values_supported: ["RS256"],
  authorization_response_iss_parameter_supported: true,
}));
app.get("/jwks.json", (req, res) => {
  res.json({ keys: [{ ...PUBLIC_KEY.export({ format: "jwk" }), kid: KID, alg: "RS256", use: "sig" }] });
});

// ---------- Step 4: /authorize checks the request ----------
const AUTHZ_PARAMS = ["response_type", "client_id", "redirect_uri", "scope", "state", "nonce", "code_challenge", "code_challenge_method"];

function checkAuthorizeRequest(q) {
  const client = clients.get(str(q.client_id));
  // These two are shown on OUR page and never redirected: until redirect_uri is verified, redirecting is an open redirect.
  if (!client || !client.grants.includes("authorization_code")) return { fatal: "Unknown client_id" };
  if (!client.redirectUris.includes(str(q.redirect_uri))) return { fatal: "redirect_uri is not registered for this client" };
  // From here on the redirect_uri is trusted, so errors go back to the app as ?error=…
  const fail = (error, description) => ({ client, error, description });
  if (q.response_type !== "code") return fail("unsupported_response_type", "Only response_type=code is supported");
  if (q.code_challenge_method !== "S256" || !/^[A-Za-z0-9_-]{43}$/.test(str(q.code_challenge) ?? "")) {
    return fail("invalid_request", "PKCE is required: code_challenge with code_challenge_method=S256");
  }
  const scopes = (str(q.scope) ?? "").split(" ").filter(Boolean);
  if (!scopes.length || scopes.some((s) => !client.scopes.includes(s))) return fail("invalid_scope", `Allowed scopes: ${client.scopes.join(" ")}`);
  return { client, scopes };
}

function redirectTo(res, uri, params) {
  const url = new URL(uri);
  for (const [k, v] of Object.entries(params)) if (v !== undefined) url.searchParams.set(k, v);
  res.redirect(302, url.href);
}

function loginPage(q, client, scopes, error) {
  const hidden = AUTHZ_PARAMS.filter((k) => str(q[k]) !== undefined)
    .map((k) => `<input type="hidden" name="${k}" value="${esc(q[k])}">`).join("\n  ");
  // Every value from the URL is escaped: the authorize page is a classic XSS target (topic 48)
  return `<!doctype html><meta charset="utf-8"><title>Sign in to ChaiCart ID</title>
<h1>Sign in to ChaiCart ID</h1>
${error ? `<p style="color:#b91c1c">${esc(error)}</p>` : ""}
<form method="post" action="/authorize">
  ${hidden}
  <label>Email <input name="email" type="email" required autocomplete="username"></label><br>
  <label>Password <input name="password" type="password" required autocomplete="current-password"></label>
  <p><b>${esc(client.name)}</b> wants to:</p>
  <ul>${scopes.map((s) => `<li>${esc(SCOPE_TEXT[s])}</li>`).join("")}</ul>
  <button name="decision" value="allow">Allow</button>
  <button name="decision" value="deny" formnovalidate>Deny</button>
</form>\n`;
}

// Step 4a: the app sends the browser here. We show OUR login page: the app never sees the password.
app.get("/authorize", (req, res) => {
  const check = checkAuthorizeRequest(req.query);
  if (check.fatal) return res.status(400).type("html").send(`<h1>Invalid request</h1><p>${esc(check.fatal)}</p>\n`);
  if (check.error) return redirectTo(res, req.query.redirect_uri, { error: check.error, error_description: check.description, state: str(req.query.state), iss: ISSUER });
  res.type("html").send(loginPage(req.query, check.client, check.scopes));
});

// Step 4b + 5: the login/consent form posts back here. Same checks again: the hidden fields came from the browser.
// shortcut: no AS login session, so every app asks for the password again. A real AS sets its own session cookie here: that's SSO (topic 57).
app.post("/authorize", (req, res) => {
  const q = req.body ?? {};
  const check = checkAuthorizeRequest(q);
  if (check.fatal) return res.status(400).type("html").send(`<h1>Invalid request</h1><p>${esc(check.fatal)}</p>\n`);
  const back = (params) => redirectTo(res, q.redirect_uri, { ...params, state: str(q.state), iss: ISSUER }); // iss defends against mix-up attacks (RFC 9207)
  if (check.error) return back({ error: check.error, error_description: check.description });
  if (q.decision !== "allow") return back({ error: "access_denied", error_description: "The user said no" });

  const user = checkPassword(q.email, q.password);
  if (!user) return res.status(401).type("html").send(loginPage(q, check.client, check.scopes, "Wrong email or password"));

  // Step 5: a one-time code. We store only its hash, plus everything /token must check later.
  const code = newSecret();
  codes.set(sha256(code), {
    clientId: check.client.id, userId: user.id, redirectUri: q.redirect_uri, scopes: check.scopes,
    codeChallenge: q.code_challenge, nonce: str(q.nonce), authTime: Math.floor(Date.now() / 1000),
    expiresAt: Date.now() + CODE_TTL_MS, used: false, familyId: null,
  });
  console.log(`🎫 Code issued to ${check.client.id} for ${user.email} (scopes: ${check.scopes.join(" ")})`);
  back({ code });
});

// ---------- Step 6: /token ----------
// Who is calling? Confidential clients prove it with their secret (HTTP Basic). Public clients only name themselves: PKCE is their proof.
function authenticateClient(req) {
  const basic = req.get("authorization")?.match(/^Basic (\S+)$/)?.[1];
  if (basic) {
    // shortcut: the spec says id and secret are form-urlencoded inside Basic. Ours have no special characters, so we skip decoding.
    const raw = Buffer.from(basic, "base64").toString("utf8");
    const i = raw.indexOf(":");
    const client = i > 0 ? clients.get(raw.slice(0, i)) : undefined;
    return client?.type === "confidential" && safeEqual(sha256(raw.slice(i + 1)), client.secretHash) ? client : null;
  }
  const client = clients.get(str(req.body?.client_id));
  return client?.type === "public" ? client : null; // a confidential client MUST send its secret
}

function issueTokens({ client, user, scopes, nonce, authTime, familyId }) {
  const sign = (claims, options) => jwt.sign(claims, PRIVATE_KEY, { algorithm: "RS256", keyid: KID, issuer: ISSUER, expiresIn: ACCESS_TTL, ...options });
  const out = { token_type: "Bearer", expires_in: ACCESS_TTL, scope: scopes.join(" ") };

  // Access token: for the API. aud says WHICH API. typ "at+jwt" (RFC 9068) so an ID token can't be passed off as one.
  out.access_token = sign({ scope: scopes.join(" "), client_id: client.id }, {
    header: { typ: "at+jwt" }, subject: user?.id ?? client.id, jwtid: crypto.randomUUID(),
    audience: scopes.includes("openid") ? [API_AUDIENCE, USERINFO_AUDIENCE] : API_AUDIENCE,
  });

  // ID token (OIDC, topic 36): for the APP, to know who logged in. aud = the client, and it carries the app's nonce back.
  if (user && scopes.includes("openid")) {
    out.id_token = sign({
      nonce, auth_time: authTime,
      ...(scopes.includes("profile") && { name: user.name }),
      ...(scopes.includes("email") && { email: user.email, email_verified: true }),
    }, { audience: client.id, subject: user.id });
  }

  // Refresh token: opaque random string, only if the user agreed to offline_access. Stored hashed, rotated on every use.
  if (user && scopes.includes("offline_access") && client.grants.includes("refresh_token")) {
    out.refresh_token = newSecret();
    refreshTokens.set(sha256(out.refresh_token), {
      familyId, clientId: client.id, userId: user.id, scopes, authTime, expiresAt: Date.now() + REFRESH_TTL_MS, used: false,
    });
  }
  return out;
}

app.post("/token", (req, res) => {
  const client = authenticateClient(req);
  if (!client) {
    res.set("WWW-Authenticate", 'Basic realm="ChaiCart ID"');
    return oauthError(res, 401, "invalid_client", "Client authentication failed");
  }
  const grant = str(req.body?.grant_type);
  if (!client.grants.includes(grant)) return oauthError(res, 400, "unauthorized_client", `${client.id} may not use grant_type=${grant}`);

  if (grant === "authorization_code") {
    const hash = sha256(str(req.body.code) ?? "");
    const rec = codes.get(hash);
    if (!rec || rec.expiresAt < Date.now()) return oauthError(res, 400, "invalid_grant", "Code is invalid or expired");
    if (rec.used) {
      // A used code came back: someone stole it. Kill every token that was issued from it (RFC 6749 section 4.1.2).
      revokedFamilies.add(rec.familyId);
      console.log(`🚨 Code replay for ${rec.clientId}: refresh-token family ${rec.familyId} revoked`);
      return oauthError(res, 400, "invalid_grant", "Code was already used");
    }
    if (rec.clientId !== client.id) return oauthError(res, 400, "invalid_grant", "Code was issued to another client");
    if (rec.redirectUri !== req.body.redirect_uri) return oauthError(res, 400, "invalid_grant", "redirect_uri does not match");
    // PKCE: only the app that started the login knows the verifier. A stolen code alone is useless.
    if (!safeEqual(sha256(str(req.body.code_verifier) ?? ""), rec.codeChallenge)) return oauthError(res, 400, "invalid_grant", "PKCE verification failed");

    rec.used = true;
    rec.familyId = crypto.randomUUID();
    console.log(`🔑 Tokens issued to ${client.id} for ${rec.userId} (code exchanged)`);
    return res.json(issueTokens({ client, user: userById(rec.userId), scopes: rec.scopes, nonce: rec.nonce, authTime: rec.authTime, familyId: rec.familyId }));
  }

  if (grant === "refresh_token") {
    const rec = refreshTokens.get(sha256(str(req.body.refresh_token) ?? ""));
    if (!rec || rec.clientId !== client.id || rec.expiresAt < Date.now() || revokedFamilies.has(rec.familyId)) {
      return oauthError(res, 400, "invalid_grant", "Refresh token is invalid, expired or revoked");
    }
    if (rec.used) {
      // Rotation + reuse detection (topic 23): an old refresh token came back, so either the thief or Rahul has a copy. Kill the chain.
      revokedFamilies.add(rec.familyId);
      console.log(`🚨 Refresh token reuse for ${rec.userId}: family ${rec.familyId} revoked`);
      return oauthError(res, 400, "invalid_grant", "Refresh token was already used");
    }
    rec.used = true;
    return res.json(issueTokens({ client, user: userById(rec.userId), scopes: rec.scopes, authTime: rec.authTime, familyId: rec.familyId }));
  }

  // client_credentials: a machine asking for itself. No user, so no ID token and no refresh token (it can just ask again).
  const scopes = str(req.body.scope)?.split(" ").filter(Boolean) ?? client.scopes;
  if (!scopes.length || scopes.some((s) => !client.scopes.includes(s))) return oauthError(res, 400, "invalid_scope", `Allowed scopes: ${client.scopes.join(" ")}`);
  console.log(`🤖 Machine token issued to ${client.id}`);
  res.json(issueTokens({ client, user: null, scopes }));
});

// ---------- Step 7: /revoke (RFC 7009), used by the app on logout ----------
app.post("/revoke", (req, res) => {
  const client = authenticateClient(req);
  if (!client) return oauthError(res, 401, "invalid_client", "Client authentication failed");
  const rec = refreshTokens.get(sha256(str(req.body?.token) ?? ""));
  if (rec?.clientId === client.id) revokedFamilies.add(rec.familyId);
  res.status(200).end(); // always 200, even for unknown tokens: don't tell a caller which tokens exist
});

// ---------- /userinfo (OIDC): the AS is also a small API that only accepts its own access tokens ----------
app.get("/userinfo", (req, res) => {
  try {
    const claims = jwt.verify(bearer(req) ?? "", PUBLIC_KEY, { algorithms: ["RS256"], issuer: ISSUER, audience: USERINFO_AUDIENCE });
    const scopes = claims.scope.split(" ");
    const user = userById(claims.sub);
    if (!user || !scopes.includes("openid")) throw new Error("not a user token with openid scope");
    res.json({
      sub: user.id,
      ...(scopes.includes("profile") && { name: user.name }),
      ...(scopes.includes("email") && { email: user.email, email_verified: true }),
    });
  } catch {
    res.set("WWW-Authenticate", 'Bearer error="invalid_token"').status(401).json({ error: "invalid_token" });
  }
});

// ======================================================================
// THE RESOURCE SERVER ("ChaiCart Orders API"): trusts tokens only because it can check them with the AS's PUBLIC key
// ======================================================================
const api = express();
api.use((req, res, next) => { res.set("Cache-Control", "no-store"); next(); });

// shortcut: fetched once and cached forever. A real API refetches when it sees an unknown kid (key rotation, topic 54), or uses jose's createRemoteJWKSet.
let jwksCache;
async function getKeys() {
  if (!jwksCache) {
    const conf = await (await fetch(`${ISSUER}/.well-known/openid-configuration`)).json();
    jwksCache = (await (await fetch(conf.jwks_uri)).json()).keys;
  }
  return jwksCache;
}

const requireScope = (scope) => async (req, res, next) => {
  const deny = (status, error, description) => {
    res.set("WWW-Authenticate", `Bearer error="${error}"${error === "insufficient_scope" ? `, scope="${scope}"` : ""}`);
    return res.status(status).json({ error, error_description: description });
  };
  const token = bearer(req);
  if (!token) return deny(401, "invalid_token", "Missing Bearer token");
  try {
    const { header } = jwt.decode(token, { complete: true }) ?? {};
    // kid picks one of the ISSUER's keys (never a URL from the token, topic 53). typ must be at+jwt: an ID token is not an access token.
    const jwk = (await getKeys()).find((k) => k.kid === header?.kid);
    if (!jwk) throw new Error(`unknown kid "${header?.kid}"`);
    if (header.typ !== "at+jwt") throw new Error(`typ is "${header.typ}", expected at+jwt`);
    req.auth = jwt.verify(token, crypto.createPublicKey({ key: jwk, format: "jwk" }), { algorithms: ["RS256"], issuer: ISSUER, audience: API_AUDIENCE });
  } catch (err) {
    console.log(`❌ API rejected a token: ${err.message}`);
    return deny(401, "invalid_token", err.message); // shortcut: the reason is shown for learning. Production sends only the error code.
  }
  if (!req.auth.scope.split(" ").includes(scope)) return deny(403, "insufficient_scope", `Needs scope ${scope}`);
  next();
};

api.get("/orders", requireScope("orders:read"), (req, res) => {
  // sub is a user id for user tokens, and the client id for machine tokens (client_credentials)
  const isMachine = req.auth.sub === req.auth.client_id;
  res.json({
    caller: isMachine ? `client ${req.auth.client_id}` : `user ${req.auth.sub} via ${req.auth.client_id}`,
    orders: isMachine ? orders : orders.filter((o) => o.userId === req.auth.sub),
  });
});

// ---------- 404 + error handlers for both servers ----------
for (const server of [app, api]) {
  server.use((req, res) => res.status(404).json({ error: "Not found" }));
  // Errors (bad JSON, body too big, bugs) come here. Never send the stack trace to the client.
  server.use((err, req, res, next) => {
    if (err.type === "entity.parse.failed") return res.status(400).json({ error: "Body must be valid JSON" });
    if (err.type === "entity.too.large") return res.status(413).json({ error: "Request body too large" });
    console.error(err);
    res.status(500).json({ error: "Something went wrong" });
  });
}

// ---------- Self-check: the full flow, plus the attacks each check exists for ----------
async function selfCheck() {
  const form = (url, body, headers = {}) => fetch(url, {
    method: "POST", redirect: "manual", body: new URLSearchParams(body),
    headers: { "Content-Type": "application/x-www-form-urlencoded", ...headers },
  });
  const REDIRECT = "http://localhost:5173/callback";
  const login = async (extra = {}) => {
    const verifier = newSecret();
    const res = await form(`${ISSUER}/authorize`, {
      response_type: "code", client_id: "chaicart-spa", redirect_uri: REDIRECT, scope: "openid profile email orders:read offline_access",
      state: "s1", nonce: "n1", code_challenge: sha256(verifier), code_challenge_method: "S256",
      email: "rahul@mail.com", password: "rahul-pass-123", decision: "allow", ...extra,
    });
    return { res, verifier, code: new URL(res.headers.get("location") ?? "http://x").searchParams.get("code") };
  };
  const exchange = async (code, verifier) => (await form(`${ISSUER}/token`, { grant_type: "authorization_code", client_id: "chaicart-spa", redirect_uri: REDIRECT, code, code_verifier: verifier })).json();
  const refresh = async (token) => (await form(`${ISSUER}/token`, { grant_type: "refresh_token", client_id: "chaicart-spa", refresh_token: token })).json();
  const orders = async (token) => (await fetch(`${API_URL}/orders`, { headers: { Authorization: `Bearer ${token}` } })).status;

  const { code, verifier } = await login();
  assert(code, "login should redirect with a code");
  assert.equal((await exchange(code, newSecret())).error, "invalid_grant", "wrong PKCE verifier must fail");
  const tokens = await exchange(code, verifier);
  assert(tokens.access_token && tokens.id_token && tokens.refresh_token, "code + verifier should give all three tokens");
  assert.equal(jwt.decode(tokens.id_token).nonce, "n1", "ID token carries the nonce");
  assert.equal(await orders(tokens.access_token), 200, "API accepts the access token");
  assert.equal(await orders(tokens.id_token), 401, "API rejects an ID token");
  assert.equal((await exchange(code, verifier)).error, "invalid_grant", "code replay must fail");
  assert.equal((await refresh(tokens.refresh_token)).error, "invalid_grant", "code replay revokes the refresh tokens from that code");

  const second = await login();
  const t1 = await exchange(second.code, second.verifier);
  const t2 = await refresh(t1.refresh_token);
  assert(t2.refresh_token && t2.refresh_token !== t1.refresh_token, "refresh rotates the refresh token");
  assert.equal((await refresh(t1.refresh_token)).error, "invalid_grant", "old refresh token is rejected");
  assert.equal((await refresh(t2.refresh_token)).error, "invalid_grant", "reuse kills the whole family");

  const bad = await login({ redirect_uri: "https://evil.example/steal" });
  assert(bad.res.status === 400 && !bad.res.headers.get("location"), "unregistered redirect_uri: error page, no redirect");
  const basic = (secret) => ({ Authorization: `Basic ${Buffer.from(`reports-job:${secret}`).toString("base64")}` });
  assert.equal((await form(`${ISSUER}/token`, { grant_type: "client_credentials" }, basic("wrong"))).status, 401, "wrong client secret");
  const machine = await (await form(`${ISSUER}/token`, { grant_type: "client_credentials" }, basic(REPORTS_JOB_SECRET))).json();
  assert(machine.access_token && !machine.refresh_token && !machine.id_token, "machine gets only an access token");
  assert.equal(await orders(machine.access_token), 200, "API accepts the machine token");

  codes.clear(); refreshTokens.clear(); revokedFamilies.clear(); // start the demo clean
  console.log("✅ Self-check passed: code + PKCE, nonce, code replay, refresh rotation + reuse, redirect_uri, client secret, ID token at API");
}

app.listen(PORT, () => {
  console.log(`🔐 ChaiCart ID (authorization server) on ${ISSUER}  discovery: ${ISSUER}/.well-known/openid-configuration`);
  api.listen(API_PORT, () => {
    console.log(`📦 ChaiCart Orders API (resource server) on ${API_URL}`);
    selfCheck().catch((err) => { console.error("❌ Self-check failed:", err.message); process.exit(1); });
  });
});
