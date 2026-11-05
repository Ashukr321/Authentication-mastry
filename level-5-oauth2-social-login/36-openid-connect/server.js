const express = require("express");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const { promisify } = require("util");

const scrypt = promisify(crypto.scrypt);
const SCRYPT_OPTIONS = { N: 2 ** 17, r: 8, p: 1, maxmem: 256 * 1024 * 1024 };

// Two apps, two ports, one file
const RP_PORT = Number(process.env.PORT) || 3000; // PrintKaro: the RELYING PARTY (the app that offers "Log in with PhotoVault")
const OP_PORT = RP_PORT + 1;                      // PhotoVault: the OPENID PROVIDER (an OAuth authorization server that also says WHO you are)
const RP_URL = `http://localhost:${RP_PORT}`;     // URLs from config, never from the Host header
const ISSUER = `http://localhost:${OP_PORT}`;     // the provider's identity. Real ones: https://accounts.google.com
const REDIRECT_URI = `${RP_URL}/callback`;
// shortcut: hard-coded demo client credentials. Real ones come from the provider's console and live in a secret store.
const CLIENT_ID = "printkaro";
const CLIENT_SECRET = process.env.CLIENT_SECRET || "printkaro-demo-secret";

// ---------- Shared helpers ----------
const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");
const randomToken = (bytes = 32) => crypto.randomBytes(bytes).toString("base64url");
const safeEqual = (a, b) => crypto.timingSafeEqual(Buffer.from(sha256(a)), Buffer.from(sha256(b)));
const str = (v) => (typeof v === "string" ? v : undefined); // query/body values can be arrays: accept strings only
const pkceChallenge = (verifier) => crypto.createHash("sha256").update(verifier).digest("base64url");
const parseCookies = (req) => Object.fromEntries((req.headers.cookie ?? "").split(";").filter((c) => c.includes("="))
  .map((c) => [c.slice(0, c.indexOf("=")).trim(), c.slice(c.indexOf("=") + 1).trim()]));

function newApp() {
  const app = express();
  app.use(express.json({ limit: "10kb" }));
  app.use(express.urlencoded({ extended: false, limit: "10kb" }));
  app.use((req, res, next) => { res.set("Cache-Control", "no-store"); next(); });
  return app;
}
function finish(app) {
  app.use((req, res) => res.status(404).json({ error: "Not found" }));
  // Errors (bad JSON, body too big, bugs) come here. Never send the stack trace to the client.
  app.use((err, req, res, next) => {
    if (err.type === "entity.parse.failed") return res.status(400).json({ error: "Body must be valid JSON" });
    if (err.type === "entity.too.large") return res.status(413).json({ error: "Request body too large" });
    console.error(err);
    res.status(500).json({ error: "Something went wrong" });
  });
}

// =====================================================================================
// OPENID PROVIDER (OP): PhotoVault. OAuth 2.0 + three additions: the ID token, /userinfo, and discovery + JWKS.
// =====================================================================================
// RS256: the OP signs ID tokens with its PRIVATE key and publishes the PUBLIC key as a JWKS (topic 18).
// shortcut: a new key pair on every start, kept in memory. Real providers keep keys in an HSM/KMS and rotate them.
const KID = `pv-${randomToken(6)}`;
const { privateKey, publicKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
const PUBLIC_JWK = { ...publicKey.export({ format: "jwk" }), kid: KID, alg: "RS256", use: "sig" };

// shortcut: in-memory Maps, lost on restart.
const CLIENTS = new Map([[CLIENT_ID, { id: CLIENT_ID, secretHash: sha256(CLIENT_SECRET), redirectUris: [REDIRECT_URI] }]]);
// sub = the user's PERMANENT id at this provider: never reused, never changes (emails can change)
const opUsers = new Map([
  ["rahul", { sub: "248289761001", username: "rahul", name: "Rahul Sharma", givenName: "Rahul", email: "rahul@example.com", emailVerified: true }],
  ["sneha", { sub: "248289761002", username: "sneha", name: "Sneha Iyer", givenName: "Sneha", email: "sneha@example.com", emailVerified: false }],
]);
const opSessions = new Map();   // sid -> { username, authTime, expiresAt }
const codes = new Map();        // sha256(code) -> { username, scope, nonce, challenge, authTime, redirectUri, expiresAt, used }
const accessTokens = new Map(); // sha256(token) -> { username, scope, expiresAt }

async function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const hash = await scrypt(password, salt, 64, SCRYPT_OPTIONS);
  return `${salt.toString("hex")}:${hash.toString("hex")}`;
}
async function verifyPassword(password, stored) {
  const [saltHex, hashHex] = stored.split(":");
  const attempt = await scrypt(password, Buffer.from(saltHex, "hex"), 64, SCRYPT_OPTIONS);
  return crypto.timingSafeEqual(attempt, Buffer.from(hashHex, "hex"));
}
const DUMMY_HASH_PROMISE = hashPassword("dummy-password-never-used");
// Password for every demo user: "chai1234" (demo only!)
const ready = Promise.all([...opUsers.values()].map(async (u) => { u.passwordHash = await hashPassword("chai1234"); }));

const op = newApp();

// Step 1: DISCOVERY. One URL tells clients every endpoint and what the provider supports.
op.get("/.well-known/openid-configuration", (req, res) => res.json({
  issuer: ISSUER,
  authorization_endpoint: `${ISSUER}/authorize`,
  token_endpoint: `${ISSUER}/token`,
  userinfo_endpoint: `${ISSUER}/userinfo`,
  jwks_uri: `${ISSUER}/jwks.json`,
  response_types_supported: ["code"],
  subject_types_supported: ["public"],
  id_token_signing_alg_values_supported: ["RS256"],
  scopes_supported: ["openid", "profile", "email"],
  claims_supported: ["sub", "name", "given_name", "email", "email_verified"],
  code_challenge_methods_supported: ["S256"],
  token_endpoint_auth_methods_supported: ["client_secret_basic"],
}));

// Step 2: JWKS. The public keys that verify ID tokens. "kid" says which key signed which token.
op.get("/jwks.json", (req, res) => res.json({ keys: [PUBLIC_JWK] }));

// shortcut: JSON login and no consent screen, so the flow fits in curl. Topic 33 shows the real HTML pages.
op.post("/login", async (req, res) => {
  const [username, password] = [req.body?.username, req.body?.password].map(str);
  if (!username || !password) return res.status(400).json({ error: "username and password are required" });
  await ready;
  const user = opUsers.get(username.toLowerCase());
  const ok = await verifyPassword(password, user?.passwordHash ?? (await DUMMY_HASH_PROMISE)); // same timing for unknown users
  if (!user || !ok) return res.status(401).json({ error: "Wrong username or password" });
  const sid = randomToken();
  opSessions.set(sid, { username: user.username, authTime: Math.floor(Date.now() / 1000), expiresAt: Date.now() + 60 * 60 * 1000 });
  res.set("Set-Cookie", `op_sid=${sid}; HttpOnly; SameSite=Lax; Path=/; Max-Age=3600`);
  res.json({ ok: true, user: user.username });
});

op.get("/authorize", (req, res) => {
  const q = Object.fromEntries(["response_type", "client_id", "redirect_uri", "scope", "state", "nonce", "code_challenge", "code_challenge_method"].map((k) => [k, str(req.query[k])]));
  const client = CLIENTS.get(q.client_id);
  if (!client || !client.redirectUris.includes(q.redirect_uri)) return res.status(400).json({ error: "invalid_request", error_description: "Unknown client or redirect_uri. Not redirecting." });
  const back = (params) => res.redirect(`${q.redirect_uri}?${new URLSearchParams({ ...params, ...(q.state && { state: q.state }) })}`);
  if (q.response_type !== "code") return back({ error: "unsupported_response_type" });
  const scopes = (q.scope ?? "").split(" ").filter(Boolean);
  // "openid" is what turns an OAuth request into an OpenID Connect request
  if (!scopes.includes("openid")) return back({ error: "invalid_scope", error_description: "scope must include openid" });
  if (!scopes.every((s) => ["openid", "profile", "email"].includes(s))) return back({ error: "invalid_scope" });
  if (q.code_challenge_method !== "S256" || !/^[A-Za-z0-9_-]{43}$/.test(q.code_challenge ?? "")) return back({ error: "invalid_request", error_description: "PKCE (S256) is required" });
  const s = opSessions.get(parseCookies(req).op_sid);
  if (!s || s.expiresAt < Date.now()) return res.status(401).json({ error: "login_required", error_description: "POST /login first" });

  const code = randomToken();
  codes.set(sha256(code), { username: s.username, scope: scopes, nonce: q.nonce, challenge: q.code_challenge, authTime: s.authTime, redirectUri: q.redirect_uri, expiresAt: Date.now() + 60 * 1000, used: false });
  back({ code });
});

op.post("/token", (req, res) => {
  const [scheme, value] = (req.headers.authorization ?? "").split(" ");
  const [id, secret] = scheme === "Basic" && value ? Buffer.from(value, "base64").toString().split(":").map(decodeURIComponent) : [];
  const client = CLIENTS.get(id);
  if (!client || !secret || !safeEqual(sha256(secret), client.secretHash)) return res.status(401).json({ error: "invalid_client" });
  if (str(req.body?.grant_type) !== "authorization_code") return res.status(400).json({ error: "unsupported_grant_type" });
  const code = str(req.body?.code), verifier = str(req.body?.code_verifier);
  const record = code && codes.get(sha256(code));
  if (!record || record.used || record.expiresAt < Date.now() || str(req.body?.redirect_uri) !== record.redirectUri) return res.status(400).json({ error: "invalid_grant" });
  if (!verifier || !safeEqual(pkceChallenge(verifier), record.challenge)) return res.status(400).json({ error: "invalid_grant", error_description: "PKCE verification failed" });
  record.used = true;

  const user = opUsers.get(record.username);
  const accessToken = randomToken();
  accessTokens.set(sha256(accessToken), { username: user.username, scope: record.scope, expiresAt: Date.now() + 10 * 60 * 1000 });

  // Step 3: the ID TOKEN. A signed JWT that says: "this user (sub) logged in at this provider (iss),
  // for this app (aud), at this time (auth_time), for this login request (nonce)". It's FOR the app, not for APIs.
  const idToken = jwt.sign({
    sub: user.sub,
    auth_time: record.authTime,
    ...(record.nonce && { nonce: record.nonce }),
    ...(record.scope.includes("profile") && { name: user.name, given_name: user.givenName }),
    ...(record.scope.includes("email") && { email: user.email, email_verified: user.emailVerified }),
  }, privateKey, { algorithm: "RS256", keyid: KID, issuer: ISSUER, audience: client.id, expiresIn: "5m" });

  console.log(`📸 OP: ${user.username} logged in to ${client.id} [${record.scope}] → ID token (kid ${KID}) + access token`);
  res.set("Pragma", "no-cache");
  res.json({ access_token: accessToken, token_type: "Bearer", expires_in: 600, scope: record.scope.join(" "), id_token: idToken });
});

// Step 4: USERINFO. An OAuth-protected API that returns claims about the user, by scope.
op.get("/userinfo", (req, res) => {
  const [scheme, token] = (req.headers.authorization ?? "").split(" ");
  const record = scheme === "Bearer" && token && accessTokens.get(sha256(token));
  if (!record || record.expiresAt < Date.now()) {
    res.set("WWW-Authenticate", 'Bearer error="invalid_token"');
    return res.status(401).json({ error: "invalid_token" });
  }
  const user = opUsers.get(record.username);
  res.json({
    sub: user.sub,
    ...(record.scope.includes("profile") && { name: user.name, given_name: user.givenName }),
    ...(record.scope.includes("email") && { email: user.email, email_verified: user.emailVerified }),
  });
});
finish(op);

// =====================================================================================
// RELYING PARTY (RP): PrintKaro. Uses OpenID Connect to LOG USERS IN.
// =====================================================================================
// shortcut: in-memory Maps, lost on restart. A real app has a users table with a UNIQUE (issuer, subject) index.
const accounts = new Map();   // `${iss}|${sub}` -> { id, iss, sub, name, email, emailVerified, createdAt }
const rpSessions = new Map(); // sid -> { pending: Map(state -> { nonce, verifier, expiresAt }), accountId, lastLogin }
const rp = newApp();

// The RP learns everything from the issuer URL: endpoints from discovery, keys from JWKS
let discovery = null;
let jwksCache = new Map(); // kid -> KeyObject
async function getDiscovery() {
  if (discovery) return discovery;
  const doc = await (await fetch(`${ISSUER}/.well-known/openid-configuration`)).json();
  if (doc.issuer !== ISSUER) throw new Error("Discovery issuer mismatch"); // the document must describe the issuer we asked about
  return (discovery = doc);
}
async function getSigningKey(kid) {
  if (!jwksCache.has(kid)) {
    // Unknown kid = the provider may have rotated its keys: fetch the JWKS again (once), from OUR configured issuer only
    const { keys } = await (await fetch((await getDiscovery()).jwks_uri)).json();
    jwksCache = new Map(keys.filter((k) => k.use === "sig" && k.kty === "RSA").map((k) => [k.kid, crypto.createPublicKey({ key: k, format: "jwk" })]));
  }
  const key = jwksCache.get(kid);
  if (!key) throw new Error(`No signing key with kid ${kid}`);
  return key;
}

function rpSession(req, res) {
  let sid = parseCookies(req).pk_sid;
  if (!sid || !rpSessions.has(sid)) {
    sid = randomToken();
    rpSessions.set(sid, { pending: new Map(), accountId: null, lastLogin: null });
    res.append("Set-Cookie", `pk_sid=${sid}; HttpOnly; SameSite=Lax; Path=/`);
  }
  return { sid, session: rpSessions.get(sid) };
}

rp.get("/login", async (req, res) => {
  const { session } = rpSession(req, res);
  const { authorization_endpoint } = await getDiscovery();
  const state = randomToken(16), nonce = randomToken(16), verifier = randomToken(32); // topic 35 and topic 34
  session.pending.set(state, { nonce, verifier, expiresAt: Date.now() + 10 * 60 * 1000 });
  res.redirect(`${authorization_endpoint}?${new URLSearchParams({
    response_type: "code", client_id: CLIENT_ID, redirect_uri: REDIRECT_URI,
    scope: "openid profile email", // openid = "log me in", profile/email = which claims we'd like
    state, nonce, code_challenge: pkceChallenge(verifier), code_challenge_method: "S256",
  })}`);
});

// Step 5: validate the ID token. Every check from topic 27, plus the OIDC ones (nonce, azp).
async function verifyIdToken(idToken, expectedNonce) {
  const decoded = jwt.decode(idToken, { complete: true }); // ONLY to read the kid: nothing is trusted until verify()
  if (!decoded?.header?.kid) throw new Error("ID token has no kid");
  const key = await getSigningKey(decoded.header.kid);
  const claims = jwt.verify(idToken, key, { algorithms: ["RS256"], issuer: ISSUER, audience: CLIENT_ID, clockTolerance: 30 });
  if (typeof claims.sub !== "string" || !claims.sub) throw new Error("sub missing");
  if (Array.isArray(claims.aud) && claims.aud.length > 1 && claims.azp !== CLIENT_ID) throw new Error("azp mismatch"); // several audiences: we must be the "authorized party"
  if (!claims.nonce || !safeEqual(claims.nonce, expectedNonce)) throw new Error("nonce mismatch");
  return claims;
}

rp.get("/callback", async (req, res) => {
  const { sid, session } = rpSession(req, res);
  const [code, state, error] = ["code", "state", "error"].map((k) => str(req.query[k]));
  const pending = state ? session.pending.get(state) : null;
  if (state) session.pending.delete(state);
  if (!pending || pending.expiresAt < Date.now()) return res.status(400).json({ error: "This login didn't start in this browser (state mismatch)" });
  if (error) return res.status(400).json({ error: `PhotoVault said: ${error}` });
  if (!code) return res.status(400).json({ error: "Missing code" });

  const { token_endpoint, userinfo_endpoint } = await getDiscovery();
  const tokenRes = await fetch(token_endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded", Authorization: `Basic ${Buffer.from(`${CLIENT_ID}:${encodeURIComponent(CLIENT_SECRET)}`).toString("base64")}` },
    body: new URLSearchParams({ grant_type: "authorization_code", code, redirect_uri: REDIRECT_URI, code_verifier: pending.verifier }),
  });
  const tokens = await tokenRes.json();
  if (!tokenRes.ok || !tokens.id_token) return res.status(400).json({ error: `Token exchange failed: ${tokens.error ?? "no id_token"}` });

  let claims;
  try {
    claims = await verifyIdToken(tokens.id_token, pending.nonce);
  } catch (e) {
    console.log(`🚨 RP: ID token rejected: ${e.message}`);
    return res.status(400).json({ error: "Login failed: invalid ID token" });
  }

  // Optional: more claims from /userinfo. Its sub MUST equal the ID token's sub, or the response is for someone else.
  const userinfo = await (await fetch(userinfo_endpoint, { headers: { Authorization: `Bearer ${tokens.access_token}` } })).json();
  if (userinfo.sub !== claims.sub) return res.status(400).json({ error: "Login failed: userinfo sub mismatch" });

  // Step 6: find the local account by (iss, sub). NOT by email: emails change, get recycled, and may be unverified.
  const key = `${claims.iss}|${claims.sub}`;
  let account = accounts.get(key);
  if (account) {
    console.log(`👋 RP: returning user ${account.id} (iss ${claims.iss}, sub ${claims.sub})`);
  } else {
    account = { id: `acct_${randomToken(4)}`, iss: claims.iss, sub: claims.sub, createdAt: new Date().toISOString() };
    accounts.set(key, account);
    console.log(`🆕 RP: new account ${account.id} for sub ${claims.sub}`);
  }
  // Profile data is a COPY you refresh on each login, not an identity
  Object.assign(account, { name: userinfo.name ?? claims.name, email: userinfo.email ?? claims.email, emailVerified: userinfo.email_verified ?? claims.email_verified ?? false });

  // New session id after login (topic 50). The tokens stay on the server; the browser only gets our cookie.
  rpSessions.delete(sid);
  const newSid = randomToken();
  rpSessions.set(newSid, { pending: new Map(), accountId: account.id, lastLogin: { idTokenClaims: claims, userinfo } });
  res.set("Set-Cookie", `pk_sid=${newSid}; HttpOnly; SameSite=Lax; Path=/`);
  res.redirect(303, "/me");
});

rp.get("/me", (req, res) => {
  const { session } = rpSession(req, res);
  const account = [...accounts.values()].find((a) => a.id === session.accountId);
  if (!account) return res.status(401).json({ error: "Not logged in. Open /login" });
  // Showing the verified claims is for learning. A real app wouldn't send them to the browser.
  res.json({ account, idTokenClaims: session.lastLogin.idTokenClaims, userinfo: session.lastLogin.userinfo });
});
finish(rp);

ready.then(() => {
  op.listen(OP_PORT, () => console.log(`📸 PhotoVault (OpenID provider) on ${ISSUER}  (discovery: ${ISSUER}/.well-known/openid-configuration)`));
  rp.listen(RP_PORT, () => console.log(`🖨️  PrintKaro (relying party) on ${RP_URL}  (users rahul, sneha; password chai1234)`));
});
