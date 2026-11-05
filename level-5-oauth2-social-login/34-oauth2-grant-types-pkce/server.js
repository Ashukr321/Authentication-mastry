const express = require("express");
const crypto = require("crypto");
const { promisify } = require("util");

const scrypt = promisify(crypto.scrypt);
const SCRYPT_OPTIONS = { N: 2 ** 17, r: 8, p: 1, maxmem: 256 * 1024 * 1024 };

const PORT = Number(process.env.PORT) || 3000;
const BASE_URL = `http://localhost:${PORT}`; // from config, never from the Host header
const ACCESS_TTL_SECONDS = 10 * 60;
const REFRESH_TTL_MS = 30 * 24 * 60 * 60 * 1000;
const CODE_TTL_MS = 60 * 1000;
const DEVICE_TTL_SECONDS = 10 * 60;
const DEVICE_INTERVAL_SECONDS = 5;
const DEVICE_GRANT = "urn:ietf:params:oauth:grant-type:device_code";

// ---------- Helpers ----------
const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");
const randomToken = (bytes = 32) => crypto.randomBytes(bytes).toString("base64url");
const safeEqual = (a, b) => crypto.timingSafeEqual(Buffer.from(sha256(a)), Buffer.from(sha256(b))); // constant time, any length
const str = (v) => (typeof v === "string" ? v : undefined); // query/body values can be arrays: accept strings only
const parseCookies = (req) => Object.fromEntries((req.headers.cookie ?? "").split(";").filter((c) => c.includes("="))
  .map((c) => [c.slice(0, c.indexOf("=")).trim(), c.slice(c.indexOf("=") + 1).trim()]));

// PKCE S256: challenge = BASE64URL(SHA256(verifier)). The client keeps the verifier secret until the token request.
const pkceChallenge = (verifier) => crypto.createHash("sha256").update(verifier).digest("base64url");
// Self-check against the example in RFC 7636 (Appendix B), on every start
if (pkceChallenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk") !== "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM") throw new Error("PKCE self-check failed");

// ---------- Step 1: CLIENTS, each registered for the grant types that fit it ----------
// shortcut: hard-coded demo secrets. Real secrets are random, issued by the provider, and kept in a secret store.
const CLIENTS = new Map([
  // A web app with a backend: can keep a secret (confidential). Uses code + PKCE + secret.
  ["printkaro-web", { type: "confidential", secretHash: sha256("web-demo-secret"), redirectUris: [`${BASE_URL}/demo/callback`],
    grants: ["authorization_code", "refresh_token"], scopes: ["photos.read"] }],
  // A mobile app / SPA: anyone can unpack it, so it has NO secret (public). PKCE is what protects its codes.
  ["printkaro-mobile", { type: "public", redirectUris: [`${BASE_URL}/demo/callback`],
    grants: ["authorization_code", "refresh_token"], scopes: ["photos.read"] }],
  // A server-side job with no user at all: machine to machine
  ["nightly-report-job", { type: "confidential", secretHash: sha256("job-demo-secret"), redirectUris: [],
    grants: ["client_credentials"], scopes: ["reports.read"] }],
  // A smart TV: no keyboard, no good browser. The user approves on their phone.
  ["photovault-tv", { type: "public", redirectUris: [],
    grants: [DEVICE_GRANT, "refresh_token"], scopes: ["photos.read"] }],
]);
for (const [id, client] of CLIENTS) client.id = id;

// ---------- "Database" ----------
// shortcut: in-memory Maps, lost on restart. A real authorization server uses tables (or is Auth0/Keycloak/Google).
const users = new Map([["u_rahul", { id: "u_rahul", username: "rahul" }]]);
const asSessions = new Map();    // sid -> { userId, expiresAt }
const codes = new Map();         // sha256(code) -> { clientId, redirectUri, userId, scope, challenge, expiresAt, used }
const accessTokens = new Map();  // sha256(token) -> { sub, clientId, scope, grant, expiresAt, familyId }
const refreshTokens = new Map(); // sha256(token) -> { userId, clientId, scope, familyId, expiresAt, used }
const deviceCodes = new Map();   // sha256(device_code) -> { clientId, scope, userCode, status, userId, expiresAt, interval, lastPollAt }
const userCodes = new Map();     // "WDJBMJHT" -> the same record

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
// Password for the demo user: "chai1234" (demo only!)
const ready = Promise.all([...users.values()].map(async (u) => { u.passwordHash = await hashPassword("chai1234"); }));

const app = express();
app.use(express.json({ limit: "10kb" }));
app.use(express.urlencoded({ extended: false, limit: "10kb" })); // the token endpoint uses form encoding
app.use((req, res, next) => { res.set("Cache-Control", "no-store"); next(); }); // codes and tokens must never be cached

// ---------- Logging in at the authorization server (topic 33 showed the HTML pages) ----------
// shortcut: a JSON login and no consent screen, so every grant fits in a few curl commands.
app.post("/login", async (req, res) => {
  const [username, password] = [req.body?.username, req.body?.password].map(str);
  if (!username || !password) return res.status(400).json({ error: "username and password are required" });
  await ready;
  const user = [...users.values()].find((u) => u.username === username.toLowerCase());
  const ok = await verifyPassword(password, user?.passwordHash ?? (await DUMMY_HASH_PROMISE)); // same timing for unknown users
  if (!user || !ok) return res.status(401).json({ error: "Wrong username or password" });
  const sid = randomToken();
  asSessions.set(sid, { userId: user.id, expiresAt: Date.now() + 60 * 60 * 1000 });
  res.set("Set-Cookie", `as_sid=${sid}; HttpOnly; SameSite=Lax; Path=/; Max-Age=3600`);
  res.json({ ok: true, user: user.id });
});
function currentUser(req) {
  const s = asSessions.get(parseCookies(req).as_sid);
  return s && s.expiresAt > Date.now() ? users.get(s.userId) : null;
}

// ---------- Grant 1: AUTHORIZATION CODE + PKCE (users, in a browser) ----------
app.get("/authorize", (req, res) => {
  const q = Object.fromEntries(["response_type", "client_id", "redirect_uri", "scope", "state", "code_challenge", "code_challenge_method"].map((k) => [k, str(req.query[k])]));
  const client = CLIENTS.get(q.client_id);
  if (!client || !client.redirectUris.includes(q.redirect_uri)) return res.status(400).json({ error: "invalid_request", error_description: "Unknown client or redirect_uri. Not redirecting." });
  const back = (params) => res.redirect(`${q.redirect_uri}?${new URLSearchParams({ ...params, ...(q.state && { state: q.state }) })}`);

  // The IMPLICIT grant (token straight in the URL) is removed in OAuth 2.1
  if (q.response_type === "token") return back({ error: "unsupported_response_type", error_description: "Implicit flow is not supported. Use response_type=code with PKCE." });
  if (q.response_type !== "code") return back({ error: "unsupported_response_type" });
  if (!client.grants.includes("authorization_code")) return back({ error: "unauthorized_client" });
  const scopes = (q.scope ?? "").split(" ").filter(Boolean);
  if (!scopes.length || !scopes.every((s) => client.scopes.includes(s))) return back({ error: "invalid_scope" });

  // Step 2: PKCE is REQUIRED for every client (OAuth 2.1), and only the S256 method
  if (!q.code_challenge) return back({ error: "invalid_request", error_description: "code_challenge is required (PKCE)" });
  if (q.code_challenge_method !== "S256") return back({ error: "invalid_request", error_description: "code_challenge_method must be S256" });
  if (!/^[A-Za-z0-9_-]{43}$/.test(q.code_challenge)) return back({ error: "invalid_request", error_description: "code_challenge is malformed" });

  const user = currentUser(req);
  if (!user) return res.status(401).json({ error: "login_required", error_description: "POST /login first (a real server shows its login page here)" });

  const code = randomToken();
  // The challenge is saved WITH the code: only whoever holds the matching verifier can redeem it
  codes.set(sha256(code), { clientId: client.id, redirectUri: q.redirect_uri, userId: user.id, scope: scopes, challenge: q.code_challenge, expiresAt: Date.now() + CODE_TTL_MS, used: false });
  console.log(`✅ code for ${client.id} (${client.type}), user ${user.id}, PKCE challenge ${q.code_challenge.slice(0, 8)}…`);
  back({ code });
});

// Pretend this is the app's redirect URI. A real app reads ?code=&state= here; we just show it to you.
app.get("/demo/callback", (req, res) => res.json({ note: "This is the app's redirect_uri. The app would now check state and POST the code to /token.", query: req.query }));

// ---------- Grant 3: DEVICE AUTHORIZATION (TVs, CLIs, consoles) ----------
const USER_CODE_ALPHABET = "BCDFGHJKLMNPQRSTVWXZ"; // no vowels (no accidental words), no 0/O, 1/I confusion
// 8 letters from 20 = about 34 bits. Enough because the code lives 10 minutes and works once (rate-limit /device too).
// shortcut: b % 20 has a tiny bias (256 isn't a multiple of 20). Fine for a short-lived code; use crypto.randomInt for secrets.
const newUserCode = () => Array.from(crypto.randomBytes(8), (b) => USER_CODE_ALPHABET[b % USER_CODE_ALPHABET.length]).join("");

app.post("/device_authorization", (req, res) => {
  const client = authenticateClient(req);
  if (!client || !client.grants.includes(DEVICE_GRANT)) return res.status(401).json({ error: "invalid_client" });
  const scopes = (str(req.body?.scope) ?? "").split(" ").filter(Boolean);
  if (!scopes.length || !scopes.every((s) => client.scopes.includes(s))) return res.status(400).json({ error: "invalid_scope" });
  const deviceCode = randomToken();
  const userCode = newUserCode();
  const record = { clientId: client.id, scope: scopes, userCode, status: "pending", userId: null, expiresAt: Date.now() + DEVICE_TTL_SECONDS * 1000, interval: DEVICE_INTERVAL_SECONDS, lastPollAt: 0 };
  deviceCodes.set(sha256(deviceCode), record);
  userCodes.set(userCode, record);
  console.log(`📺 ${client.id} asked for device login, user code ${userCode.slice(0, 4)}-${userCode.slice(4)}`);
  res.json({
    device_code: deviceCode,                                 // secret: stays on the TV
    user_code: `${userCode.slice(0, 4)}-${userCode.slice(4)}`, // shown on the TV screen
    verification_uri: `${BASE_URL}/device`,                  // the user opens this on their phone
    verification_uri_complete: `${BASE_URL}/device?user_code=${userCode}`, // for a QR code
    expires_in: DEVICE_TTL_SECONDS,
    interval: DEVICE_INTERVAL_SECONDS,
  });
});

// The user, logged in on their PHONE, types the code from the TV and approves.
// shortcut: JSON only. A real server shows a page: "Enter the code on your TV", then "PhotoVault TV wants to: See your photos".
app.post("/device", (req, res) => {
  const user = currentUser(req);
  if (!user) return res.status(401).json({ error: "Please log in first" });
  const typed = (str(req.body?.user_code) ?? "").toUpperCase().replace(/[^A-Z]/g, ""); // forgive dashes, spaces, lower case
  const record = userCodes.get(typed);
  if (!record || record.status !== "pending" || record.expiresAt < Date.now()) return res.status(400).json({ error: "Code not found or expired. Check the code on your TV." });
  record.status = str(req.body?.decision) === "allow" ? "approved" : "denied";
  record.userId = user.id;
  userCodes.delete(typed); // one use
  console.log(`📱 ${user.id} ${record.status} ${record.clientId}`);
  res.json({ message: record.status === "approved" ? "Done! Your TV is now connected." : "OK, the TV was not connected." });
});

// ---------- The TOKEN endpoint: one URL, many grant types ----------
function authenticateClient(req) {
  let id = str(req.body?.client_id), secret = str(req.body?.client_secret);
  const [scheme, value] = (req.headers.authorization ?? "").split(" ");
  if (scheme === "Basic" && value) {
    const decoded = Buffer.from(value, "base64").toString();
    const i = decoded.indexOf(":");
    if (i > 0) [id, secret] = [decodeURIComponent(decoded.slice(0, i)), decodeURIComponent(decoded.slice(i + 1))];
  }
  const client = id && CLIENTS.get(id);
  if (!client) return null;
  if (client.type === "public") return client; // public clients only identify themselves; PKCE / device codes protect them
  return secret && safeEqual(sha256(secret), client.secretHash) ? client : null;
}

function issueTokens(res, { sub, clientId, scope, grant, withRefresh, familyId = randomToken(8) }) {
  const access = randomToken();
  accessTokens.set(sha256(access), { sub, clientId, scope, grant, familyId, expiresAt: Date.now() + ACCESS_TTL_SECONDS * 1000 });
  const body = { access_token: access, token_type: "Bearer", expires_in: ACCESS_TTL_SECONDS, scope: scope.join(" ") };
  if (withRefresh) {
    body.refresh_token = randomToken();
    refreshTokens.set(sha256(body.refresh_token), { userId: sub, clientId, scope, familyId, expiresAt: Date.now() + REFRESH_TTL_MS, used: false });
  }
  console.log(`🎟️  ${grant}: token for ${sub} via ${clientId} [${scope}]${withRefresh ? " + refresh token" : ""}`);
  res.set("Pragma", "no-cache");
  res.json(body);
}

// Kill every token from one login (same familyId): used when a stolen token or code is replayed
function revokeFamily(familyId) {
  for (const t of accessTokens.values()) if (t.familyId === familyId) t.expiresAt = 0;
  for (const t of refreshTokens.values()) if (t.familyId === familyId) t.used = true;
}

const err = (res, status, error, error_description) => res.status(status).json({ error, ...(error_description && { error_description }) });

app.post("/token", (req, res) => {
  const grantType = str(req.body?.grant_type);
  // The PASSWORD grant (app collects the user's password) is removed in OAuth 2.1: the whole point is never to share it
  if (grantType === "password") return err(res, 400, "unsupported_grant_type", "The password grant is not supported. Use authorization_code with PKCE.");

  const client = authenticateClient(req);
  if (!client) {
    res.set("WWW-Authenticate", 'Basic realm="PhotoVault"');
    return err(res, 401, "invalid_client", "Client authentication failed");
  }
  if (!grantType || !client.grants.includes(grantType)) {
    const known = ["authorization_code", "refresh_token", "client_credentials", DEVICE_GRANT].includes(grantType);
    return err(res, 400, known ? "unauthorized_client" : "unsupported_grant_type", known ? `${client.id} may not use ${grantType}` : undefined);
  }

  // ----- authorization_code: redeem the code, PROVING you started the flow (PKCE) -----
  if (grantType === "authorization_code") {
    const code = str(req.body?.code), verifier = str(req.body?.code_verifier);
    const record = code && codes.get(sha256(code));
    if (!record || record.clientId !== client.id) return err(res, 400, "invalid_grant", "Unknown code");
    if (record.used) return err(res, 400, "invalid_grant", "Code already used");
    if (record.expiresAt < Date.now()) return err(res, 400, "invalid_grant", "Code expired");
    if (str(req.body?.redirect_uri) !== record.redirectUri) return err(res, 400, "invalid_grant", "redirect_uri does not match");
    // Step 3: the verifier must hash to the challenge sent at /authorize. A stolen code alone is useless.
    if (!verifier || !/^[A-Za-z0-9._~-]{43,128}$/.test(verifier)) return err(res, 400, "invalid_grant", "code_verifier is missing or malformed");
    if (!safeEqual(pkceChallenge(verifier), record.challenge)) {
      record.used = true; // a wrong verifier = someone else has this code: burn it
      console.log(`🚨 PKCE mismatch for ${client.id}: code burned`);
      return err(res, 400, "invalid_grant", "PKCE verification failed");
    }
    record.used = true;
    return issueTokens(res, { sub: record.userId, clientId: client.id, scope: record.scope, grant: grantType, withRefresh: client.grants.includes("refresh_token") });
  }

  // ----- refresh_token: new access token without the user, ROTATING the refresh token (topic 23) -----
  if (grantType === "refresh_token") {
    const rt = str(req.body?.refresh_token);
    const record = rt && refreshTokens.get(sha256(rt));
    if (!record || record.clientId !== client.id || record.expiresAt < Date.now()) return err(res, 400, "invalid_grant", "Unknown or expired refresh token");
    if (record.used) {
      revokeFamily(record.familyId); // an old refresh token came back: it was copied. Log everyone out of this grant.
      console.log(`🚨 refresh token reuse for ${client.id}: whole token family revoked`);
      return err(res, 400, "invalid_grant", "Refresh token already used");
    }
    record.used = true;
    return issueTokens(res, { sub: record.userId, clientId: client.id, scope: record.scope, grant: grantType, withRefresh: true, familyId: record.familyId });
  }

  // ----- client_credentials: no user, the app acts as ITSELF -----
  if (grantType === "client_credentials") {
    if (client.type !== "confidential") return err(res, 400, "unauthorized_client"); // a public client can't prove who it is
    const requested = (str(req.body?.scope) ?? client.scopes.join(" ")).split(" ").filter(Boolean);
    if (!requested.length || !requested.every((s) => client.scopes.includes(s))) return err(res, 400, "invalid_scope");
    return issueTokens(res, { sub: client.id, clientId: client.id, scope: requested, grant: grantType, withRefresh: false }); // no refresh: just ask again
  }

  // ----- device_code: the TV polls until the user approves on their phone -----
  const deviceCode = str(req.body?.device_code);
  const record = deviceCode && deviceCodes.get(sha256(deviceCode));
  if (!record || record.clientId !== client.id) return err(res, 400, "invalid_grant", "Unknown device_code");
  if (record.expiresAt < Date.now()) return err(res, 400, "expired_token");
  const now = Date.now();
  if (now - record.lastPollAt < record.interval * 1000) {
    record.interval += 5; // polling too fast: the spec says slow down by 5 seconds
    record.lastPollAt = now;
    return err(res, 400, "slow_down");
  }
  record.lastPollAt = now;
  if (record.status === "pending") return err(res, 400, "authorization_pending");
  deviceCodes.delete(sha256(deviceCode)); // one use, approved or not
  if (record.status === "denied") return err(res, 400, "access_denied");
  return issueTokens(res, { sub: record.userId, clientId: client.id, scope: record.scope, grant: "device_code", withRefresh: true });
});

// ---------- A tiny resource server: who does this token represent? ----------
app.get("/api/whoami", (req, res) => {
  const [scheme, token] = (req.headers.authorization ?? "").split(" ");
  const record = scheme === "Bearer" && token && accessTokens.get(sha256(token));
  if (!record || record.expiresAt < Date.now()) {
    res.set("WWW-Authenticate", 'Bearer error="invalid_token"');
    return res.status(401).json({ error: "invalid_token" });
  }
  res.json({ sub: record.sub, client_id: record.clientId, scope: record.scope.join(" "), grant: record.grant, user: record.sub.startsWith("u_") });
});

app.use((req, res) => res.status(404).json({ error: "Not found" }));

// Errors (bad JSON, body too big, bugs) come here. Never send the stack trace to the client.
app.use((e, req, res, next) => {
  if (e.type === "entity.parse.failed") return res.status(400).json({ error: "Body must be valid JSON" });
  if (e.type === "entity.too.large") return res.status(413).json({ error: "Request body too large" });
  console.error(e);
  res.status(500).json({ error: "Something went wrong" });
});

ready.then(() => app.listen(PORT, () => console.log(`OAuth grant types + PKCE demo on ${BASE_URL} (user rahul / chai1234)`)));
