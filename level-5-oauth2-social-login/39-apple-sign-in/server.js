const express = require("express");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");

const APP_PORT = Number(process.env.PORT) || 3000; // TiffinBox: website + iPhone app backend
const APPLE_PORT = APP_PORT + 1;                    // a MOCK "appleid.apple.com"
const APP_URL = `http://localhost:${APP_PORT}`;     // URLs from config, never from the Host header
const APPLE_URL = `http://localhost:${APPLE_PORT}`; // real: https://appleid.apple.com (also the ID token issuer)

// What you set up once in the Apple Developer portal (demo values)
const TEAM_ID = "A1B2C3D4E5";          // your Apple developer team
const KEY_ID = "KEY7XQ2P9M";           // the "Sign in with Apple" key you created
const BUNDLE_ID = "in.tiffinbox.app";  // the iPhone app (primary App ID): its client_id
const SERVICES_ID = "in.tiffinbox.web"; // a "Services ID" for the website: the website's client_id
const REDIRECT_URI = `${APP_URL}/callback/apple`;

// ---------- Shared helpers ----------
const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");
const randomToken = (bytes = 32) => crypto.randomBytes(bytes).toString("base64url");
const safeEqual = (a, b) => crypto.timingSafeEqual(Buffer.from(sha256(a)), Buffer.from(sha256(b)));
const str = (v) => (typeof v === "string" ? v : undefined); // body/query values can be arrays or objects: accept strings only
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
const parseCookies = (req) => Object.fromEntries((req.headers.cookie ?? "").split(";").filter((c) => c.includes("="))
  .map((c) => [c.slice(0, c.indexOf("=")).trim(), c.slice(c.indexOf("=") + 1).trim()]));
const now = () => Math.floor(Date.now() / 1000);

function newApp() {
  const app = express();
  app.use(express.json({ limit: "10kb" }));
  app.use(express.urlencoded({ extended: false, limit: "10kb" })); // Apple's callback is an HTML form POST
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

// Step 1: the ".p8" key. Apple shows you the private key ONCE as AuthKey_<KEY_ID>.p8 and keeps the public half.
// shortcut: generated at startup so the demo runs anywhere. A real app loads the .p8 from a secret store (Level 7).
const { privateKey: P8_KEY, publicKey: P8_PUBLIC } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });

// =====================================================================================
// PART 1: MOCK APPLE. A small fake of appleid.apple.com, with Apple's real-world QUIRKS.
// shortcut: no real Apple ID, Face ID or consent screen: a page lets you pick a test user.
// =====================================================================================
const APPLE_TEAM = {
  keys: { [KEY_ID]: P8_PUBLIC },                          // public halves of your .p8 keys
  clients: { [SERVICES_ID]: [REDIRECT_URI], [BUNDLE_ID]: [] }, // website: registered return URLs; iPhone app: none
  notificationUrl: `${APP_URL}/apple/notifications`,       // "Server-to-Server Notification Endpoint"
};
const MOCK_USERS = {
  // sub is the same for every app of ONE team (website + iPhone app), different for other teams
  rahul: { sub: "001234.5f2c9a7e1b8d4c60a3e9f1d2b7c4a6e8.0420", firstName: "Rahul", lastName: "Sharma", email: "rahul@example.com", hidden: false },
  // Priya tapped "Hide My Email": your app only ever sees a random relay address
  priya: { sub: "001234.9b1e7c3a5d2f4e8a6c0b3d9f1e7a2c5b.1137", firstName: "Priya", lastName: "Nair", email: "k7x2mqp9vd@privaterelay.appleid.com", hidden: true },
};
const APPLE_KEY = (() => { // Apple signs ID tokens with RS256 and publishes the keys at /auth/keys
  const { privateKey, publicKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  const kid = `apple-${randomToken(4)}`;
  return { privateKey, kid, jwk: { ...publicKey.export({ format: "jwk" }), kid, alg: "RS256", use: "sig" } };
})();

const authorized = new Set();  // users who already said "yes" to TiffinBox
const appleCodes = new Map();  // code -> { clientId, who, nonce, redirectUri, expiresAt }
const appleRefresh = new Map(); // refresh token -> { clientId, who }
const apple = newApp();

function appleIdToken(who, audience, nonce) {
  const u = MOCK_USERS[who];
  // QUIRK: email_verified / is_private_email have historically been the STRINGS "true"/"false"
  return jwt.sign({ sub: u.sub, email: u.email, email_verified: "true", is_private_email: String(u.hidden), auth_time: now(), nonce_supported: true, ...(nonce && { nonce }) },
    APPLE_KEY.privateKey, { algorithm: "RS256", keyid: APPLE_KEY.kid, issuer: APPLE_URL, audience, expiresIn: "10m" });
}
const firstTimeUser = (who) => { const u = MOCK_USERS[who]; return { name: { firstName: u.firstName, lastName: u.lastName }, email: u.email }; };

apple.get("/auth/authorize", (req, res) => {
  const q = Object.fromEntries(["client_id", "redirect_uri", "response_type", "response_mode", "scope", "state", "nonce", "mock_user"].map((k) => [k, str(req.query[k])]));
  if (!APPLE_TEAM.clients[q.client_id]?.includes(q.redirect_uri)) return res.status(400).send("invalid_client or redirect_uri not registered. Not redirecting.");
  if (q.response_type !== "code") return res.status(400).send("unsupported response_type");
  const scopes = (q.scope ?? "").split(" ");
  const wantsInfo = scopes.includes("name") || scopes.includes("email");
  // QUIRK: asking for name or email REQUIRES response_mode=form_post (the answer comes back as a POST, not a redirect)
  if (wantsInfo && q.response_mode !== "form_post") return res.status(400).send("response_mode must be form_post when name or email scope is requested");
  if (!q.mock_user) {
    const links = Object.keys(MOCK_USERS).map((u) => `<li><a href="${esc(`${req.originalUrl}&mock_user=${u}`)}">Continue as ${esc(u)}${MOCK_USERS[u].hidden ? " (Hide My Email)" : ""}</a></li>`).join("");
    return res.send(`<!doctype html><meta charset="utf-8"><title>Mock Apple</title><body style="font-family:system-ui;max-width:520px;margin:40px auto">
      <h2> Mock Sign in with Apple</h2><p>The real page asks for the Apple ID, Face ID / password, and lets the user share or hide their email.</p><ul>${links}</ul>`);
  }
  const u = MOCK_USERS[q.mock_user];
  if (!u) return res.status(400).send("Unknown mock user");
  const code = randomToken();
  appleCodes.set(code, { clientId: q.client_id, who: q.mock_user, nonce: q.nonce, redirectUri: q.redirect_uri, expiresAt: Date.now() + 5 * 60_000 });
  const fields = { code, ...(q.state && { state: q.state }) };
  // QUIRK: the user's NAME is sent only the FIRST time they authorize your app, never again. It's not signed.
  if (wantsInfo && !authorized.has(q.mock_user)) {
    const info = firstTimeUser(q.mock_user);
    fields.user = JSON.stringify({ ...(scopes.includes("name") && { name: info.name }), ...(scopes.includes("email") && { email: info.email }) });
  }
  authorized.add(q.mock_user);
  const inputs = Object.entries(fields).map(([k, v]) => `<input type="hidden" name="${k}" value="${esc(v)}">`).join("\n");
  // form_post: Apple's page makes the BROWSER POST these fields to your redirect_uri (a cross-site POST)
  res.send(`<!doctype html><meta charset="utf-8"><title>Signing in…</title><body>
<form method="post" action="${esc(q.redirect_uri)}">
${inputs}
<noscript><button>Continue</button></noscript></form><script>document.forms[0].submit()</script>`);
});

// Your "client secret" is a short JWT you sign with the .p8 key: ES256, kid = key id, iss = team, sub = client_id
function clientAuthError(clientId, secret) {
  try {
    const kid = jwt.decode(secret ?? "", { complete: true })?.header?.kid;
    const key = APPLE_TEAM.keys[kid];
    if (!key) return "unknown key id";
    if (!(clientId in APPLE_TEAM.clients)) return "unknown client_id";
    const c = jwt.verify(secret, key, { algorithms: ["ES256"], issuer: TEAM_ID, audience: APPLE_URL, subject: clientId });
    if (!c.iat || c.exp - c.iat > 180 * 24 * 3600) return "client secret may live at most 6 months";
    return null;
  } catch (e) { return e.message; }
}

apple.post("/auth/token", (req, res) => {
  const p = Object.fromEntries(["client_id", "client_secret", "code", "grant_type", "redirect_uri"].map((k) => [k, str(req.body?.[k])]));
  const authError = clientAuthError(p.client_id, p.client_secret);
  if (authError) { console.log(`🍎 token: invalid_client (${authError})`); return res.status(400).json({ error: "invalid_client" }); }
  if (p.grant_type !== "authorization_code") return res.status(400).json({ error: "unsupported_grant_type" }); // shortcut: refresh_token grant not mocked
  const record = appleCodes.get(p.code);
  appleCodes.delete(p.code); // single use
  // Website codes must come back with the same redirect_uri. Codes from the iPhone app have none.
  if (!record || record.expiresAt < Date.now() || record.clientId !== p.client_id || (record.redirectUri ?? undefined) !== p.redirect_uri) {
    return res.status(400).json({ error: "invalid_grant" });
  }
  const refreshToken = randomToken();
  appleRefresh.set(refreshToken, { clientId: p.client_id, who: record.who });
  res.json({ access_token: randomToken(), token_type: "Bearer", expires_in: 3600, refresh_token: refreshToken, id_token: appleIdToken(record.who, p.client_id, record.nonce) });
});

apple.post("/auth/revoke", (req, res) => {
  const p = Object.fromEntries(["client_id", "client_secret", "token"].map((k) => [k, str(req.body?.[k])]));
  if (clientAuthError(p.client_id, p.client_secret)) return res.status(400).json({ error: "invalid_client" });
  const t = appleRefresh.get(p.token);
  if (t && t.clientId === p.client_id) {
    for (const [k, v] of appleRefresh) if (v.who === t.who) appleRefresh.delete(k);
    authorized.delete(t.who); // TiffinBox disappears from "Apps using Apple ID"; next sign-in asks again and sends the name again
    console.log(`🍎 revoked TiffinBox for ${t.who}`);
  }
  res.status(200).end(); // 200 even for unknown tokens (RFC 7009)
});
apple.get("/auth/keys", (req, res) => res.json({ keys: [APPLE_KEY.jwk] }));

// --- Demo-only helpers: things that happen on an iPhone or in the user's Apple ID settings ---
// What the iOS app gets from ASAuthorizationAppleIDCredential after Face ID. The app sets nonce = SHA256(rawNonce).
apple.get("/mock/ios-sign-in", (req, res) => {
  const who = str(req.query.user), nonce = str(req.query.nonce);
  if (!MOCK_USERS[who]) return res.status(400).json({ error: "Unknown mock user" });
  const code = randomToken();
  appleCodes.set(code, { clientId: BUNDLE_ID, who, nonce, expiresAt: Date.now() + 5 * 60_000 });
  const first = !authorized.has(who);
  authorized.add(who);
  const info = firstTimeUser(who);
  res.json({ identityToken: appleIdToken(who, BUNDLE_ID, nonce), authorizationCode: code, user: MOCK_USERS[who].sub,
    ...(first && { fullName: `${info.name.firstName} ${info.name.lastName}`, email: info.email }) }); // fullName/email: first time only
});
// The user changes something in Settings → Apple ID → Sign in with Apple. Apple tells your server with a signed JWT.
apple.post("/mock/notify", async (req, res) => {
  const who = str(req.body?.user), type = str(req.body?.type);
  if (!MOCK_USERS[who] || !["email-disabled", "email-enabled", "consent-revoked", "account-delete"].includes(type)) return res.status(400).json({ error: "user or type" });
  if (type === "consent-revoked" || type === "account-delete") { authorized.delete(who); for (const [k, v] of appleRefresh) if (v.who === who) appleRefresh.delete(k); }
  const u = MOCK_USERS[who];
  const events = JSON.stringify({ type, sub: u.sub, event_time: Date.now(), ...(type.startsWith("email") && { email: u.email, is_private_email: String(u.hidden) }) });
  const payload = jwt.sign({ jti: randomToken(8), events }, APPLE_KEY.privateKey, { algorithm: "RS256", keyid: APPLE_KEY.kid, issuer: APPLE_URL, audience: BUNDLE_ID });
  const r = await fetch(APPLE_TEAM.notificationUrl, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ payload }) });
  res.json({ sent: type, to: who, yourServerSaid: r.status });
});
finish(apple);

// =====================================================================================
// PART 2: TIFFINBOX. The website uses the web flow; the iPhone app sends its token to /auth/apple/native.
// =====================================================================================
const postForm = async (url, body) => {
  const r = await fetch(url, { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded", Accept: "application/json" }, body: new URLSearchParams(body) });
  return r.headers.get("content-type")?.includes("json") ? r.json() : {};
};

// Step 2: make the client secret. Up to 6 months is allowed; a short one, cached and re-made, limits the damage if it leaks.
const secretCache = new Map(); // clientId -> { token, exp }
function clientSecret(clientId) {
  const cached = secretCache.get(clientId);
  if (cached && cached.exp - 60 > now()) return cached.token;
  const token = jwt.sign({ sub: clientId }, P8_KEY, { algorithm: "ES256", keyid: KEY_ID, issuer: TEAM_ID, audience: APPLE_URL, expiresIn: "1h" });
  secretCache.set(clientId, { token, exp: now() + 3600 });
  return token;
}

let appleKeys = new Map(); // kid -> KeyObject, refreshed when an unknown kid shows up (key rotation)
async function verifyAppleJwt(token, audience) {
  const kid = jwt.decode(token, { complete: true })?.header?.kid; // decode ONLY to pick the key
  if (!appleKeys.has(kid)) {
    const { keys } = await (await fetch(`${APPLE_URL}/auth/keys`)).json();
    appleKeys = new Map(keys.map((k) => [k.kid, crypto.createPublicKey({ key: k, format: "jwk" })]));
  }
  const key = appleKeys.get(kid);
  if (!key) throw new Error("unknown kid");
  return jwt.verify(token, key, { algorithms: ["RS256"], issuer: APPLE_URL, audience, clockTolerance: 30 });
}
async function verifyIdToken(token, audience, expectedNonce) {
  const claims = await verifyAppleJwt(token, audience);
  if (!claims.nonce || !safeEqual(claims.nonce, expectedNonce)) throw new Error("nonce mismatch");
  return claims;
}
async function exchangeCode(code, clientId, redirectUri) {
  const tokens = await postForm(`${APPLE_URL}/auth/token`, { client_id: clientId, client_secret: clientSecret(clientId), code, grant_type: "authorization_code", ...(redirectUri && { redirect_uri: redirectUri }) });
  if (!tokens.id_token) throw new Error(`token exchange: ${tokens.error ?? "no id_token"}`);
  return tokens;
}
const isTrue = (v) => v === true || v === "true"; // Apple's booleans can be strings

// The "user" field / fullName is NOT signed: anyone can POST it. Use it only as a display name, never for email or identity.
function cleanName(raw, isJson) {
  try {
    if (!raw) return null;
    const n = isJson ? JSON.parse(raw)?.name : null;
    const full = isJson ? [n?.firstName, n?.lastName].filter((x) => typeof x === "string").join(" ") : raw;
    return full.trim().slice(0, 100) || null;
  } catch { return null; }
}

// shortcut: in-memory Maps, lost on restart. Real apps: users + user_identities(provider, provider_user_id UNIQUE) tables.
const accounts = new Map();      // apple sub -> account
const sessions = new Map();      // sid -> apple sub
const pendingLogins = new Map(); // loginId (cookie) -> { state, nonce, expiresAt }
const seenNotifications = new Set(); // jti, so a replayed notification is ignored
const app = newApp();

// Step 5: account by Apple's "sub". Save the name NOW: you will never get it again.
function saveAppleLogin(claims, name, tokens, clientId) {
  let account = accounts.get(claims.sub);
  const isNew = !account;
  if (isNew) accounts.set(claims.sub, account = { id: `acct_${randomToken(4)}`, appleSub: claims.sub, name: null, createdAt: new Date().toISOString() });
  if (name && !account.name) account.name = name;
  Object.assign(account, {
    email: claims.email ?? account.email ?? null,
    emailVerified: isTrue(claims.email_verified),
    isPrivateEmail: isTrue(claims.is_private_email), // a @privaterelay.appleid.com address
    emailForwarding: account.emailForwarding ?? true,
    appleClientId: clientId,
    appleRefreshToken: tokens.refresh_token, // shortcut: encrypt at rest in a real DB. Needed to REVOKE on account deletion.
  });
  console.log(`${isNew ? "🆕" : "👋"} Apple (${clientId === BUNDLE_ID ? "iPhone app" : "website"}): ${account.name ?? "(no name)"} → ${account.id} (sub ${claims.sub.slice(0, 12)}…)` +
    `, email ${account.email}${account.isPrivateEmail ? " 🕶️ private relay" : ""}${name ? ", name received (first time only!)" : ", no name sent this time"}`);
  return account;
}
function startSession(res, sub) {
  const sid = randomToken();
  sessions.set(sid, sub);
  res.append("Set-Cookie", `tb_sid=${sid}; HttpOnly; SameSite=Lax; Path=/`);
}
const endSessionsOf = (sub) => { for (const [sid, s] of sessions) if (s === sub) sessions.delete(sid); };
const currentAccount = (req) => accounts.get(sessions.get(parseCookies(req).tb_sid));
const publicView = ({ appleRefreshToken, appleClientId, ...rest }) => rest; // never send Apple's tokens to the browser

app.get("/", (req, res) => res.send(`<!doctype html><meta charset="utf-8"><title>TiffinBox</title><body style="font-family:system-ui;max-width:520px;margin:40px auto">
  <h2>🍱 TiffinBox</h2><p><a href="/login/apple"> Sign in with Apple</a></p><p><a href="/me">Who am I?</a></p>
  <p><button onclick="fetch('/me',{method:'DELETE'}).then(r=>r.json()).then(j=>alert(JSON.stringify(j)))">Delete my account</button></p>`));

// Step 3: start the web login
app.get("/login/apple", (req, res) => {
  const loginId = randomToken(16), state = randomToken(16), nonce = randomToken(16);
  pendingLogins.set(loginId, { state, nonce, expiresAt: Date.now() + 10 * 60_000 });
  // Apple sends the user back with a CROSS-SITE POST. Browsers don't send SameSite=Lax cookies on those,
  // so this one short-lived cookie must be SameSite=None (which requires Secure; browsers allow that on localhost).
  res.append("Set-Cookie", `apple_login=${loginId}; HttpOnly; Secure; SameSite=None; Path=/callback/apple; Max-Age=600`);
  const params = new URLSearchParams({ response_type: "code", response_mode: "form_post", client_id: SERVICES_ID, redirect_uri: REDIRECT_URI, scope: "name email", state, nonce });
  res.redirect(`${APPLE_URL}/auth/authorize?${params}`);
});

// Step 4: Apple POSTs code + state (+ "user" the first time) to the callback
app.post("/callback/apple", async (req, res) => {
  const loginId = parseCookies(req).apple_login;
  const pending = loginId && pendingLogins.get(loginId);
  if (loginId) pendingLogins.delete(loginId); // one try per login
  res.append("Set-Cookie", "apple_login=; HttpOnly; Secure; SameSite=None; Path=/callback/apple; Max-Age=0");
  const [code, state, error, user] = ["code", "state", "error", "user"].map((k) => str(req.body?.[k]));
  if (!pending || pending.expiresAt < Date.now() || !state || !safeEqual(state, pending.state)) {
    return res.status(400).json({ error: "This login didn't start here (state mismatch)" });
  }
  if (error) return res.status(400).json({ error: `Apple said: ${error}` }); // e.g. user_cancelled_authorize
  if (!code) return res.status(400).json({ error: "Missing code" });
  try {
    const tokens = await exchangeCode(code, SERVICES_ID, REDIRECT_URI);
    const claims = await verifyIdToken(tokens.id_token, SERVICES_ID, pending.nonce); // the EMAIL comes from here, signed
    const account = saveAppleLogin(claims, cleanName(user, true), tokens, SERVICES_ID);
    startSession(res, account.appleSub); // new session id after login (topic 50)
    res.redirect(303, "/me");
  } catch (e) {
    console.log(`🚨 Apple login failed: ${e.message}`);
    res.status(400).json({ error: "Apple login failed" });
  }
});

// Step 6: the iPhone app signs in natively and sends what it got to the backend
app.post("/auth/apple/native", async (req, res) => {
  const [identityToken, authorizationCode, rawNonce, fullName] = ["identityToken", "authorizationCode", "rawNonce", "fullName"].map((k) => str(req.body?.[k]));
  if (!identityToken || !authorizationCode || !rawNonce) return res.status(400).json({ error: "identityToken, authorizationCode and rawNonce are required" });
  try {
    // aud is the BUNDLE id here, not the Services ID. The app hashed its nonce, so compare with SHA256(rawNonce).
    const claims = await verifyIdToken(identityToken, BUNDLE_ID, sha256(rawNonce));
    const tokens = await exchangeCode(authorizationCode, BUNDLE_ID); // proves the code is real + gives the refresh token for revoking
    if (tokens.id_token && (await verifyAppleJwt(tokens.id_token, BUNDLE_ID)).sub !== claims.sub) throw new Error("code belongs to another user");
    const account = saveAppleLogin(claims, cleanName(fullName, false), tokens, BUNDLE_ID);
    startSession(res, account.appleSub); // shortcut: a real mobile API would usually hand out its own tokens (Level 3)
    res.json(publicView(account));
  } catch (e) {
    console.log(`🚨 Apple native login failed: ${e.message}`);
    res.status(401).json({ error: "Apple login failed" });
  }
});

// Step 7: Apple's server-to-server notifications (register this URL in the developer portal)
app.post("/apple/notifications", async (req, res) => {
  let claims, event;
  try {
    claims = await verifyAppleJwt(str(req.body?.payload) ?? "", [BUNDLE_ID, SERVICES_ID]); // signed by Apple, or it's ignored
    event = typeof claims.events === "string" ? JSON.parse(claims.events) : claims.events;
  } catch (e) {
    console.log(`🚨 Rejected Apple notification: ${e.message}`);
    return res.status(400).json({ error: "Invalid notification" });
  }
  if (!claims.jti || seenNotifications.has(claims.jti)) return res.sendStatus(200); // replay or duplicate: already handled
  seenNotifications.add(claims.jti);
  const account = accounts.get(event?.sub);
  if (account) {
    if (event.type === "email-disabled") account.emailForwarding = false; // relay is off: mails to it bounce, stop sending
    if (event.type === "email-enabled") account.emailForwarding = true;
    if (event.type === "consent-revoked") { endSessionsOf(account.appleSub); delete account.appleRefreshToken; } // user stopped "Sign in with Apple" for us
    if (event.type === "account-delete") { endSessionsOf(account.appleSub); accounts.delete(account.appleSub); } // the Apple ID itself is gone
    console.log(`📬 Apple notification: ${event.type} for ${account.id}`);
  }
  res.sendStatus(200); // answer fast; Apple only needs to know you got it
});

app.get("/me", (req, res) => {
  const account = currentAccount(req);
  if (!account) return res.status(401).json({ error: "Not logged in. Open / and sign in with Apple" });
  res.json(publicView(account));
});

// Step 8: account deletion (required by App Store rules when you offer sign-up): revoke Apple's tokens, then delete
app.delete("/me", async (req, res) => {
  const account = currentAccount(req);
  if (!account) return res.status(401).json({ error: "Not logged in" });
  if (account.appleRefreshToken) {
    await postForm(`${APPLE_URL}/auth/revoke`, { client_id: account.appleClientId, client_secret: clientSecret(account.appleClientId), token: account.appleRefreshToken, token_type_hint: "refresh_token" });
  }
  endSessionsOf(account.appleSub);
  accounts.delete(account.appleSub);
  console.log(`🗑️  Deleted ${account.id} and revoked its Apple tokens`);
  res.json({ deleted: account.id });
});
finish(app);

apple.listen(APPLE_PORT, () => console.log(`🍎 Mock Apple on ${APPLE_URL}`));
app.listen(APP_PORT, () => console.log(`🍱 TiffinBox on ${APP_URL}  ← open this one`));
