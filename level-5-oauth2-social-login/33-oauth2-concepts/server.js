const express = require("express");
const crypto = require("crypto");
const { promisify } = require("util");

const scrypt = promisify(crypto.scrypt);
const SCRYPT_OPTIONS = { N: 2 ** 17, r: 8, p: 1, maxmem: 256 * 1024 * 1024 };

// Three separate apps, three ports, one file. In real life they belong to different companies.
const CLIENT_PORT = Number(process.env.PORT) || 3000; // PrintKaro: the CLIENT (a photo printing website)
const AUTH_PORT = CLIENT_PORT + 1;                     // PhotoVault Accounts: the AUTHORIZATION SERVER
const API_PORT = CLIENT_PORT + 2;                      // PhotoVault API: the RESOURCE SERVER
// URLs come from config, never from the Host header
const CLIENT_URL = `http://localhost:${CLIENT_PORT}`;
const AUTH_URL = `http://localhost:${AUTH_PORT}`;
const API_URL = `http://localhost:${API_PORT}`;
const REDIRECT_URI = `${CLIENT_URL}/callback`;

const CODE_TTL_MS = 60 * 1000;          // authorization codes live 1 minute and work once
const TOKEN_TTL_SECONDS = 10 * 60;      // access tokens live 10 minutes
// shortcut: a hard-coded demo secret. A real client secret is random, issued by the provider, and kept in a secret store.
const CLIENT_SECRET = process.env.CLIENT_SECRET || "printkaro-demo-secret";

// ---------- Shared helpers ----------
const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");
const randomToken = (bytes = 32) => crypto.randomBytes(bytes).toString("base64url");
const safeEqual = (a, b) => crypto.timingSafeEqual(Buffer.from(sha256(a)), Buffer.from(sha256(b))); // same length, constant time
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
const str = (v) => (typeof v === "string" ? v : undefined); // query/body values can be arrays or objects: accept strings only

function parseCookies(req) {
  return Object.fromEntries((req.headers.cookie ?? "").split(";").filter((c) => c.includes("=")).map((c) => {
    const i = c.indexOf("=");
    return [c.slice(0, i).trim(), decodeURIComponent(c.slice(i + 1).trim())];
  }));
}

const page = (title, body) => `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>${esc(title)}</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>body{font-family:system-ui,sans-serif;max-width:560px;margin:40px auto;padding:0 16px;line-height:1.5}
.box{border:1px solid #ccc;border-radius:8px;padding:16px 20px}button,.btn{font:inherit;padding:8px 16px;margin-right:8px;cursor:pointer}
input{font:inherit;padding:6px;width:100%;box-sizing:border-box;margin-bottom:10px}small{color:#666}</style></head>
<body>${body}</body></html>`;

function newApp() {
  const app = express();
  app.use(express.json({ limit: "10kb" }));
  app.use(express.urlencoded({ extended: false, limit: "10kb" })); // OAuth forms and the token endpoint use form encoding
  app.use((req, res, next) => { res.set("Cache-Control", "no-store"); next(); }); // tokens and codes must never be cached
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
// 1. AUTHORIZATION SERVER: "PhotoVault Accounts". Knows the users, asks for consent, issues codes and tokens.
// =====================================================================================
// shortcut: in-memory Maps, lost on restart. A real authorization server uses tables (or is Google/Auth0/Keycloak).
const SCOPES = { "photos.read": "See your photos", "photos.delete": "Delete your photos" };

// Step 1: the client is REGISTERED in advance: its id, its secret (hashed), its exact redirect URIs, the scopes it may ask for
const CLIENTS = new Map([
  ["printkaro", {
    id: "printkaro",
    name: "PrintKaro (photo printing)",
    secretHash: sha256(CLIENT_SECRET),
    redirectUris: [REDIRECT_URI],
    allowedScopes: ["photos.read"],
  }],
]);

const asUsers = new Map([
  ["u_rahul", { id: "u_rahul", username: "rahul" }],
  ["u_sneha", { id: "u_sneha", username: "sneha" }],
]);
const asSessions = new Map();      // sid -> { userId, expiresAt }   (the user's login AT PhotoVault)
const pendingConsents = new Map(); // consentId -> { userId, clientId, redirectUri, scope, state, expiresAt }
const codes = new Map();           // sha256(code) -> { clientId, redirectUri, userId, scope, expiresAt, usedAt, tokenHash }
const accessTokens = new Map();    // sha256(token) -> { userId, clientId, scope, expiresAt, revoked }

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
const ready = Promise.all([...asUsers.values()].map(async (u) => { u.passwordHash = await hashPassword("chai1234"); }));

const auth = newApp();

function currentAsUser(req) {
  const s = asSessions.get(parseCookies(req).as_sid);
  return s && s.expiresAt > Date.now() ? asUsers.get(s.userId) : null;
}

const loginPage = (next, error = "") => page("Sign in to PhotoVault", `
  <h2>📸 PhotoVault</h2><div class="box">
  <p>Sign in to <b>PhotoVault</b>. You are typing your password on <b>PhotoVault's</b> own page (${esc(AUTH_URL)}), not on the app's.</p>
  ${error && `<p style="color:#b91c1c">${esc(error)}</p>`}
  <form method="post" action="/login">
    <input name="username" placeholder="username (rahul)" autocomplete="username">
    <input name="password" type="password" placeholder="password (chai1234)" autocomplete="current-password">
    <input type="hidden" name="next" value="${esc(next)}">
    <button>Sign in</button>
  </form></div>`);

// Step 2: the AUTHORIZATION ENDPOINT. The user's BROWSER is sent here by the client (front channel).
auth.get("/authorize", (req, res) => {
  const [responseType, clientId, redirectUri, scope, state] = ["response_type", "client_id", "redirect_uri", "scope", "state"].map((k) => str(req.query[k]));
  const client = CLIENTS.get(clientId);
  // Unknown client or a redirect_uri that isn't registered EXACTLY: show an error here, never redirect.
  // Redirecting to an unchecked URL would send the code to an attacker (and make us an open redirector).
  if (!client || !client.redirectUris.includes(redirectUri)) {
    console.log(`❌ /authorize refused: client_id=${clientId} redirect_uri=${redirectUri}`);
    return res.status(400).send(page("Error", `<h2>Invalid request</h2><p>Unknown app or redirect address. You were <b>not</b> redirected.</p>`));
  }
  // From here on, the redirect_uri is trusted, so errors go back to the client the standard way
  const back = (params) => res.redirect(`${redirectUri}?${new URLSearchParams({ ...params, ...(state && { state }) })}`);
  if (responseType !== "code") return back({ error: "unsupported_response_type" });
  const scopes = (scope ?? "").split(" ").filter(Boolean);
  if (scopes.length === 0 || !scopes.every((s) => client.allowedScopes.includes(s))) return back({ error: "invalid_scope" });

  // Not logged in at PhotoVault yet: log in first, then come back to this exact URL
  const user = currentAsUser(req);
  if (!user) return res.send(loginPage(req.originalUrl));

  // Step 3: CONSENT. The server keeps the request details; the form only carries a random, one-time consentId.
  const consentId = randomToken();
  pendingConsents.set(consentId, { userId: user.id, clientId: client.id, redirectUri, scope: scopes, state, expiresAt: Date.now() + 5 * 60 * 1000 });
  res.send(page("Allow access?", `
    <h2>📸 PhotoVault</h2><div class="box">
    <p>Signed in as <b>${esc(user.username)}</b></p>
    <p><b>${esc(client.name)}</b> wants to:</p>
    <ul>${scopes.map((s) => `<li>${esc(SCOPES[s])} <small>(${esc(s)})</small></li>`).join("")}</ul>
    <p><small>It will <b>not</b> get your password, and can't do anything else. You can remove its access any time.</small></p>
    <form method="post" action="/consent">
      <input type="hidden" name="consentId" value="${esc(consentId)}">
      <button name="decision" value="allow">Allow</button><button name="decision" value="deny">Deny</button>
    </form></div>`));
});

auth.post("/login", async (req, res) => {
  const [username, password, next] = [req.body?.username, req.body?.password, req.body?.next].map(str);
  // Only ever go back to OUR authorize endpoint (no open redirect through the login form)
  if (!next || !next.startsWith("/authorize?")) return res.status(400).send(page("Error", "<p>Bad login request.</p>"));
  if (!username || !password) return res.status(400).send(loginPage(next, "Enter your username and password."));
  await ready;
  const user = [...asUsers.values()].find((u) => u.username === username.toLowerCase());
  const ok = await verifyPassword(password, user?.passwordHash ?? (await DUMMY_HASH_PROMISE)); // same timing for unknown users
  if (!user || !ok) return res.status(401).send(loginPage(next, "Wrong username or password."));
  const sid = randomToken();
  asSessions.set(sid, { userId: user.id, expiresAt: Date.now() + 60 * 60 * 1000 });
  res.set("Set-Cookie", `as_sid=${sid}; HttpOnly; SameSite=Lax; Path=/; Max-Age=3600`); // add Secure on HTTPS
  res.redirect(303, next);
});

auth.post("/consent", (req, res) => {
  const user = currentAsUser(req);
  const consentId = str(req.body?.consentId);
  const pending = consentId && pendingConsents.get(consentId);
  if (consentId) pendingConsents.delete(consentId); // one use only
  // The consent must belong to the user who is logged in now (this also blocks a forged form from another site)
  if (!user || !pending || pending.userId !== user.id || pending.expiresAt < Date.now()) {
    return res.status(400).send(page("Error", "<p>This request has expired. Go back to the app and try again.</p>"));
  }
  const back = (params) => res.redirect(303, `${pending.redirectUri}?${new URLSearchParams({ ...params, ...(pending.state && { state: pending.state }) })}`);
  if (str(req.body?.decision) !== "allow") {
    console.log(`🙅 ${user.id} denied ${pending.clientId}`);
    return back({ error: "access_denied" });
  }
  // Step 4: the AUTHORIZATION CODE: random, short-lived, one use, tied to this client, redirect_uri, user and scope
  const code = randomToken();
  codes.set(sha256(code), { clientId: pending.clientId, redirectUri: pending.redirectUri, userId: user.id, scope: pending.scope, expiresAt: Date.now() + CODE_TTL_MS, usedAt: null, tokenHash: null });
  console.log(`✅ ${user.id} allowed ${pending.clientId} [${pending.scope}] → code issued (valid 60 s, one use)`);
  back({ code });
});

// The client proves who IT is with its id + secret (HTTP Basic, as the spec recommends, or form fields)
function authenticateClient(req) {
  let id = str(req.body?.client_id), secret = str(req.body?.client_secret);
  const [scheme, value] = (req.headers.authorization ?? "").split(" ");
  if (scheme === "Basic" && value) {
    const decoded = Buffer.from(value, "base64").toString();
    const i = decoded.indexOf(":");
    if (i > 0) [id, secret] = [decodeURIComponent(decoded.slice(0, i)), decodeURIComponent(decoded.slice(i + 1))];
  }
  const client = id && CLIENTS.get(id);
  return client && secret && safeEqual(sha256(secret), client.secretHash) ? client : null;
}

const tokenError = (res, status, error, description) => res.status(status).json({ error, error_description: description });

// Step 5: the TOKEN ENDPOINT. The client's SERVER calls it directly (back channel): no browser, no URL bar.
auth.post("/token", (req, res) => {
  const client = authenticateClient(req);
  if (!client) {
    res.set("WWW-Authenticate", 'Basic realm="PhotoVault"');
    return tokenError(res, 401, "invalid_client", "Client authentication failed");
  }
  if (str(req.body?.grant_type) !== "authorization_code") return tokenError(res, 400, "unsupported_grant_type", "Only authorization_code is supported here");
  const code = str(req.body?.code);
  const record = code && codes.get(sha256(code));
  if (!record || record.clientId !== client.id) return tokenError(res, 400, "invalid_grant", "Unknown code");
  if (record.usedAt) {
    // A code used twice means it was stolen or replayed: kill the token it already produced
    const issued = record.tokenHash && accessTokens.get(record.tokenHash);
    if (issued) issued.revoked = true;
    console.log(`🚨 code reused by ${client.id}: the access token it issued is now revoked`);
    return tokenError(res, 400, "invalid_grant", "Code already used");
  }
  if (record.expiresAt < Date.now()) return tokenError(res, 400, "invalid_grant", "Code expired");
  if (str(req.body?.redirect_uri) !== record.redirectUri) return tokenError(res, 400, "invalid_grant", "redirect_uri does not match");

  record.usedAt = Date.now();
  const token = randomToken();
  record.tokenHash = sha256(token);
  accessTokens.set(record.tokenHash, { userId: record.userId, clientId: client.id, scope: record.scope, expiresAt: Date.now() + TOKEN_TTL_SECONDS * 1000, revoked: false });
  console.log(`🎟️  access token issued to ${client.id} for ${record.userId} [${record.scope}]`);
  res.set("Pragma", "no-cache");
  res.json({ access_token: token, token_type: "Bearer", expires_in: TOKEN_TTL_SECONDS, scope: record.scope.join(" ") });
});
finish(auth);

// =====================================================================================
// 2. RESOURCE SERVER: "PhotoVault API". Holds the photos. Only trusts access tokens.
// =====================================================================================
const photos = [
  { id: "ph_1", owner: "u_rahul", title: "Goa beach sunset" },
  { id: "ph_2", owner: "u_rahul", title: "Dadi's 80th birthday" },
  { id: "ph_3", owner: "u_rahul", title: "Diwali rangoli" },
  { id: "ph_4", owner: "u_sneha", title: "Sneha in Munnar" },
];
const api = newApp();

// Step 6: check the token, then the scope. The token says WHO (user) gave WHICH app (client) WHAT access (scope).
// shortcut: the API reads the authorization server's Map directly (same process). Real APIs verify a JWT access token
// with the server's public key (topic 18) or ask its introspection endpoint (topic 70).
function requireToken(scope) {
  return (req, res, next) => {
    const [scheme, token] = (req.headers.authorization ?? "").split(" ");
    const record = scheme === "Bearer" && token && accessTokens.get(sha256(token));
    if (!record || record.revoked || record.expiresAt < Date.now()) {
      res.set("WWW-Authenticate", 'Bearer error="invalid_token"');
      return res.status(401).json({ error: "invalid_token" });
    }
    if (!record.scope.includes(scope)) {
      res.set("WWW-Authenticate", `Bearer error="insufficient_scope", scope="${scope}"`);
      return res.status(403).json({ error: "insufficient_scope", needed: scope });
    }
    req.token = record;
    next();
  };
}

api.get("/photos", requireToken("photos.read"), (req, res) => {
  res.json({ user: req.token.userId, client: req.token.clientId, photos: photos.filter((p) => p.owner === req.token.userId) });
});

// PrintKaro is never allowed this scope, so its tokens can't delete anything
api.delete("/photos/:id", requireToken("photos.delete"), (req, res) => {
  const i = photos.findIndex((p) => p.id === req.params.id && p.owner === req.token.userId);
  if (i === -1) return res.status(404).json({ error: "Photo not found" });
  photos.splice(i, 1);
  res.status(204).end();
});
finish(api);

// =====================================================================================
// 3. CLIENT: "PrintKaro", a photo printing website. Wants Rahul's photos WITHOUT his PhotoVault password.
// =====================================================================================
const clientSessions = new Map(); // sid -> { state, accessToken, tokenExpiresAt }   (kept on PrintKaro's server, never in the browser)
const client = newApp();

function clientSession(req, res) {
  let sid = parseCookies(req).pk_sid;
  if (!sid || !clientSessions.has(sid)) {
    sid = randomToken();
    clientSessions.set(sid, {});
    res.append("Set-Cookie", `pk_sid=${sid}; HttpOnly; SameSite=Lax; Path=/`); // different name from as_sid: localhost cookies are shared across ports
  }
  return clientSessions.get(sid);
}

client.get("/", (req, res) => {
  const session = clientSession(req, res);
  const connected = session.accessToken && session.tokenExpiresAt > Date.now();
  res.send(page("PrintKaro", `
    <h2>🖨️ PrintKaro</h2><div class="box">
    <p>Print your memories on glossy paper, delivered across India. ₹15 per print.</p>
    ${connected
      ? `<p>✅ Connected to PhotoVault.</p><a class="btn" href="/photos">See my photos</a>`
      : `<p>Import photos straight from your PhotoVault account. We never see your PhotoVault password.</p>
         <a class="btn" href="/connect">Import from 📸 PhotoVault</a>`}
    </div>`));
});

// Step 2 (client side): send the user's browser to the authorization server
client.get("/connect", (req, res) => {
  const session = clientSession(req, res);
  // state: a random value we check when the user comes back, so nobody can push THEIR code into OUR session (topic 35)
  // shortcut: no PKCE here to keep the first flow small. Real apps add code_challenge / code_verifier (topic 34).
  session.state = randomToken(16);
  const params = new URLSearchParams({ response_type: "code", client_id: "printkaro", redirect_uri: REDIRECT_URI, scope: "photos.read", state: session.state });
  res.redirect(`${AUTH_URL}/authorize?${params}`);
});

// Step 5 (client side): the browser comes back with ?code=...&state=... and our SERVER swaps the code for a token
client.get("/callback", async (req, res) => {
  const session = clientSession(req, res);
  const [code, state, error] = ["code", "state", "error"].map((k) => str(req.query[k]));
  const expected = session.state;
  delete session.state; // one use
  if (!state || !expected || state !== expected) {
    return res.status(400).send(page("Error", `<h2>🖨️ PrintKaro</h2><p>That sign-in didn't start here (state mismatch). Please <a href="/">try again</a>.</p>`));
  }
  if (error) return res.send(page("Not connected", `<h2>🖨️ PrintKaro</h2><p>No problem, we didn't import anything (${esc(error)}). <a href="/">Back</a></p>`));
  if (!code) return res.status(400).send(page("Error", "<p>Missing code.</p>"));

  const tokenRes = await fetch(`${AUTH_URL}/token`, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Authorization: `Basic ${Buffer.from(`${encodeURIComponent("printkaro")}:${encodeURIComponent(CLIENT_SECRET)}`).toString("base64")}`,
    },
    body: new URLSearchParams({ grant_type: "authorization_code", code, redirect_uri: REDIRECT_URI }),
  });
  const data = await tokenRes.json();
  if (!tokenRes.ok) {
    console.log(`PrintKaro: token exchange failed: ${data.error}`);
    return res.status(502).send(page("Error", `<h2>🖨️ PrintKaro</h2><p>PhotoVault said no (${esc(data.error)}). <a href="/">Try again</a></p>`));
  }
  session.accessToken = data.access_token; // stays on OUR server; the browser only has our session cookie (topic 25)
  session.tokenExpiresAt = Date.now() + data.expires_in * 1000;
  res.redirect(303, "/photos");
});

// Step 6 (client side): call the API with the access token
client.get("/photos", async (req, res) => {
  const session = clientSession(req, res);
  if (!session.accessToken) return res.redirect("/");
  const apiRes = await fetch(`${API_URL}/photos`, { headers: { Authorization: `Bearer ${session.accessToken}` } });
  if (apiRes.status === 401) {
    delete session.accessToken; // expired or revoked: ask the user to connect again
    return res.send(page("Reconnect", `<h2>🖨️ PrintKaro</h2><p>Access to PhotoVault has ended. <a href="/connect">Connect again</a></p>`));
  }
  if (!apiRes.ok) return res.status(502).send(page("Error", "<p>PhotoVault is not available right now.</p>"));
  const data = await apiRes.json();
  res.send(page("Your photos", `
    <h2>🖨️ PrintKaro</h2><div class="box">
    <p>Photos imported from PhotoVault:</p>
    <ul>${data.photos.map((p) => `<li>🖼️ ${esc(p.title)} <small>(${esc(p.id)})</small></li>`).join("")}</ul>
    <p><small>We asked for <b>photos.read</b> only, so we can't delete or change anything in your PhotoVault.</small></p>
    </div>`));
});
finish(client);

ready.then(() => {
  auth.listen(AUTH_PORT, () => console.log(`📸 PhotoVault Accounts (authorization server) on ${AUTH_URL}`));
  api.listen(API_PORT, () => console.log(`📸 PhotoVault API (resource server)        on ${API_URL}`));
  client.listen(CLIENT_PORT, () => console.log(`🖨️  PrintKaro (client)                      on ${CLIENT_URL}  ← open this one (users rahul, sneha; password chai1234)`));
});
