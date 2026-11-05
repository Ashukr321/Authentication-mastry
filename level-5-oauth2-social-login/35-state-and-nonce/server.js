const express = require("express");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const { promisify } = require("util");

const scrypt = promisify(crypto.scrypt);
const SCRYPT_OPTIONS = { N: 2 ** 17, r: 8, p: 1, maxmem: 256 * 1024 * 1024 };

// Two apps, two ports, one file (topic 33 has the full three-role version)
const CLIENT_PORT = Number(process.env.PORT) || 3000; // PrintKaro: the CLIENT, offers "Log in with PhotoVault"
const AUTH_PORT = CLIENT_PORT + 1;                     // PhotoVault Accounts: the AUTHORIZATION SERVER (OpenID provider)
const CLIENT_URL = `http://localhost:${CLIENT_PORT}`;  // URLs from config, never from the Host header
const AUTH_URL = `http://localhost:${AUTH_PORT}`;
const PENDING_TTL_MS = 10 * 60 * 1000; // a login must finish within 10 minutes
// shortcut: a hard-coded demo secret. Real secrets are random, issued by the provider, and kept in a secret store.
const CLIENT_SECRET = process.env.CLIENT_SECRET || "printkaro-demo-secret-at-least-32-bytes-long";

// The client's callback runs in three versions so you can compare them. Only "safe" belongs in real code.
const VARIANTS = {
  safe:      { path: "/callback",                 checkState: true,  checkNonce: true },
  naive:     { path: "/buggy/naive/callback",     checkState: false, checkNonce: false }, // ❌ no state, no nonce
  "no-nonce": { path: "/buggy/no-nonce/callback", checkState: true,  checkNonce: false }, // ❌ state only
};

// ---------- Shared helpers ----------
const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");
const randomToken = (bytes = 32) => crypto.randomBytes(bytes).toString("base64url");
const safeEqual = (a, b) => crypto.timingSafeEqual(Buffer.from(sha256(a)), Buffer.from(sha256(b)));
const str = (v) => (typeof v === "string" ? v : undefined); // query/body values can be arrays: accept strings only
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
// AUTHORIZATION SERVER: PhotoVault Accounts. Issues codes, and ID tokens that carry the nonce.
// =====================================================================================
// shortcut: in-memory Maps, lost on restart.
const CLIENT = { id: "printkaro", secretHash: sha256(CLIENT_SECRET), redirectUris: Object.values(VARIANTS).map((v) => CLIENT_URL + v.path) };
const asUsers = new Map([
  ["u_rahul", { id: "u_rahul", username: "rahul", name: "Rahul Sharma" }],
  ["u_vikram", { id: "u_vikram", username: "vikram", name: "Vikram (attacker)" }],
]);
const asSessions = new Map(); // sid -> { userId, expiresAt }
const codes = new Map();      // sha256(code) -> { userId, redirectUri, nonce, expiresAt, used }

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

// shortcut: JSON login and no consent screen, so the attacks fit in curl. Topic 33 shows the real HTML pages.
auth.post("/login", async (req, res) => {
  const [username, password] = [req.body?.username, req.body?.password].map(str);
  if (!username || !password) return res.status(400).json({ error: "username and password are required" });
  await ready;
  const user = [...asUsers.values()].find((u) => u.username === username.toLowerCase());
  const ok = await verifyPassword(password, user?.passwordHash ?? (await DUMMY_HASH_PROMISE)); // same timing for unknown users
  if (!user || !ok) return res.status(401).json({ error: "Wrong username or password" });
  const sid = randomToken();
  asSessions.set(sid, { userId: user.id, expiresAt: Date.now() + 60 * 60 * 1000 });
  res.set("Set-Cookie", `as_sid=${sid}; HttpOnly; SameSite=Lax; Path=/; Max-Age=3600`);
  res.json({ ok: true, user: user.id });
});

auth.get("/authorize", (req, res) => {
  const [responseType, clientId, redirectUri, scope, state, nonce] = ["response_type", "client_id", "redirect_uri", "scope", "state", "nonce"].map((k) => str(req.query[k]));
  if (clientId !== CLIENT.id || !CLIENT.redirectUris.includes(redirectUri)) return res.status(400).json({ error: "invalid_request", error_description: "Unknown client or redirect_uri. Not redirecting." });
  const back = (params) => res.redirect(`${redirectUri}?${new URLSearchParams({ ...params, ...(state && { state }) })}`);
  if (responseType !== "code") return back({ error: "unsupported_response_type" });
  if (!(scope ?? "").split(" ").includes("openid")) return back({ error: "invalid_scope", error_description: "scope must include openid" });
  const s = asSessions.get(parseCookies(req).as_sid);
  if (!s || s.expiresAt < Date.now()) return res.status(401).json({ error: "login_required", error_description: "POST /login first" });

  // The AS doesn't check state: it just sends it back untouched. It's the CLIENT's job.
  // The nonce is saved with the code and copied into the ID token later.
  const code = randomToken();
  codes.set(sha256(code), { userId: s.userId, redirectUri, nonce, expiresAt: Date.now() + 60 * 1000, used: false });
  console.log(`📸 AS: code for ${s.userId} → ${redirectUri.replace(CLIENT_URL, "")} (nonce ${nonce ? nonce.slice(0, 6) + "…" : "none"})`);
  back({ code });
});

auth.post("/token", (req, res) => {
  const [scheme, value] = (req.headers.authorization ?? "").split(" ");
  const [id, secret] = scheme === "Basic" && value ? Buffer.from(value, "base64").toString().split(":").map(decodeURIComponent) : [];
  if (id !== CLIENT.id || !secret || !safeEqual(sha256(secret), CLIENT.secretHash)) return res.status(401).json({ error: "invalid_client" });
  if (str(req.body?.grant_type) !== "authorization_code") return res.status(400).json({ error: "unsupported_grant_type" });
  const code = str(req.body?.code);
  const record = code && codes.get(sha256(code));
  if (!record || record.used || record.expiresAt < Date.now() || str(req.body?.redirect_uri) !== record.redirectUri) {
    return res.status(400).json({ error: "invalid_grant" });
  }
  record.used = true;
  const user = asUsers.get(record.userId);
  // The ID token: a signed statement "this user just logged in, for THIS client, for THIS login request (nonce)".
  // OpenID Connect allows HS256 signed with the client secret for confidential clients. Topic 36 uses RS256 + JWKS.
  const idToken = jwt.sign({ sub: user.id, name: user.name, ...(record.nonce && { nonce: record.nonce }) }, CLIENT_SECRET,
    { algorithm: "HS256", issuer: AUTH_URL, audience: CLIENT.id, expiresIn: "5m" });
  // shortcut: no access token / API in this demo (topic 33 has one). Only the login part matters here.
  res.json({ token_type: "Bearer", id_token: idToken });
});
finish(auth);

// =====================================================================================
// CLIENT: PrintKaro. "Log in with PhotoVault". This is where state and nonce are created and CHECKED.
// =====================================================================================
const clientSessions = new Map(); // sid -> { pending: Map(state -> { nonce, returnTo, expiresAt }), user }
const client = newApp();

function clientSession(req, res) {
  let sid = parseCookies(req).pk_sid;
  if (!sid || !clientSessions.has(sid)) {
    sid = randomToken();
    clientSessions.set(sid, { pending: new Map(), user: null });
    res.append("Set-Cookie", `pk_sid=${sid}; HttpOnly; SameSite=Lax; Path=/`); // a different name from as_sid: localhost cookies are shared across ports
  }
  return { sid, session: clientSessions.get(sid) };
}

// Step 1: start the login. Make a fresh state and nonce, remember them IN THIS USER'S SESSION, send them along.
client.get("/login", (req, res) => {
  const { session } = clientSession(req, res);
  const variant = VARIANTS[str(req.query.variant) ?? "safe"];
  if (!variant) return res.status(400).json({ error: `variant must be one of: ${Object.keys(VARIANTS).join(", ")}` });
  // Where to go after login. Kept on OUR server, never put in the URL as-is, and only a local path (no open redirect).
  const returnTo = str(req.query.returnTo) ?? "/me";
  if (!returnTo.startsWith("/") || returnTo.startsWith("//")) return res.status(400).json({ error: "returnTo must be a local path" });

  const state = randomToken(16); // unguessable, one use, tied to this browser's session
  const nonce = randomToken(16); // will come back INSIDE the signed ID token
  session.pending.set(state, { nonce, returnTo, expiresAt: Date.now() + PENDING_TTL_MS }); // a Map, so two tabs can log in at once
  const params = new URLSearchParams({ response_type: "code", client_id: CLIENT.id, redirect_uri: CLIENT_URL + variant.path, scope: "openid", state, nonce });
  // shortcut: no PKCE, to show what state and nonce do on their own. Real apps add PKCE too (topic 34): it also blocks attack 2.
  res.redirect(`${AUTH_URL}/authorize?${params}`);
});

function handleCallback({ checkState, checkNonce }) {
  return async (req, res) => {
    const { sid, session } = clientSession(req, res);
    const [code, state, error] = ["code", "state", "error"].map((k) => str(req.query[k]));

    // Step 2: STATE. Did THIS browser start THIS login? If not, someone else's login is being pushed into our session.
    let pending = null;
    if (checkState) {
      pending = state ? session.pending.get(state) : null;
      if (state) session.pending.delete(state); // one use
      if (!pending || pending.expiresAt < Date.now()) {
        console.log(`🚨 PrintKaro: state check failed (${state ? "unknown or expired state" : "no state"}): login refused`);
        return res.status(400).json({ error: "This login didn't start in this browser (state mismatch). Please start again." });
      }
    }
    if (error) return res.status(400).json({ error: `PhotoVault said: ${error}` });
    if (!code) return res.status(400).json({ error: "Missing code" });

    const tokenRes = await fetch(`${AUTH_URL}/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded", Authorization: `Basic ${Buffer.from(`${CLIENT.id}:${encodeURIComponent(CLIENT_SECRET)}`).toString("base64")}` },
      body: new URLSearchParams({ grant_type: "authorization_code", code, redirect_uri: CLIENT_URL + req.path }),
    });
    const data = await tokenRes.json();
    if (!tokenRes.ok) return res.status(400).json({ error: `Token exchange failed: ${data.error}` });

    // Validate the ID token like any JWT (topic 27): algorithm pinned, signature, issuer, audience, expiry
    let claims;
    try {
      claims = jwt.verify(data.id_token, CLIENT_SECRET, { algorithms: ["HS256"], issuer: AUTH_URL, audience: CLIENT.id, clockTolerance: 30 });
    } catch (e) {
      return res.status(400).json({ error: `Invalid ID token: ${e.message}` });
    }

    // Step 3: NONCE. Was this ID token made for the login THIS browser started? (it's inside the signature, so it can't be edited)
    if (checkNonce && (!claims.nonce || !safeEqual(claims.nonce, pending.nonce))) {
      console.log(`🚨 PrintKaro: nonce mismatch: ID token for ${claims.sub} belongs to a different login: refused`);
      return res.status(400).json({ error: "This sign-in was not started here (nonce mismatch). Please start again." });
    }

    // Logged in. New session id after login, so a session id planted before login is useless (topic 50).
    clientSessions.delete(sid);
    const newSid = randomToken();
    clientSessions.set(newSid, { pending: new Map(), user: { sub: claims.sub, name: claims.name } });
    res.set("Set-Cookie", `pk_sid=${newSid}; HttpOnly; SameSite=Lax; Path=/`);
    console.log(`✅ PrintKaro (${req.path}): browser is now logged in as ${claims.sub}`);
    res.redirect(303, pending?.returnTo ?? "/me");
  };
}
for (const variant of Object.values(VARIANTS)) client.get(variant.path, handleCallback(variant));

client.get("/me", (req, res) => {
  const { session } = clientSession(req, res);
  res.json(session.user ? { loggedInAs: session.user.sub, name: session.user.name } : { loggedInAs: null });
});
client.get("/orders", (req, res) => {
  const { session } = clientSession(req, res);
  if (!session.user) return res.status(401).json({ error: "Please log in" });
  res.json({ user: session.user.sub, orders: [], note: "returnTo brought you here after login" });
});
finish(client);

ready.then(() => {
  auth.listen(AUTH_PORT, () => console.log(`📸 PhotoVault Accounts (authorization server) on ${AUTH_URL}`));
  client.listen(CLIENT_PORT, () => console.log(`🖨️  PrintKaro (client) on ${CLIENT_URL}  (users rahul, vikram; password chai1234)`));
});
