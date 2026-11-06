const express = require("express");
const crypto = require("crypto");

const PORT = Number(process.env.PORT) || 3000;
const BASE_URL = `http://localhost:${PORT}`;
const ISSUER = `${BASE_URL}/idp`;
const BACKCHANNEL_EVENT = "http://schemas.openid.net/event/backchannel-logout";
const IDP_SESSION_MS = 12 * 60 * 60 * 1000; // the IdP login ends 12 h after login
const APP_SESSION_MS = 8 * 60 * 60 * 1000;  // an app's own session ends 8 h after login, SLO or not

// shortcut: ONE process plays four sites: the IdP (/idp) and three apps (/mail, /drive, /chat).
// In real life they are separate origins (accounts.chai.com, mail.chai.com, ...). Each cookie gets its own
// Path here so the four "sites" still have separate cookie jars in the browser (and in curl).

// ---------- "Database" ----------
// shortcut: in-memory Maps, lost on restart. A real IdP and real apps use database tables (or Redis).
const users = new Map();       // email -> { id, email, salt, passwordHash }
const idpSessions = new Map(); // sha256(idp cookie) -> { sid, userId, email, apps: Set(client_id), createdAt }
const codes = new Map();       // sha256(code) -> { clientId, userId, email, sid, expiresAt }

// ---------- Helpers ----------
const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");
const randomToken = () => crypto.randomBytes(32).toString("base64url");
const str = (v) => (typeof v === "string" ? v : undefined);
const nowSec = () => Math.floor(Date.now() / 1000);
const safeEqual = (a, b) => crypto.timingSafeEqual(Buffer.from(sha256(a)), Buffer.from(sha256(b)));
const parseCookies = (req) => Object.fromEntries((req.headers.cookie ?? "").split(";").filter((c) => c.includes("="))
  .map((c) => [c.slice(0, c.indexOf("=")).trim(), c.slice(c.indexOf("=") + 1).trim()]));

const DUMMY_SALT = crypto.randomBytes(16);
// shortcut: one test account with a known password. A real app has a signup (topic 06).
for (const [id, email, password] of [["user-1001", "rahul@mail.com", "chai-and-code-42"]]) {
  const salt = crypto.randomBytes(16);
  users.set(email, { id, email, salt, passwordHash: crypto.scryptSync(password, salt, 64) });
}
function checkPassword(email, password) {
  const user = email ? users.get(email) : undefined;
  const hash = crypto.scryptSync(password ?? "", user?.salt ?? DUMMY_SALT, 64); // same time for unknown emails (topic 51)
  return user && crypto.timingSafeEqual(hash, user.passwordHash) ? user : null;
}

// ---------- JWTs signed by the IdP (ID tokens and logout tokens) ----------
// shortcut: a new RSA key on every restart, and the apps use `publicKey` directly "as if fetched from the IdP's JWKS".
// A real IdP keeps its keys, publishes them at jwks_uri with a `kid`, and rotates them (topics 22, 54).
const { privateKey, publicKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
const b64json = (obj) => Buffer.from(JSON.stringify(obj)).toString("base64url");

function signJwt(payload, typ = "JWT") {
  const data = `${b64json({ alg: "RS256", typ })}.${b64json(payload)}`;
  return `${data}.${crypto.sign("sha256", Buffer.from(data), privateKey).toString("base64url")}`;
}

function verifyJwt(token) {
  try {
    const [h, p, sig, extra] = (token ?? "").split(".");
    if (!sig || extra !== undefined) return null;
    const header = JSON.parse(Buffer.from(h, "base64url"));
    const payload = JSON.parse(Buffer.from(p, "base64url"));
    // Only RS256. Never let the token choose "none" or HS256 (topic 53).
    if (header?.alg !== "RS256" || !payload || typeof payload !== "object") return null;
    const ok = crypto.verify("sha256", Buffer.from(`${h}.${p}`), publicKey, Buffer.from(sig, "base64url"));
    return ok ? { header, payload } : null;
  } catch {
    return null;
  }
}

// ---------- Registered apps (OIDC clients) ----------
// Every URL the IdP will ever call or redirect to is REGISTERED up front. Nothing is taken from the request.
const clients = {
  mail:  { name: "📧 ChaiMail",  secret: "mail-secret-123",  backchannel: true },
  drive: { name: "📁 ChaiDrive", secret: "drive-secret-456", backchannel: true },
  chat:  { name: "💬 ChaiChat",  secret: "chat-secret-789",  backchannel: false }, // an old app with no SLO support
};
for (const [id, c] of Object.entries(clients)) {
  c.id = id;
  c.redirectUri = `${BASE_URL}/${id}/callback`;
  c.postLogoutRedirectUri = `${BASE_URL}/${id}/logged-out`;
  c.backchannelLogoutUri = c.backchannel ? `${BASE_URL}/${id}/backchannel-logout` : null;
}
// Object.hasOwn: so "?client_id=constructor" doesn't find Object's built-in properties
const getClient = (id) => (id && Object.hasOwn(clients, id) ? clients[id] : null);

// ---------- App ----------
const app = express();
app.use(express.json({ limit: "10kb" }));
app.use(express.urlencoded({ extended: false, limit: "10kb" })); // /token and back-channel logout are form posts
app.use((req, res, next) => {
  res.set("Cache-Control", "no-store"); // the back-channel spec requires it, and session pages need it anyway
  next();
});

// =====================================================================
//  THE IdP (identity provider): one login for every app (topics 57, 60)
// =====================================================================
const IDP_COOKIE = { httpOnly: true, sameSite: "lax", path: "/idp" };

function getIdpSession(req) {
  const value = parseCookies(req).idp_sid;
  const key = value && sha256(value);
  const s = key && idpSessions.get(key);
  if (!s) return null;
  if (Date.now() - s.createdAt > IDP_SESSION_MS) { idpSessions.delete(key); return null; }
  return { key, s };
}

// What an app reads to learn that this IdP supports logout, and where (OpenID Connect Discovery)
app.get("/idp/.well-known/openid-configuration", (req, res) => {
  res.json({
    issuer: ISSUER,
    authorization_endpoint: `${ISSUER}/authorize`,
    token_endpoint: `${ISSUER}/token`,
    end_session_endpoint: `${ISSUER}/logout`,  // STEP 2: RP-initiated logout lands here
    backchannel_logout_supported: true,        // STEP 3: the IdP calls each app server-to-server
    backchannel_logout_session_supported: true, // ...and puts the `sid` in the logout token
    frontchannel_logout_supported: false,      // iframes: broken by third-party cookie blocking (see notes)
  });
});

// shortcut: a JSON login instead of the IdP's login page (and no MFA, topic 45)
app.post("/idp/login", async (req, res) => {
  const user = checkPassword(str(req.body?.email)?.trim().toLowerCase(), str(req.body?.password));
  if (!user) return res.status(401).json({ error: "Wrong email or password" });
  const old = getIdpSession(req);
  if (old) await endIdpSession(old.key); // new id at login (topic 50); the old session's apps are told
  const cookie = randomToken();
  // `sid` is the PUBLIC name of this login session. It goes into tokens; the cookie value never does.
  const s = { sid: crypto.randomUUID(), userId: user.id, email: user.email, apps: new Set(), createdAt: Date.now() };
  idpSessions.set(sha256(cookie), s);
  res.cookie("idp_sid", cookie, IDP_COOKIE);
  res.json({ message: `Signed in to the IdP as ${user.email}`, sid: s.sid });
});

app.get("/idp/me", (req, res) => {
  const cur = getIdpSession(req);
  if (!cur) return res.status(401).json({ error: "Not signed in to the IdP" });
  res.json({ email: cur.s.email, sid: cur.s.sid, appsSignedIn: [...cur.s.apps] });
});

// STEP 1: SSO login. The IdP REMEMBERS every app the user signed in to during this session.
// That list is what makes single logout possible later.
// shortcut: no PKCE or nonce (topics 35, 60), so the demo stays about logout.
app.get("/idp/authorize", (req, res) => {
  const client = getClient(str(req.query.client_id));
  if (!client || req.query.redirect_uri !== client.redirectUri) return res.status(400).json({ error: "Unknown client_id or redirect_uri" });
  const cur = getIdpSession(req);
  // shortcut: a real IdP shows its login page here; the demo asks you to POST /idp/login first
  if (!cur) return res.status(401).json({ error: "login_required", hint: "POST /idp/login first" });

  cur.s.apps.add(client.id);
  const code = randomToken();
  codes.set(sha256(code), { clientId: client.id, userId: cur.s.userId, email: cur.s.email, sid: cur.s.sid, expiresAt: Date.now() + 60_000 });
  const url = new URL(client.redirectUri);
  url.searchParams.set("code", code);
  url.searchParams.set("state", str(req.query.state) ?? "");
  res.redirect(url.href);
});

app.post("/idp/token", (req, res) => {
  const client = getClient(str(req.body?.client_id));
  if (!client || !safeEqual(str(req.body?.client_secret) ?? "", client.secret)) return res.status(401).json({ error: "invalid_client" });
  const key = sha256(str(req.body.code) ?? "");
  const c = codes.get(key);
  codes.delete(key); // single use
  if (!c || c.clientId !== client.id || c.expiresAt < Date.now() || req.body.redirect_uri !== client.redirectUri) {
    return res.status(400).json({ error: "invalid_grant" });
  }
  const iat = nowSec();
  // The ID token carries `sid`, so the app can later match a logout token to the right local session
  const idToken = signJwt({ iss: ISSUER, sub: c.userId, aud: client.id, iat, exp: iat + 300, email: c.email, sid: c.sid });
  res.json({ token_type: "Bearer", id_token: idToken, expires_in: 300 }); // shortcut: no access token, the apps don't call APIs
});

// STEP 3: end the IdP session and tell EVERY app in it, server to server (OIDC Back-Channel Logout 1.0)
async function endIdpSession(key) {
  const s = idpSessions.get(key);
  if (!s) return [];
  idpSessions.delete(key); // first: whatever happens below, no app can silently log back in through this session

  return Promise.all([...s.apps].map(async (clientId) => {
    const client = clients[clientId];
    if (!client.backchannelLogoutUri) {
      console.log(`⚠️  ${client.name} has no backchannel_logout_uri: its own session stays alive until it expires`);
      return { app: clientId, result: "not supported" };
    }
    const iat = nowSec();
    const logoutToken = signJwt({
      iss: ISSUER,
      aud: clientId,                      // a token for Mail can't be replayed at Drive
      iat,
      exp: iat + 120,
      jti: crypto.randomUUID(),           // the app remembers it, so the same token can't be replayed
      sub: s.userId,
      sid: s.sid,                         // which login session to end (not "every session of this user")
      events: { [BACKCHANNEL_EVENT]: {} }, // what makes it a LOGOUT token and not an ID token
    }, "logout+jwt");
    try {
      const r = await fetch(client.backchannelLogoutUri, {
        method: "POST",
        body: new URLSearchParams({ logout_token: logoutToken }), // form-encoded, as the spec says
        signal: AbortSignal.timeout(3000), // one slow app must not hang everybody's logout
      });
      console.log(`📡 back-channel logout → ${client.name}: ${r.status}`);
      return { app: clientId, result: r.status };
    } catch (err) {
      // shortcut: a real IdP retries a few times and alerts; the app's session stays alive meanwhile
      console.log(`❌ back-channel logout → ${client.name} failed: ${err.message}`);
      return { app: clientId, result: "failed" };
    }
  }));
}

// STEP 2: RP-initiated logout (OIDC RP-Initiated Logout 1.0). The app sends the browser here.
app.get("/idp/logout", async (req, res) => {
  const hint = str(req.query.id_token_hint);
  const redirect = str(req.query.post_logout_redirect_uri);
  // The hint only says WHO is logging out, so an expired one is fine. A forged one is not.
  const claims = hint ? verifyJwt(hint)?.payload : null;
  if (hint && claims?.iss !== ISSUER) return res.status(400).json({ error: "Invalid id_token_hint" });

  // Only redirect to a URL the app REGISTERED. Otherwise /idp/logout is an open redirect for phishing.
  if (redirect) {
    const client = getClient(claims ? str(claims.aud) : str(req.query.client_id));
    if (!client || redirect !== client.postLogoutRedirectUri) {
      return res.status(400).json({ error: "post_logout_redirect_uri is not registered for this app" });
    }
  }

  const cur = getIdpSession(req);
  if (cur && claims?.sid !== cur.s.sid) {
    // No hint (or a hint for a different session): maybe an <img src=".../idp/logout"> on some other site.
    // Logging out everywhere is disruptive, so ASK. The button POSTs, and SameSite=Lax blocks cross-site POSTs.
    return res.json({ message: `Sign out of all apps as ${cur.s.email}?`, confirm: "POST /idp/logout" });
  }
  if (cur) {
    await endIdpSession(cur.key); // wait for the apps, THEN send the browser back
    res.clearCookie("idp_sid", IDP_COOKIE);
  }
  if (redirect) return res.redirect(redirect);
  res.json({ message: "Signed out" });
});

// IdP-initiated logout: the "Sign out everywhere" button on the IdP's own page (or the confirm step above)
app.post("/idp/logout", async (req, res) => {
  const cur = getIdpSession(req);
  if (!cur) return res.status(401).json({ error: "Not signed in to the IdP" });
  const apps = await endIdpSession(cur.key);
  res.clearCookie("idp_sid", IDP_COOKIE);
  res.json({ message: "Signed out of the IdP and every app", apps });
});

// =====================================================================
//  THE APPS (relying parties). Same code three times, each with its own sessions.
// =====================================================================
function mountApp(client) {
  const sessions = new Map(); // sha256(app cookie) -> { sub, email, idpSid, idToken, createdAt }
  const seenJti = new Map();  // jti -> exp, for replay protection of logout tokens
  const COOKIE = { httpOnly: true, sameSite: "lax", path: `/${client.id}` };
  const cookieName = `${client.id}_sid`;
  const r = express.Router();

  function getSession(req) {
    const value = parseCookies(req)[cookieName];
    const key = value && sha256(value);
    const s = key && sessions.get(key);
    if (!s) return null;
    if (Date.now() - s.createdAt > APP_SESSION_MS) { sessions.delete(key); return null; }
    return { key, s };
  }

  r.get("/login", (req, res) => {
    const state = randomToken(); // login CSRF protection (topic 35)
    res.cookie(`${client.id}_state`, state, { ...COOKIE, maxAge: 10 * 60 * 1000 });
    const url = new URL(`${ISSUER}/authorize`);
    url.search = new URLSearchParams({ response_type: "code", scope: "openid email", client_id: client.id, redirect_uri: client.redirectUri, state });
    res.redirect(url.href);
  });

  r.get("/callback", async (req, res) => {
    const state = parseCookies(req)[`${client.id}_state`];
    res.clearCookie(`${client.id}_state`, COOKIE);
    if (!state || req.query.state !== state) return res.status(400).json({ error: "State mismatch" });

    const tokenRes = await fetch(`${ISSUER}/token`, {
      method: "POST",
      body: new URLSearchParams({ grant_type: "authorization_code", code: str(req.query.code) ?? "", redirect_uri: client.redirectUri, client_id: client.id, client_secret: client.secret }),
      signal: AbortSignal.timeout(3000),
    });
    const body = await tokenRes.json();
    const claims = tokenRes.ok ? verifyJwt(body.id_token)?.payload : null;
    if (!claims || claims.iss !== ISSUER || claims.aud !== client.id || !(claims.exp > nowSec())) {
      return res.status(401).json({ error: "Login failed" });
    }
    const cookie = randomToken();
    // Keep `sid` (to match back-channel logout) and the ID token (the id_token_hint for RP-initiated logout)
    sessions.set(sha256(cookie), { sub: claims.sub, email: claims.email, idpSid: claims.sid, idToken: body.id_token, createdAt: Date.now() });
    res.cookie(cookieName, cookie, COOKIE);
    res.json({ message: `Signed in to ${client.name} as ${claims.email}`, sid: claims.sid });
  });

  r.get("/me", (req, res) => {
    const cur = getSession(req);
    if (!cur) return res.status(401).json({ error: `Not signed in to ${client.name}` });
    res.json({ app: client.name, email: cur.s.email, sid: cur.s.idpSid });
  });

  // ❌ LOCAL logout only: ends this app's session. The IdP session lives on, so the next
  // "Sign in" is silent and needs no password, and the other apps never hear about it.
  r.post("/logout-local", (req, res) => {
    const cur = getSession(req);
    if (cur) sessions.delete(cur.key);
    res.clearCookie(cookieName, COOKIE);
    res.json({ message: `Signed out of ${client.name} (only here)` });
  });

  // ✅ STEP 2: SINGLE logout. End our session, then send the browser to the IdP's end_session_endpoint.
  // POST, so another site can't log you out with a link (logout CSRF).
  r.post("/logout", (req, res) => {
    const cur = getSession(req);
    if (cur) sessions.delete(cur.key);
    res.clearCookie(cookieName, COOKIE);
    const url = new URL(`${ISSUER}/logout`);
    if (cur) url.searchParams.set("id_token_hint", cur.s.idToken); // proves to the IdP which session this is
    url.searchParams.set("client_id", client.id);
    url.searchParams.set("post_logout_redirect_uri", client.postLogoutRedirectUri);
    res.redirect(url.href);
  });

  r.get("/logged-out", (req, res) => res.json({ message: `You're signed out of ${client.name}` }));

  // ✅ STEP 4: the back-channel logout endpoint. The IdP's SERVER calls this; no browser, no cookie.
  // So we can't clear a cookie: we delete our server-side session, and the next request with that cookie gets 401.
  if (client.backchannelLogoutUri) {
    r.post("/backchannel-logout", (req, res) => {
      const reject = (why) => {
        console.log(`🛑 ${client.name} rejected a logout_token: ${why}`);
        res.status(400).json({ error: "invalid_request", error_description: why });
      };
      const jwt = verifyJwt(str(req.body?.logout_token));
      if (!jwt) return reject("bad signature or alg (only RS256 signed by our IdP)");
      const { header, payload: t } = jwt;
      // An ID token is ALSO signed by the IdP. These two checks stop one being replayed as a logout token.
      if (header.typ !== "logout+jwt" || !t.events?.[BACKCHANNEL_EVENT]) return reject("not a logout token (typ / events claim)");
      if ("nonce" in t) return reject("a logout token must not contain a nonce");
      if (t.iss !== ISSUER || ![].concat(t.aud).includes(client.id)) return reject("wrong iss or aud");
      const now = nowSec();
      if (!(t.iat > now - 120 && t.iat <= now + 30) || !(t.exp > now)) return reject("expired or too old");
      if (!t.sid && !t.sub) return reject("needs a sid or sub");
      if (typeof t.jti !== "string" || seenJti.has(t.jti)) return reject("jti missing or already used (replay)");
      seenJti.set(t.jti, t.exp);

      // With `sid`: end only the sessions from THAT IdP login. Without it: every session of that user.
      let ended = 0;
      for (const [key, s] of sessions) {
        if (t.sid ? s.idpSid === t.sid : s.sub === t.sub) { sessions.delete(key); ended++; }
      }
      console.log(`🔒 ${client.name}: logout_token OK for sid ${t.sid ?? "-"}, ended ${ended} session(s)`);
      res.sendStatus(200); // 200 even when nothing was found: the user is logged out either way
    });
  }

  // Sweep expired sessions and old jti's so the Maps don't grow forever
  setInterval(() => {
    for (const [k, s] of sessions) if (Date.now() - s.createdAt > APP_SESSION_MS) sessions.delete(k);
    for (const [jti, exp] of seenJti) if (exp < nowSec()) seenJti.delete(jti);
  }, 60_000).unref();

  app.use(`/${client.id}`, r);
}
Object.values(clients).forEach(mountApp);

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
  console.log(`🔑 IdP on ${ISSUER}`);
  for (const c of Object.values(clients)) console.log(`${c.name} on ${BASE_URL}/${c.id}`);
});

setInterval(() => {
  for (const [k, c] of codes) if (c.expiresAt < Date.now()) codes.delete(k);
}, 60_000).unref();
