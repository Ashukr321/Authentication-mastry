const express = require("express");
const crypto = require("crypto");

// Three servers from one file: ONE identity provider and TWO apps that trust it.
const PORT = Number(process.env.PORT) || 3000;
const IDP_URL = `http://localhost:${PORT}`;     // 🔐 ChaiCorp Login (the IdP, like Okta / Azure AD / Keycloak)
const HR_PORT = PORT + 1;                        // 👥 HR Portal (an SP)
const PAYROLL_PORT = PORT + 2;                   // 💰 Payroll  (an SP)
const ASSERTION_TTL_S = 120;                     // an assertion is a one-way ticket: use it within 2 minutes
const CLOCK_SKEW_S = 30;                         // servers' clocks are never exactly equal
const IDP_SESSION_MS = 8 * 60 * 60 * 1000;       // one work day: log in once in the morning
const SP_SESSION_MS = 60 * 60 * 1000;            // each app keeps its OWN shorter session

// ---------- Helpers ----------
const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");
const randomToken = () => crypto.randomBytes(32).toString("base64url");
const str = (v) => (typeof v === "string" ? v : undefined);
const nowS = () => Math.floor(Date.now() / 1000);
const parseCookies = (req) => Object.fromEntries((req.headers.cookie ?? "").split(";").filter((c) => c.includes("="))
  .map((c) => [c.slice(0, c.indexOf("=")).trim(), c.slice(c.indexOf("=") + 1).trim()]));
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
const page = (title, body) => `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>${esc(title)}</title>
<style>body{font-family:system-ui,sans-serif;max-width:560px;margin:48px auto;padding:0 16px;line-height:1.5}
input,button{font:inherit;padding:8px 12px}input{width:100%;box-sizing:border-box;margin:6px 0}</style></head>
<body>${body}</body></html>`;
// shortcut: all three servers are on "localhost", and browsers share cookies across ports of the same host.
// So every server uses its OWN cookie name (idp_sid, hr_sid, payroll_sid). Real IdPs and apps live on different domains.
// shortcut: no Secure flag because the demo runs on http://localhost. In production add `secure: true` (topic 10).
const COOKIE = { httpOnly: true, sameSite: "lax", path: "/" };

// ---------- Basic error handling, shared by all three servers ----------
function finish(app) {
  app.use((req, res) => res.status(404).json({ error: "Not found" }));
  // Never send the stack trace to the client
  app.use((err, req, res, next) => {
    if (err.type === "entity.parse.failed") return res.status(400).json({ error: "Body must be valid JSON" });
    if (err.type === "entity.too.large") return res.status(413).json({ error: "Request body too large" });
    console.error(err);
    res.status(500).json({ error: "Something went wrong" });
  });
}
function base(app) {
  app.use(express.json({ limit: "10kb" }));
  app.use(express.urlencoded({ extended: false, limit: "10kb" }));
  app.use((req, res, next) => { res.set("Cache-Control", "no-store"); next(); });
}
// Express 5 passes a listen error (like "port already in use") to the callback instead of crashing
const listen = (app, port, label) => app.listen(port, (err) => { if (err) throw err; console.log(label); });

// =====================================================================
// 🔐 THE IDENTITY PROVIDER (IdP): the ONLY place passwords are typed
// =====================================================================

// STEP 1 (trust setup): the IdP signs with a PRIVATE key; every app gets the PUBLIC key once, via metadata.
// shortcut: a new key on every start. A real IdP keeps it in a KMS/HSM and publishes old + new keys while rotating (topic 54).
const { privateKey, publicKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });

// shortcut: in-memory Maps, lost on restart. A real IdP uses database tables (and a directory like Active Directory, topic 63).
const idpUsers = new Map();    // email -> { id, email, name, department, salt, passwordHash }
const idpSessions = new Map(); // sha256(sid) -> { email, authAt, expiresAt, apps: Set }

// shortcut: test employees with known passwords. A real IdP gets them from HR / SCIM (topic 62).
for (const [email, name, department, password] of [
  ["rahul@chaicorp.com", "Rahul Sharma", "Engineering", "chai-and-code-42"],
  ["priya@chaicorp.com", "Priya Iyer", "Finance", "masala-dosa-77"],
]) {
  const salt = crypto.randomBytes(16);
  idpUsers.set(email, { id: crypto.randomUUID(), email, name, department, salt, passwordHash: crypto.scryptSync(password, salt, 64) });
}
const DUMMY_SALT = crypto.randomBytes(16);

// STEP 1 (trust setup): the IdP only knows apps an admin REGISTERED, each with its fixed ACS URL.
// It never sends an assertion to a URL that came from the request: that would hand tokens to an attacker.
const serviceProviders = new Map([
  ["hr-portal", { name: "HR Portal", acs: `http://localhost:${HR_PORT}/acs` }],
  ["payroll", { name: "Payroll", acs: `http://localhost:${PAYROLL_PORT}/acs` }],
]);

// A signed assertion = base64url(JSON) + "." + base64url(RSA-SHA256 signature).
// (SAML signs XML, OIDC signs a JWT: same idea, topics 58 and 60.)
function signAssertion(claims) {
  const body = Buffer.from(JSON.stringify(claims)).toString("base64url");
  return `${body}.${crypto.sign("sha256", Buffer.from(body), privateKey).toString("base64url")}`;
}

function getIdpSession(req) {
  const sid = parseCookies(req).idp_sid;
  const key = sid && sha256(sid);
  const s = key && idpSessions.get(key);
  if (!s) return null;
  if (Date.now() > s.expiresAt) { idpSessions.delete(key); return null; }
  return s;
}

// STEP 4: build the assertion for THIS app and THIS request, and auto-POST it to the app's registered ACS URL.
// This is the "HTTP-POST binding": the browser carries it, so the IdP and the app never talk to each other directly.
function sendAssertion(res, session, sp, spId, requestId, relayState) {
  const user = idpUsers.get(session.email);
  const iat = nowS();
  const assertion = signAssertion({
    id: crypto.randomUUID(),         // unique, so the app can refuse a replay
    iss: IDP_URL,                    // WHO says this
    sub: user.id,                    // a STABLE id: emails change, this doesn't
    email: user.email, name: user.name, department: user.department,
    aud: spId,                       // WHICH app it's for: another app must refuse it
    acs: sp.acs,                     // WHERE it may be delivered
    inResponseTo: requestId ?? null, // WHICH login request it answers (null = IdP-initiated)
    authAt: Math.floor(session.authAt / 1000), // when the password was really typed
    iat, exp: iat + ASSERTION_TTL_S,
  });
  session.apps.add(spId); // the IdP remembers which apps you're in (needed for Single Logout, topic 61)
  console.log(`🎫 IdP → ${sp.name}: assertion for ${user.email}`);
  res.send(page("Signing you in…", `<p>Signing you in to <b>${esc(sp.name)}</b>…</p>
<form method="post" action="${esc(sp.acs)}">
<input type="hidden" name="assertion" value="${esc(assertion)}">
<input type="hidden" name="relay_state" value="${esc(relayState)}">
<noscript><button>Continue</button></noscript></form>
<script>document.forms[0].submit()</script>`));
}

const idp = express();
base(idp);

// STEP 1: metadata. An app's admin copies this ONCE when setting up the trust (SAML metadata XML / OIDC discovery JSON).
idp.get("/metadata", (req, res) => {
  res.json({ issuer: IDP_URL, ssoUrl: `${IDP_URL}/sso`, signingKey: publicKey.export({ type: "spki", format: "pem" }) });
});

// STEP 3: an app sent the browser here. Already logged in at the IdP? Then no password: that's single sign-on.
function checkSsoRequest(req, res) {
  const spId = str(req.query.sp);
  const sp = spId && serviceProviders.get(spId);
  if (!sp) { res.status(400).json({ error: "Unknown app: it must be registered with the IdP first" }); return null; }
  const requestId = str(req.query.request_id);
  if (requestId !== undefined && !/^[\w-]{16,64}$/.test(requestId)) { res.status(400).json({ error: "Bad request_id" }); return null; }
  const relayState = str(req.query.relay_state) ?? "/";
  if (relayState.length > 200) { res.status(400).json({ error: "relay_state too long" }); return null; }
  return { spId, sp, requestId, relayState };
}

const loginPage = (sp, error) => page("ChaiCorp Login", `<h1>🔐 ChaiCorp Login</h1>
<p><b>${esc(sp.name)}</b> wants to know who you are.</p>${error ? `<p style="color:#b91c1c">${esc(error)}</p>` : ""}
<form method="post"><input name="email" type="email" value="rahul@chaicorp.com" autocomplete="username">
<input name="password" type="password" placeholder="Password" autocomplete="current-password"><button>Log in</button></form>
<p>Test accounts: <b>rahul@chaicorp.com</b> / <b>chai-and-code-42</b>, <b>priya@chaicorp.com</b> / <b>masala-dosa-77</b></p>`);

idp.get("/sso", (req, res) => {
  const r = checkSsoRequest(req, res);
  if (!r) return;
  const session = getIdpSession(req);
  if (session) return sendAssertion(res, session, r.sp, r.spId, r.requestId, r.relayState); // ✅ no password asked
  res.send(loginPage(r.sp));
});

// The login form posts back to the SAME URL (/sso?sp=…&request_id=…), so the request details survive the login
idp.post("/sso", (req, res) => {
  const r = checkSsoRequest(req, res);
  if (!r) return;
  const email = str(req.body?.email)?.trim().toLowerCase();
  const user = email ? idpUsers.get(email) : undefined;
  // Hash even for unknown emails so the response time doesn't reveal who works here (topic 51)
  const hash = crypto.scryptSync(str(req.body?.password) ?? "", user?.salt ?? DUMMY_SALT, 64);
  if (!user || !crypto.timingSafeEqual(hash, user.passwordHash)) return res.status(401).send(loginPage(r.sp, "Wrong email or password"));
  // shortcut: password only. A real IdP adds MFA here (topic 45), once, for every app behind it.

  const sid = randomToken(); // a NEW id at login (session fixation, topic 50)
  const session = { email: user.email, authAt: Date.now(), expiresAt: Date.now() + IDP_SESSION_MS, apps: new Set() };
  idpSessions.set(sha256(sid), session);
  res.cookie("idp_sid", sid, { ...COOKIE, maxAge: IDP_SESSION_MS });
  console.log(`🔐 IdP: ${user.email} typed the password`);
  sendAssertion(res, session, r.sp, r.spId, r.requestId, r.relayState);
});

// The IdP's own page: who you are and which apps you used today
idp.get("/me", (req, res) => {
  const s = getIdpSession(req);
  if (!s) return res.status(401).json({ error: "Not signed in at the IdP" });
  res.json({ email: s.email, loggedInAt: new Date(s.authAt).toISOString(), apps: [...s.apps] });
});

// Logs you out of the IdP ONLY. Every app keeps its own session until it expires: that's what Single Logout fixes (topic 61).
idp.post("/logout", (req, res) => {
  const sid = parseCookies(req).idp_sid;
  if (sid) idpSessions.delete(sha256(sid));
  res.clearCookie("idp_sid", COOKIE);
  res.json({ message: "Logged out of ChaiCorp Login (the apps still have their own sessions)" });
});

finish(idp);
listen(idp, PORT, `🔐 ChaiCorp Login (IdP) on ${IDP_URL}`);

// =====================================================================
// 🏢 THE SERVICE PROVIDERS (SPs): apps that NEVER see a password
// =====================================================================
function createSp({ id, name, emoji, port, prefix }) {
  const url = `http://localhost:${port}`;
  const acs = `${url}/acs`;
  // shortcut: in-memory Maps per app. A real app uses its own database tables.
  const sessions = new Map(); // sha256(sid) -> { sub, email, name, expiresAt }
  const pending = new Map();  // requestId -> expiresAt  (logins THIS app started)
  const used = new Map();     // assertion id -> exp     (replay cache, kept until the assertion would expire anyway)
  const localUsers = new Map(); // sub -> { email, name, department, createdAt }  (created on first login: "JIT provisioning")

  // STEP 1 (trust setup): fetch the IdP's metadata ONCE and pin the key.
  // Never take a key or IdP URL from inside the assertion itself: the attacker wrote that.
  let idpKey = null;
  const getIdpKey = async () => {
    if (!idpKey) idpKey = crypto.createPublicKey((await (await fetch(`${IDP_URL}/metadata`)).json()).signingKey);
    return idpKey;
  };

  const getSession = (req) => {
    const sid = parseCookies(req)[`${prefix}_sid`];
    const key = sid && sha256(sid);
    const s = key && sessions.get(key);
    if (!s) return null;
    if (Date.now() > s.expiresAt) { sessions.delete(key); return null; }
    return s;
  };

  const app = express();
  base(app);

  // STEP 2: not logged in here → send the browser to the IdP with a request id (SP-initiated SSO)
  app.get("/", (req, res) => {
    const s = getSession(req);
    if (s) {
      return res.send(page(name, `<h1>${emoji} ${esc(name)}</h1><p>Welcome, <b>${esc(s.name)}</b> (${esc(s.email)}).</p>
<p>You never typed a password here: ChaiCorp Login vouched for you.</p><p><a href="${IDP_URL}/me">Your IdP session</a></p>`));
    }
    const requestId = randomToken();
    pending.set(requestId, Date.now() + 5 * 60 * 1000);
    // Tie the request to THIS browser, so an assertion meant for someone else's login can't be planted here (login CSRF)
    // shortcut: SameSite=Lax works because localhost ports are the same "site". In production the IdP is another site,
    // and its cross-site POST to /acs would NOT carry a Lax cookie: use SameSite=None; Secure for this short-lived cookie.
    res.cookie(`${prefix}_req`, requestId, { ...COOKIE, maxAge: 5 * 60 * 1000 });
    const to = new URL(`${IDP_URL}/sso`);
    to.search = new URLSearchParams({ sp: id, request_id: requestId, relay_state: req.originalUrl }).toString();
    res.redirect(302, to.href);
  });

  // STEP 5: the Assertion Consumer Service. Every check below stops a real attack.
  app.post("/acs", async (req, res) => {
    const fail = (error) => { console.log(`⛔ ${name}: ${error}`); return res.status(401).json({ error }); };
    const assertion = str(req.body?.assertion) ?? "";
    const [body, sig, extra] = assertion.split(".");
    if (!body || !sig || extra !== undefined) return fail("Malformed assertion");

    // 5a. Signature: only the IdP's private key could have made it. Checked FIRST, before trusting a single field.
    if (!crypto.verify("sha256", Buffer.from(body), await getIdpKey(), Buffer.from(sig, "base64url"))) {
      return fail("Bad signature: not from our IdP, or changed on the way");
    }
    let a;
    try { a = JSON.parse(Buffer.from(body, "base64url").toString("utf8")); } catch { return fail("Malformed assertion"); }

    if (a.iss !== IDP_URL) return fail("Wrong issuer");                                        // 5b. from OUR IdP
    if (a.aud !== id) return fail(`This assertion is for "${a.aud}", not "${id}"`);             // 5c. for THIS app
    if (a.acs !== acs) return fail("Wrong destination");                                        // 5d. delivered HERE
    const now = nowS();
    if (now > a.exp + CLOCK_SKEW_S || a.iat > now + CLOCK_SKEW_S) return fail("Assertion expired"); // 5e. fresh
    if (used.has(a.id)) return fail("Assertion already used (replay)");                         // 5f. one-time
    // 5g. It must answer a login THIS browser started. That refuses unsolicited (IdP-initiated) assertions,
    // a common way to plant someone else's login or replay a leaked one.
    if (!a.inResponseTo) return fail("Unsolicited assertion refused: start the login from the app");
    const expected = parseCookies(req)[`${prefix}_req`];
    if (a.inResponseTo !== expected || !(pending.get(expected) > Date.now())) return fail("Assertion doesn't match a login started in this browser");

    used.set(a.id, a.exp);
    pending.delete(expected);

    // STEP 6: the app's OWN user record, keyed by the IdP's stable `sub`, created on first login (JIT provisioning)
    if (!localUsers.has(a.sub)) {
      localUsers.set(a.sub, { email: a.email, name: a.name, department: a.department, createdAt: new Date().toISOString() });
      console.log(`👤 ${name}: new local account for ${a.email} (just-in-time)`);
    }
    // STEP 6: the app's OWN session. From now on it doesn't ask the IdP on every request.
    const sid = randomToken();
    sessions.set(sha256(sid), { sub: a.sub, email: a.email, name: a.name, expiresAt: Date.now() + SP_SESSION_MS });
    res.cookie(`${prefix}_sid`, sid, { ...COOKIE, maxAge: SP_SESSION_MS });
    res.clearCookie(`${prefix}_req`, COOKIE);
    console.log(`✅ ${name}: ${a.email} signed in via SSO`);
    // relay_state is where the user was going. Only allow a local path, or it's an open redirect.
    const relay = str(req.body?.relay_state) ?? "/";
    res.redirect(303, relay.startsWith("/") && !relay.startsWith("//") ? relay : "/");
  });

  app.get("/api/me", (req, res) => {
    const s = getSession(req);
    if (!s) return res.status(401).json({ error: `Not signed in to ${name}` });
    res.json({ app: name, email: s.email, name: s.name, sub: s.sub, localAccountCreatedAt: localUsers.get(s.sub).createdAt });
  });

  // Logs you out of THIS app only. The IdP session stays, so the next visit signs you straight back in.
  app.post("/logout", (req, res) => {
    const sid = parseCookies(req)[`${prefix}_sid`];
    if (sid) sessions.delete(sha256(sid));
    res.clearCookie(`${prefix}_sid`, COOKIE);
    res.json({ message: `Logged out of ${name} only` });
  });

  finish(app);
  listen(app, port, `${emoji} ${name} (SP) on ${url}`);

  setInterval(() => {
    const t = Date.now();
    for (const [k, s] of sessions) if (t > s.expiresAt) sessions.delete(k);
    for (const [k, exp] of pending) if (t > exp) pending.delete(k);
    for (const [k, exp] of used) if (nowS() > exp + CLOCK_SKEW_S) used.delete(k);
  }, 60_000).unref();
}

createSp({ id: "hr-portal", name: "HR Portal", emoji: "👥", port: HR_PORT, prefix: "hr" });
createSp({ id: "payroll", name: "Payroll", emoji: "💰", port: PAYROLL_PORT, prefix: "payroll" });

setInterval(() => {
  for (const [k, s] of idpSessions) if (Date.now() > s.expiresAt) idpSessions.delete(k);
}, 60_000).unref();
