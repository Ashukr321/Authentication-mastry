const express = require("express");
const crypto = require("crypto");

const PORT = Number(process.env.PORT) || 3000;
const BASE_URL = `http://localhost:${PORT}`;
const IDLE_TIMEOUT_MS = 30 * 60 * 1000;          // 30 min without a request → session ends
const ABSOLUTE_TIMEOUT_MS = 12 * 60 * 60 * 1000; // 12 h after login → session ends, however active

// ---------- "Database" ----------
// shortcut: in-memory Maps, lost on restart. A real app uses database tables (or Redis for sessions).
const users = new Map();    // email -> { email, salt, passwordHash }
const sessions = new Map(); // sha256(sid) -> { email | null, cart, ua, createdAt, lastSeenAt }

// ---------- Helpers ----------
const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");
const randomToken = () => crypto.randomBytes(32).toString("base64url");
const str = (v) => (typeof v === "string" ? v : undefined);
const parseCookies = (req) => Object.fromEntries((req.headers.cookie ?? "").split(";").filter((c) => c.includes("="))
  .map((c) => [c.slice(0, c.indexOf("=")).trim(), c.slice(c.indexOf("=") + 1).trim()]));
// A short, harmless label for a session so you can SEE when the id changes. Never show the real id.
const tag = (sid) => sha256(sid).slice(0, 8);
const ua = (req) => req.get("user-agent") ?? "";

const DUMMY_SALT = crypto.randomBytes(16);
// shortcut: test accounts with known passwords. A real app has a signup (topic 06).
for (const [email, password] of [["rahul@mail.com", "chai-and-code-42"], ["vikram@mail.com", "vikram-pass-99"]]) {
  const salt = crypto.randomBytes(16);
  users.set(email, { email, salt, passwordHash: crypto.scryptSync(password, salt, 64) });
}

function checkPassword(email, password) {
  const user = email ? users.get(email) : undefined;
  // Hash even for unknown emails so the response time doesn't reveal who has an account (topic 51)
  const hash = crypto.scryptSync(password ?? "", user?.salt ?? DUMMY_SALT, 64);
  return user && crypto.timingSafeEqual(hash, user.passwordHash) ? user : null;
}

// shortcut: no Secure flag because the demo runs on http://localhost. In production add `secure: true`
// and name the cookie `__Host-sid`, so a subdomain can't plant (toss) a session cookie for you (topic 10).
const SAFE_COOKIE = { httpOnly: true, sameSite: "lax", path: "/" }; // ✅ document.cookie can't read it
const WEAK_COOKIE = { path: "/" };                                   // ❌ any script on the page can read it

// Every session id comes from HERE: 256 random bits from the server. Never from the client.
function newSession(res, data = {}, cookie = SAFE_COOKIE) {
  const sid = randomToken();
  const now = Date.now();
  const s = { email: null, cart: [], ua: null, ...data, createdAt: now, lastSeenAt: now };
  sessions.set(sha256(sid), s); // store only the hash: a leaked sessions table can't be replayed
  res.cookie("sid", sid, cookie);
  return { sid, s };
}

// ✅ SAFE lookup: the id must be one WE issued, still fresh, and used from the same browser it logged in from
function getSession(req) {
  const sid = parseCookies(req).sid;
  const key = sid && sha256(sid);
  const s = key && sessions.get(key);
  if (!s) return null; // unknown id (maybe one an attacker made up): ignored, never adopted

  // DEFENSE 3: timeouts shrink the window a stolen id is worth anything
  const now = Date.now();
  if (now - s.lastSeenAt > IDLE_TIMEOUT_MS || now - s.createdAt > ABSOLUTE_TIMEOUT_MS) {
    sessions.delete(key);
    return null;
  }

  // DEFENSE 4: a logged-in session suddenly used from a different browser is probably a copied cookie.
  // shortcut: compares the full User-Agent, which also changes when Chrome auto-updates. Real apps compare the
  // browser family + OS, add IP/ASN and device signals, and score the risk instead of a yes/no (topics 52, 55).
  if (s.email && s.ua !== ua(req)) {
    sessions.delete(key); // end it for BOTH: we can't tell which one is the real Rahul
    console.log(`🚨 Session ${tag(sid)} of ${s.email} used from a different browser ("${ua(req)}"): revoked`);
    console.log(`📧 To: ${s.email}  "We signed you out because your session was used from a new browser. If this wasn't you, change your password."`);
    return null;
  }

  s.lastSeenAt = now; // sliding idle timeout
  return { sid, s };
}

// ❌ VULNERABLE lookup: any id that exists works forever, from anywhere
function getSessionVulnerable(req) {
  const sid = parseCookies(req).sid;
  const s = sid && sessions.get(sha256(sid));
  return s ? { sid, s } : null;
}

// ---------- App ----------
const app = express();
app.use(express.json({ limit: "10kb" }));
app.use((req, res, next) => {
  res.set("Cache-Control", "no-store"); // pages with a session must not be cached by a shared proxy
  next();
});

// ✅ The shop works BEFORE login (a guest cart). That's why a session exists before login, and why fixation is possible.
app.get("/shop", (req, res) => {
  // ✅ The session id is read from the cookie only. A ?sid= in the URL is ignored.
  const cur = getSession(req) ?? newSession(res);
  res.json({ shop: "☕ ChaiCart", signedInAs: cur.s.email, cart: cur.s.cart, session: tag(cur.sid) });
});

// ❌ VULNERABLE: accepts a session id from the URL (old "URL rewriting" like ;jsessionid=…),
// and is "permissive": it adopts an id the server never issued. This is how the attacker plants his id.
app.get("/vulnerable/shop", (req, res) => {
  const fromUrl = str(req.query.sid);
  let cur;
  if (fromUrl) {
    if (!/^[\w-]{8,100}$/.test(fromUrl)) return res.status(400).json({ error: "Bad session id" });
    const key = sha256(fromUrl);
    if (!sessions.has(key)) sessions.set(key, { email: null, cart: [], ua: null, createdAt: Date.now(), lastSeenAt: Date.now() });
    res.cookie("sid", fromUrl, WEAK_COOKIE);
    cur = { sid: fromUrl, s: sessions.get(key) };
  } else {
    cur = getSessionVulnerable(req) ?? newSession(res, {}, WEAK_COOKIE);
  }
  res.json({ shop: "☕ ChaiCart (vulnerable)", signedInAs: cur.s.email, cart: cur.s.cart, session: tag(cur.sid) });
});

app.post("/cart", (req, res) => {
  const cur = getSession(req);
  if (!cur) return res.status(401).json({ error: "Open /shop first to get a session" });
  const item = str(req.body?.item)?.trim();
  if (!item || item.length > 50) return res.status(400).json({ error: "Item must be 1 to 50 characters" });
  if (cur.s.cart.length >= 20) return res.status(400).json({ error: "Cart is full" });
  cur.s.cart.push(item);
  res.json({ cart: cur.s.cart, session: tag(cur.sid) });
});

// ✅ SAFE login. DEFENSE 1: regenerate the session id. The pre-login id dies; a fresh one is issued.
// (express-session: req.session.regenerate(); Passport 0.6+ does it for you in req.login(), topic 41)
app.post("/login", (req, res) => {
  const user = checkPassword(str(req.body?.email)?.trim().toLowerCase(), str(req.body?.password));
  if (!user) return res.status(401).json({ error: "Wrong email or password" });

  const old = getSession(req);
  if (old) sessions.delete(sha256(old.sid)); // whoever else knows the old id now holds a dead one
  // Copy over the guest data the user should keep (the cart), and remember the browser it logged in from
  const { sid } = newSession(res, { email: user.email, cart: old?.s.cart ?? [], ua: ua(req) });
  res.json({ message: `Logged in as ${user.email}`, oldSession: old ? tag(old.sid) : null, session: tag(sid) });
});

// ❌ VULNERABLE login: marks the EXISTING session as logged in. Anyone who knew that id before is now logged in too.
app.post("/vulnerable/login", (req, res) => {
  const user = checkPassword(str(req.body?.email)?.trim().toLowerCase(), str(req.body?.password));
  if (!user) return res.status(401).json({ error: "Wrong email or password" });
  const cur = getSessionVulnerable(req) ?? newSession(res, {}, WEAK_COOKIE);
  cur.s.email = user.email;
  cur.s.ua = ua(req);
  res.json({ message: `Logged in as ${user.email}`, session: tag(cur.sid) });
});

app.get("/me", (req, res) => {
  const cur = getSession(req);
  if (!cur) res.clearCookie("sid", SAFE_COOKIE);
  if (!cur?.s.email) return res.status(401).json({ error: "Not signed in" });
  res.json({
    email: cur.s.email,
    cart: cur.s.cart,
    session: tag(cur.sid),
    idleExpiresAt: new Date(cur.s.lastSeenAt + IDLE_TIMEOUT_MS).toISOString(),
    absoluteExpiresAt: new Date(cur.s.createdAt + ABSOLUTE_TIMEOUT_MS).toISOString(),
  });
});

app.get("/vulnerable/me", (req, res) => {
  const cur = getSessionVulnerable(req);
  if (!cur?.s.email) return res.status(401).json({ error: "Not signed in" });
  res.json({ email: cur.s.email, cart: cur.s.cart, session: tag(cur.sid) });
});

// DEFENSE 5: dangerous actions need the PASSWORD, not just the cookie. A hijacker has the cookie, not the password.
// DEFENSE 6: after a password change, kill EVERY session of the user (a stolen copy dies) and give this browser a new id.
app.post("/account/password", (req, res) => {
  const cur = getSession(req);
  if (!cur?.s.email) return res.status(401).json({ error: "Not signed in" });
  if (!checkPassword(cur.s.email, str(req.body?.currentPassword))) {
    return res.status(403).json({ error: "Confirm this change with your current password" });
  }
  const newPassword = str(req.body?.newPassword) ?? "";
  if (newPassword.length < 12 || newPassword.length > 128) return res.status(400).json({ error: "New password must be 12 to 128 characters" });

  const user = users.get(cur.s.email);
  user.salt = crypto.randomBytes(16);
  user.passwordHash = crypto.scryptSync(newPassword, user.salt, 64);
  let ended = 0;
  for (const [k, s] of sessions) if (s.email === user.email) { sessions.delete(k); ended++; }
  const { sid } = newSession(res, { email: user.email, cart: cur.s.cart, ua: ua(req) });
  res.json({ message: "Password changed", sessionsEnded: ended, session: tag(sid) });
});

// Logout deletes the session ON THE SERVER. Clearing the cookie alone would leave stolen copies working.
app.post("/logout", (req, res) => {
  const sid = parseCookies(req).sid;
  if (sid) sessions.delete(sha256(sid));
  res.clearCookie("sid", SAFE_COOKIE);
  res.json({ message: "Logged out" });
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
  console.log(`☕ ChaiCart on ${BASE_URL}`);
});

// Sweep expired sessions so the Map doesn't grow forever
setInterval(() => {
  const now = Date.now();
  for (const [k, s] of sessions) {
    if (now - s.lastSeenAt > IDLE_TIMEOUT_MS || now - s.createdAt > ABSOLUTE_TIMEOUT_MS) sessions.delete(k);
  }
}, 60_000).unref();
