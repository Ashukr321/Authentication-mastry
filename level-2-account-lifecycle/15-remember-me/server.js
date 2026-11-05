const express = require("express");
const crypto = require("crypto");
const { promisify } = require("util");

const scrypt = promisify(crypto.scrypt);
const SCRYPT_OPTIONS = { N: 2 ** 17, r: 8, p: 1, maxmem: 256 * 1024 * 1024 };

const PORT = Number(process.env.PORT) || 3000;
const BASE_URL = `http://localhost:${PORT}`;
// The normal session is SHORT (set SESSION_TTL_SECONDS=5 to watch remember-me take over)
const SESSION_TTL_MS = (Number(process.env.SESSION_TTL_SECONDS) || 30 * 60) * 1000; // 30 minutes
const REMEMBER_TTL_MS = 30 * 24 * 60 * 60 * 1000;                                   // 30 days

// Same options for setting and clearing (topic 11). In production: secure: true and "__Host-" names (topic 10).
const COOKIE_OPTIONS = { httpOnly: true, sameSite: "lax", path: "/", secure: process.env.NODE_ENV === "production" };

// ---------- "Database" ----------
// shortcut: in-memory Maps, lost on restart. A real app uses database tables.
const users = new Map();          // email -> { id, email, passwordHash }
const sessions = new Map();       // sha256(sessionId) -> { userId, viaRememberMe, expiresAt }
const rememberTokens = new Map(); // selector -> { userId, validatorHash, expiresAt }

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

const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");
const findUserById = (id) => [...users.values()].find((u) => u.id === id);

function readCookie(req, name) {
  for (const part of (req.headers.cookie ?? "").split(";")) {
    const [key, ...rest] = part.trim().split("=");
    if (key === name) return rest.join("=");
  }
  return undefined;
}

// ---------- Short session (topic 09) ----------
// No maxAge: a "browser-session cookie", deleted when the browser closes. The server also expires it.
function startSession(res, user, viaRememberMe) {
  const sessionId = crypto.randomBytes(32).toString("hex");
  sessions.set(sha256(sessionId), { userId: user.id, viaRememberMe, expiresAt: Date.now() + SESSION_TTL_MS });
  res.cookie("sid", sessionId, COOKIE_OPTIONS);
}

// ---------- Remember-me token: "selector.validator" ----------
// selector  = a public lookup key (like a username for the token)
// validator = the secret. We store only its HASH, so a leaked database can't log anyone in.
function setRememberCookie(res, selector, validator, expiresAt) {
  res.cookie("remember", `${selector}.${validator}`, { ...COOKIE_OPTIONS, maxAge: expiresAt - Date.now() });
}

function createRememberToken(res, user) {
  const selector = crypto.randomBytes(12).toString("hex");
  const validator = crypto.randomBytes(32).toString("hex");
  const expiresAt = Date.now() + REMEMBER_TTL_MS;
  rememberTokens.set(selector, { userId: user.id, validatorHash: sha256(validator), expiresAt });
  setRememberCookie(res, selector, validator, expiresAt);
}

function forgetEverything(userId) {
  for (const [key, s] of sessions) if (s.userId === userId) sessions.delete(key);
  for (const [sel, t] of rememberTokens) if (t.userId === userId) rememberTokens.delete(sel);
}

function clearAuthCookies(res) {
  res.clearCookie("sid", COOKIE_OPTIONS);
  res.clearCookie("remember", COOKIE_OPTIONS);
}

// ---------- App ----------
const app = express();
app.use(express.json({ limit: "10kb" }));
app.use((req, res, next) => { res.set("Cache-Control", "no-store"); next(); });

// CSRF defense in depth (topic 11)
app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (["POST", "PUT", "PATCH", "DELETE"].includes(req.method) && origin && origin !== BASE_URL) {
    return res.status(403).json({ error: "Request from another site was blocked" });
  }
  next();
});

// WHO IS THIS? 1) a valid session, or 2) a valid remember-me cookie, which starts a new session
app.use((req, res, next) => {
  // 1. A short session that's still alive: the normal case
  const sid = readCookie(req, "sid");
  const session = /^[a-f0-9]{64}$/.test(sid ?? "") && sessions.get(sha256(sid));
  if (session && Date.now() <= session.expiresAt) {
    req.user = findUserById(session.userId);
    req.session = session;
    req.sessionKey = sha256(sid);
    return next();
  }

  // 2. No session (expired, or the browser was closed). Is there a remember-me cookie?
  const match = /^([a-f0-9]{24})\.([a-f0-9]{64})$/.exec(readCookie(req, "remember") ?? "");
  if (!match) return next();
  const [, selector, validator] = match;
  const token = rememberTokens.get(selector);

  if (!token || Date.now() > token.expiresAt) {
    if (token) rememberTokens.delete(selector);
    res.clearCookie("remember", COOKIE_OPTIONS); // dead cookie: tell the browser to drop it
    return next();
  }

  // Constant-time compare of the hashes (topic 07)
  if (!crypto.timingSafeEqual(Buffer.from(sha256(validator)), Buffer.from(token.validatorHash))) {
    // THEFT! The selector is real but the secret is an OLD one. Since we rotate the secret on every use,
    // two people have used this cookie: the owner and a thief. We can't tell who is who, so log out EVERYONE.
    forgetEverything(token.userId);
    clearAuthCookies(res);
    console.log(`\n🚨 Remember-me token reused for user ${token.userId}. All sessions and remember-me tokens deleted.\n📧 To the user: "We logged you out everywhere because your login may have been stolen."\n`);
    return res.status(401).json({ error: "Your login may have been stolen. You've been logged out everywhere. Please log in again." });
  }

  // Valid! 3. ROTATE: same selector, NEW secret. A copy of the old cookie is now a theft alarm.
  const newValidator = crypto.randomBytes(32).toString("hex");
  token.validatorHash = sha256(newValidator);
  setRememberCookie(res, selector, newValidator, token.expiresAt); // keep the ORIGINAL 30-day limit

  // 4. Start a new short session, marked "came from remember-me" (less trusted)
  const user = findUserById(token.userId);
  startSession(res, user, true);
  req.user = user;
  req.session = { viaRememberMe: true };
  next();
});

const requireAuth = (req, res, next) => (req.user ? next() : res.status(401).json({ error: "Not logged in" }));

// Sensitive pages need a REAL password login, not just "remembered" (step-up, topic 14)
const requireFreshLogin = (req, res, next) =>
  req.session.viaRememberMe ? res.status(403).json({ error: "Please log in with your password again to see this", reauth: true }) : next();

// SIGNUP: same as topic 06, kept short
app.post("/signup", async (req, res) => {
  const { email, password } = req.body ?? {};
  if (typeof email !== "string" || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim()) || typeof password !== "string" || password.length < 8 || password.length > 128) {
    return res.status(400).json({ error: "A valid email and a password of 8-128 characters are required" });
  }
  const normalizedEmail = email.trim().toLowerCase();
  const passwordHash = await hashPassword(password);
  if (users.has(normalizedEmail)) return res.status(409).json({ error: "Email already registered" });
  const user = { id: crypto.randomUUID(), email: normalizedEmail, passwordHash };
  users.set(normalizedEmail, user);
  res.status(201).json({ id: user.id, email: user.email });
});

// LOGIN, with an optional "Remember me" checkbox
app.post("/login", async (req, res) => {
  const { email, password, rememberMe } = req.body ?? {};
  if (typeof email !== "string" || typeof password !== "string" || !email || !password) {
    return res.status(400).json({ error: "Email and password are required" });
  }
  const user = users.get(email.trim().toLowerCase());
  const ok = await verifyPassword(password, user ? user.passwordHash : await DUMMY_HASH_PROMISE);
  if (!user || !ok) return res.status(401).json({ error: "Invalid email or password" });

  // Drop whatever this browser had before (never reuse old IDs)
  if (req.sessionKey) sessions.delete(req.sessionKey);
  const oldSelector = /^([a-f0-9]{24})\./.exec(readCookie(req, "remember") ?? "")?.[1];
  if (oldSelector) rememberTokens.delete(oldSelector);

  startSession(res, user, false);
  if (rememberMe === true) createRememberToken(res, user);
  else if (oldSelector) res.clearCookie("remember", COOKIE_OPTIONS);
  res.json({ message: "Logged in", email: user.email, rememberMe: rememberMe === true });
});

app.get("/me", requireAuth, (req, res) => {
  res.json({ email: req.user.email, loggedInVia: req.session.viaRememberMe ? "remember-me" : "password" });
});

app.get("/payment-methods", requireAuth, requireFreshLogin, (req, res) => {
  res.json({ cards: ["Visa ending 4242"] });
});

// LOGOUT must also kill the remember-me token, or the user is logged straight back in
app.post("/logout", (req, res) => {
  if (req.sessionKey) sessions.delete(req.sessionKey);
  const selector = /^([a-f0-9]{24})\./.exec(readCookie(req, "remember") ?? "")?.[1];
  if (selector) rememberTokens.delete(selector);
  clearAuthCookies(res);
  res.json({ message: "Logged out" });
});

// "Log out everywhere" (topic 11): every session AND every remembered device
app.post("/logout-all", requireAuth, (req, res) => {
  forgetEverything(req.user.id);
  clearAuthCookies(res);
  res.json({ message: "Logged out everywhere, and no device is remembered anymore" });
});

app.use((req, res) => res.status(404).json({ error: "Not found" }));

// Errors (bad JSON, body too big, bugs) come here. Never send the stack trace to the client.
app.use((err, req, res, next) => {
  if (err.type === "entity.parse.failed") return res.status(400).json({ error: "Body must be valid JSON" });
  if (err.type === "entity.too.large") return res.status(413).json({ error: "Request body too large" });
  console.error(err);
  res.status(500).json({ error: "Something went wrong" });
});

app.listen(PORT, () => console.log(`Remember-me API on ${BASE_URL} (sessions last ${SESSION_TTL_MS / 1000} s)`));

// Delete expired sessions and remember-me tokens every minute
setInterval(() => {
  const now = Date.now();
  for (const [key, s] of sessions) if (now > s.expiresAt) sessions.delete(key);
  for (const [sel, t] of rememberTokens) if (now > t.expiresAt) rememberTokens.delete(sel);
}, 60_000).unref();
