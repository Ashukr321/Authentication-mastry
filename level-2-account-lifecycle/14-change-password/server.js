const express = require("express");
const crypto = require("crypto");
const { promisify } = require("util");

const scrypt = promisify(crypto.scrypt);
const SCRYPT_OPTIONS = { N: 2 ** 17, r: 8, p: 1, maxmem: 256 * 1024 * 1024 };

const PORT = Number(process.env.PORT) || 3000;
// Our own address, from config. Used to check the Origin header (never trust the Host header)
const BASE_URL = `http://localhost:${PORT}`;
const SESSION_TTL_MS = 8 * 60 * 60 * 1000; // 8 hours (topic 09)
const MAX_WRONG_CURRENT = 5;               // wrong "current password" tries before we pause changes
const WRONG_LOCK_MS = 15 * 60 * 1000;      // ...for 15 minutes

// Same cookie options for setting and clearing (topic 11). In production: secure: true and "__Host-sid" (topic 10).
const COOKIE_NAME = "sid";
const COOKIE_OPTIONS = { httpOnly: true, sameSite: "lax", path: "/", secure: process.env.NODE_ENV === "production" };
// shortcut: a tiny list. A real app blocks the top 100k common passwords or checks Have I Been Pwned (topic 06).
const COMMON_PASSWORDS = new Set(["password", "12345678", "123456789", "qwerty123", "password1", "iloveyou"]);

// ---------- "Database" ----------
// shortcut: in-memory Maps, lost on restart. A real app uses database tables.
const users = new Map();    // email -> { id, email, passwordHash, passwordChangedAt, wrongCurrentCount, changeLockedUntil }
const sessions = new Map(); // sha256(sessionId) -> { userId, device, expiresAt }

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

// ---------- Sessions (topic 09 / 11) ----------
const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");
const readSessionId = (req) => /(?:^|;\s*)sid=([a-f0-9]{64})(?:;|$)/.exec(req.headers.cookie ?? "")?.[1];
const findUserById = (id) => [...users.values()].find((u) => u.id === id);

function startSession(res, user, device) {
  const sessionId = crypto.randomBytes(32).toString("hex");
  sessions.set(sha256(sessionId), { userId: user.id, device, expiresAt: Date.now() + SESSION_TTL_MS });
  res.cookie(COOKIE_NAME, sessionId, { ...COOKIE_OPTIONS, maxAge: SESSION_TTL_MS });
}

// Password rules from topic 06, plus "not the same as the email"
function newPasswordProblem(password, email) {
  if (typeof password !== "string" || password.length < 8) return "The new password must be at least 8 characters";
  if (password.length > 128) return "The new password must be at most 128 characters";
  if (COMMON_PASSWORDS.has(password.toLowerCase())) return "This password is too common, please choose another";
  if (password.toLowerCase() === email) return "The new password can't be your email";
  return null;
}

// shortcut: "sends" the email by printing it in the terminal. Use a real email service in production.
function sendPasswordChangedNotice(user) {
  console.log(`\n📧 To: ${user.email}\n   Subject: Your password was changed\n   Changed at ${user.passwordChangedAt}. If this wasn't you, reset your password: ${BASE_URL}/forgot-password\n`);
}

const isValidEmail = (email) => typeof email === "string" && email.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim());

// ---------- App ----------
const app = express();
app.use(express.json({ limit: "10kb" }));
app.use((req, res, next) => { res.set("Cache-Control", "no-store"); next(); });

// CSRF defense in depth (topic 11): a state-changing request from another site's page is refused
app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (["POST", "PUT", "PATCH", "DELETE"].includes(req.method) && origin && origin !== BASE_URL) {
    return res.status(403).json({ error: "Request from another site was blocked" });
  }
  next();
});

// Finds the current session (if any) and puts it on req
app.use((req, res, next) => {
  const sessionId = readSessionId(req);
  const key = sessionId && sha256(sessionId);
  const session = key && sessions.get(key);
  if (session && Date.now() <= session.expiresAt) Object.assign(req, { sessionKey: key, session, user: findUserById(session.userId) });
  next();
});

const requireAuth = (req, res, next) => (req.user ? next() : res.status(401).json({ error: "Not logged in" }));

// SIGNUP, LOGIN, ME, SESSIONS: same as topics 06, 07, 09 and 11, kept short
app.post("/signup", async (req, res) => {
  const { email, password } = req.body ?? {};
  if (!isValidEmail(email) || typeof password !== "string" || password.length < 8 || password.length > 128) {
    return res.status(400).json({ error: "A valid email and a password of 8-128 characters are required" });
  }
  const normalizedEmail = email.trim().toLowerCase();
  const passwordHash = await hashPassword(password);
  if (users.has(normalizedEmail)) return res.status(409).json({ error: "Email already registered" });

  const user = { id: crypto.randomUUID(), email: normalizedEmail, passwordHash, passwordChangedAt: null, wrongCurrentCount: 0, changeLockedUntil: 0 };
  users.set(normalizedEmail, user);
  res.status(201).json({ id: user.id, email: user.email });
});

app.post("/login", async (req, res) => {
  const { email, password } = req.body ?? {};
  if (typeof email !== "string" || typeof password !== "string" || !email || !password) {
    return res.status(400).json({ error: "Email and password are required" });
  }
  const user = users.get(email.trim().toLowerCase());
  const ok = await verifyPassword(password, user ? user.passwordHash : await DUMMY_HASH_PROMISE);
  if (!user || !ok) return res.status(401).json({ error: "Invalid email or password" });

  if (req.sessionKey) sessions.delete(req.sessionKey); // never reuse an old session ID (session fixation)
  const device = String(req.headers["user-agent"] ?? "Unknown device").slice(0, 100);
  startSession(res, user, device);
  res.json({ message: "Logged in", email: user.email, device });
});

app.get("/me", requireAuth, (req, res) => res.json({ id: req.user.id, email: req.user.email, device: req.session.device }));

app.get("/sessions", requireAuth, (req, res) => {
  res.json([...sessions.values()].filter((s) => s.userId === req.user.id).map((s) => ({ device: s.device, current: s === req.session })));
});

// CHANGE PASSWORD: the user is logged in and knows their current password
app.post("/change-password", requireAuth, async (req, res) => {
  const user = req.user;
  const { currentPassword, newPassword } = req.body ?? {};

  // 1. Both fields must be there
  if (typeof currentPassword !== "string" || !currentPassword || typeof newPassword !== "string") {
    return res.status(400).json({ error: "currentPassword and newPassword are required" });
  }

  // 2. Too many wrong "current password" tries? A stolen session can't be used to guess the password.
  if (Date.now() < user.changeLockedUntil) {
    return res.status(429).json({ error: "Too many wrong attempts. Try again in 15 minutes, or use Forgot password." });
  }

  // 3. Re-authenticate: prove it's really the owner, not someone who found an open laptop or stole the cookie
  if (!(await verifyPassword(currentPassword, user.passwordHash))) {
    user.wrongCurrentCount++;
    if (user.wrongCurrentCount >= MAX_WRONG_CURRENT) {
      user.wrongCurrentCount = 0;
      user.changeLockedUntil = Date.now() + WRONG_LOCK_MS;
    }
    // 403, not 401: the user IS logged in, the frontend shouldn't send them to the login page
    return res.status(403).json({ error: "Current password is incorrect" });
  }
  user.wrongCurrentCount = 0;

  // 4. Check the new password: same rules as signup, and it must actually be different
  const problem = newPasswordProblem(newPassword, user.email);
  if (problem) return res.status(400).json({ error: problem });
  if (await verifyPassword(newPassword, user.passwordHash)) {
    return res.status(400).json({ error: "The new password must be different from the current one" });
  }

  // 5. Save the new hash (never the password itself)
  user.passwordHash = await hashPassword(newPassword);
  user.passwordChangedAt = new Date().toISOString();

  // 6. Log out every OTHER device: whoever knew the old password is kicked out
  let loggedOut = 0;
  for (const [key, s] of sessions) {
    if (s.userId === user.id && key !== req.sessionKey) { sessions.delete(key); loggedOut++; }
  }

  // 7. Keep THIS device logged in, but with a brand-new session ID (the old one may have been copied)
  sessions.delete(req.sessionKey);
  startSession(res, user, req.session.device);

  // 8. Tell the owner, on a channel the attacker probably doesn't control
  sendPasswordChangedNotice(user);

  res.json({ message: "Password changed", otherDevicesLoggedOut: loggedOut });
});

app.use((req, res) => res.status(404).json({ error: "Not found" }));

// Errors (bad JSON, body too big, bugs) come here. Never send the stack trace to the client.
app.use((err, req, res, next) => {
  if (err.type === "entity.parse.failed") return res.status(400).json({ error: "Body must be valid JSON" });
  if (err.type === "entity.too.large") return res.status(413).json({ error: "Request body too large" });
  console.error(err);
  res.status(500).json({ error: "Something went wrong" });
});

app.listen(PORT, () => console.log(`Change password API on ${BASE_URL}`));

// Delete expired sessions every minute so the store doesn't grow forever
setInterval(() => {
  const now = Date.now();
  for (const [key, s] of sessions) if (now > s.expiresAt) sessions.delete(key);
}, 60_000).unref();
