const express = require("express");
const crypto = require("crypto");
const { promisify } = require("util");

const scrypt = promisify(crypto.scrypt);
const SCRYPT_OPTIONS = { N: 2 ** 17, r: 8, p: 1, maxmem: 256 * 1024 * 1024 };

const PORT = Number(process.env.PORT) || 3000;
// Our own address, from config. Used to check the Origin header (never trust the Host header)
const BASE_URL = `http://localhost:${PORT}`;
const SESSION_TTL_MS = 8 * 60 * 60 * 1000; // 8 hours (absolute timeout, topic 09)

// The cookie options. Logout MUST clear the cookie with the same name, path and domain,
// or the browser treats it as a different cookie and keeps the old one.
// In production: secure: true and the name "__Host-sid" (topic 10). Plain http://localhost can't use those.
const COOKIE_NAME = "sid";
const COOKIE_OPTIONS = { httpOnly: true, sameSite: "lax", path: "/", secure: process.env.NODE_ENV === "production" };

// ---------- "Database" ----------
// shortcut: in-memory Maps, lost on restart. A real app uses a database table or Redis for sessions.
const users = new Map();    // email -> { id, email, passwordHash }
const sessions = new Map(); // sha256(sessionId) -> { publicId, userId, device, createdAt, expiresAt }

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

// ---------- Sessions ----------
// We store only the HASH of the session ID, so a leaked session table can't be used to log in (topic 09 pro tip).
const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");
const readSessionId = (req) => {
  const match = new RegExp(`(?:^|;\\s*)${COOKIE_NAME}=([a-f0-9]{64})(?:;|$)`).exec(req.headers.cookie ?? "");
  return match?.[1];
};

function createSession(user, device) {
  const sessionId = crypto.randomBytes(32).toString("hex"); // the secret, only ever in the cookie
  sessions.set(sha256(sessionId), {
    publicId: crypto.randomUUID(), // a SEPARATE id for the "my devices" list, so we never show the secret
    userId: user.id,
    device,
    createdAt: new Date().toISOString(),
    expiresAt: Date.now() + SESSION_TTL_MS,
  });
  return sessionId;
}

function deleteSessionsOf(userId) {
  let count = 0;
  for (const [key, s] of sessions) if (s.userId === userId) { sessions.delete(key); count++; }
  return count;
}

const isValidEmail = (email) => typeof email === "string" && email.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim());

// ---------- App ----------
const app = express();
app.use(express.json({ limit: "10kb" }));
// no-store: after logout, the Back button must not show private pages from the browser cache
app.use((req, res, next) => { res.set("Cache-Control", "no-store"); next(); });

// CSRF defense in depth (topic 10): a POST/DELETE that says it comes from another site is refused.
// SameSite=Lax already stops the cookie on cross-site POSTs; this also blocks old browsers and same-site subdomains.
app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (["POST", "PUT", "PATCH", "DELETE"].includes(req.method) && origin && origin !== BASE_URL) {
    return res.status(403).json({ error: "Request from another site was blocked" });
  }
  next();
});

// Finds the current session (if any) and puts it on req. Doesn't block: logout must work even without one.
app.use((req, res, next) => {
  const sessionId = readSessionId(req);
  if (sessionId) {
    const key = sha256(sessionId);
    const session = sessions.get(key);
    if (session && Date.now() > session.expiresAt) sessions.delete(key); // expired: treat as logged out
    else if (session) Object.assign(req, { sessionKey: key, session });
  }
  next();
});

const requireAuth = (req, res, next) => (req.session ? next() : res.status(401).json({ error: "Not logged in" }));

// SIGNUP and LOGIN: same as topics 06, 07 and 09, kept short so we have something to log out of
app.post("/signup", async (req, res) => {
  const { email, password } = req.body ?? {};
  if (!isValidEmail(email) || typeof password !== "string" || password.length < 8 || password.length > 128) {
    return res.status(400).json({ error: "A valid email and a password of 8-128 characters are required" });
  }
  const normalizedEmail = email.trim().toLowerCase();
  const passwordHash = await hashPassword(password);
  if (users.has(normalizedEmail)) return res.status(409).json({ error: "Email already registered" });

  const user = { id: crypto.randomUUID(), email: normalizedEmail, passwordHash };
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

  // Already logged in on this browser? Drop that session first, so a new login never reuses an old ID (session fixation)
  if (req.sessionKey) sessions.delete(req.sessionKey);
  const device = String(req.headers["user-agent"] ?? "Unknown device").slice(0, 100);
  const sessionId = createSession(user, device);
  res.cookie(COOKIE_NAME, sessionId, { ...COOKIE_OPTIONS, maxAge: SESSION_TTL_MS });
  res.json({ message: "Logged in", email: user.email, device });
});

app.get("/me", requireAuth, (req, res) => {
  const user = [...users.values()].find((u) => u.id === req.session.userId);
  res.json({ id: user.id, email: user.email, device: req.session.device });
});

// "Where am I logged in?": the list behind a "Manage devices" page
app.get("/sessions", requireAuth, (req, res) => {
  const mine = [...sessions.values()]
    .filter((s) => s.userId === req.session.userId)
    .map((s) => ({ id: s.publicId, device: s.device, createdAt: s.createdAt, current: s === req.session }));
  res.json(mine);
});

// 1. LOGOUT (this device): delete the session on the server, then clear the cookie in the browser
app.post("/logout", (req, res) => {
  // Step 1: the server forgets the session. Now the old ID is useless, even if someone copied it.
  if (req.sessionKey) sessions.delete(req.sessionKey);

  // Step 2: tell the browser to delete the cookie (same name + path + domain as when it was set)
  res.clearCookie(COOKIE_NAME, COOKIE_OPTIONS);
  // Step 3 (bonus): ask the browser to wipe cookies and storage for this site too (localStorage, IndexedDB…)
  res.set("Clear-Site-Data", '"cookies", "storage"');

  // Same happy answer even if there was no session: logging out twice is not an error
  res.json({ message: "Logged out" });
});

// Logout must be a POST. A GET can be triggered by any <img src="/logout"> on another site, or by link prefetching.
app.get("/logout", (req, res) => res.status(405).set("Allow", "POST").json({ error: "Use POST /logout" }));

// 2. LOGOUT ALL DEVICES: "I lost my phone" or "someone else is in my account"
app.post("/logout-all", requireAuth, (req, res) => {
  const count = deleteSessionsOf(req.session.userId);
  res.clearCookie(COOKIE_NAME, COOKIE_OPTIONS);
  res.json({ message: `Logged out of ${count} device(s)` });
});

// 3. LOGOUT ONE OTHER DEVICE: the "Log out" button next to a device in the list
app.delete("/sessions/:id", requireAuth, (req, res) => {
  for (const [key, s] of sessions) {
    // Must be one of MY sessions: never let a user log out someone else by guessing an id
    if (s.publicId === req.params.id && s.userId === req.session.userId) {
      sessions.delete(key);
      if (s === req.session) res.clearCookie(COOKIE_NAME, COOKIE_OPTIONS);
      return res.json({ message: `Logged out: ${s.device}` });
    }
  }
  res.status(404).json({ error: "Session not found" });
});

app.use((req, res) => res.status(404).json({ error: "Not found" }));

// Errors (bad JSON, body too big, bugs) come here. Never send the stack trace to the client.
app.use((err, req, res, next) => {
  if (err.type === "entity.parse.failed") return res.status(400).json({ error: "Body must be valid JSON" });
  if (err.type === "entity.too.large") return res.status(413).json({ error: "Request body too large" });
  console.error(err);
  res.status(500).json({ error: "Something went wrong" });
});

app.listen(PORT, () => console.log(`Logout API on ${BASE_URL}`));

// Delete expired sessions every minute so the store doesn't grow forever
setInterval(() => {
  const now = Date.now();
  for (const [key, s] of sessions) if (now > s.expiresAt) sessions.delete(key);
}, 60_000).unref();
