const express = require("express");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const { promisify } = require("util");

const scrypt = promisify(crypto.scrypt);
const SCRYPT_OPTIONS = { N: 2 ** 17, r: 8, p: 1, maxmem: 256 * 1024 * 1024 };

const PORT = Number(process.env.PORT) || 3000;
const BASE_URL = `http://localhost:${PORT}`;
const ACCESS_TTL_SECONDS = Number(process.env.ACCESS_TTL_SECONDS) || 15 * 60; // 15 minutes
const REFRESH_TTL_MS = 30 * 24 * 60 * 60 * 1000;                             // 30 days
const MAX_DEVICES = Number(process.env.MAX_DEVICES) || 3;                     // like Netflix "3 screens"

// shortcut: a new random secret on every start (all tokens die on restart). A real app loads it from an env var / secret manager.
const ACCESS_SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString("hex");

const REFRESH_COOKIE = "refreshToken";
const REFRESH_COOKIE_OPTIONS = { httpOnly: true, sameSite: "strict", path: "/auth", secure: process.env.NODE_ENV === "production" };

// ---------- "Database" ----------
// shortcut: in-memory Maps, lost on restart. A real app uses database tables (and Redis for revokedSessions).
const users = new Map();    // email -> { id, email, passwordHash }
// Step 1: one row per LOGIN on a device. The refresh token belongs to it; access tokens carry its id ("sid").
const sessions = new Map(); // sessionId -> { id, userId, refreshTokenHash, device, ip, createdAt, lastUsedAt, expiresAt }
// Logged-out sessions whose access tokens may still be alive. Kept only for one access token lifetime.
const revokedSessions = new Map(); // sessionId -> time after which the entry can be forgotten

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
const userSessions = (userId) => [...sessions.values()].filter((s) => s.userId === userId);

function readCookie(req, name) {
  for (const part of (req.headers.cookie ?? "").split(";")) {
    const [key, ...rest] = part.trim().split("=");
    if (key === name) return rest.join("=");
  }
  return undefined;
}

// shortcut: the raw User-Agent, cut short. Real apps turn it into "Chrome on Windows" with a library like ua-parser-js.
const deviceName = (req) => (req.get("user-agent") || "Unknown device").slice(0, 80);

const accessTokenResponse = (user, session) => ({
  // "sid" ties this access token to ONE device's session, so that device can be logged out on its own
  accessToken: jwt.sign({ sub: user.id, email: user.email, sid: session.id }, ACCESS_SECRET, { algorithm: "HS256", expiresIn: ACCESS_TTL_SECONDS }),
  tokenType: "Bearer",
  expiresIn: ACCESS_TTL_SECONDS,
});

// Step 4: kill one device. The refresh token dies with the row; its access tokens die via revokedSessions.
function revokeSession(sessionId) {
  sessions.delete(sessionId);
  revokedSessions.set(sessionId, Date.now() + ACCESS_TTL_SECONDS * 1000);
}

// What the user sees in "Your devices". Never the refresh token or its hash.
const publicSession = (s, currentSid) => ({
  id: s.id, device: s.device, ip: s.ip,
  createdAt: new Date(s.createdAt).toISOString(), lastUsedAt: new Date(s.lastUsedAt).toISOString(),
  current: s.id === currentSid,
});

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

function requireAuth(req, res, next) {
  const [scheme, token] = (req.headers.authorization ?? "").split(" ");
  if (scheme !== "Bearer" || !token) return res.status(401).json({ error: "Missing access token" });
  try {
    req.auth = jwt.verify(token, ACCESS_SECRET, { algorithms: ["HS256"] });
  } catch (err) {
    if (err.name === "TokenExpiredError") return res.status(401).json({ error: "Access token expired", code: "token_expired" });
    return res.status(401).json({ error: "Invalid access token", code: "invalid_token" });
  }
  // The one stateful check: was THIS device logged out? (a small set, like the jti deny-list in topic 24)
  if (revokedSessions.has(req.auth.sid)) return res.status(401).json({ error: "This device was logged out", code: "session_revoked" });
  next();
}

app.post("/auth/signup", async (req, res) => {
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

// LOGIN = a new session for this device
app.post("/auth/login", async (req, res) => {
  const { email, password } = req.body ?? {};
  if (typeof email !== "string" || typeof password !== "string" || !email || !password) {
    return res.status(400).json({ error: "Email and password are required" });
  }
  const user = users.get(email.trim().toLowerCase());
  const ok = await verifyPassword(password, user ? user.passwordHash : await DUMMY_HASH_PROMISE);
  if (!user || !ok) return res.status(401).json({ error: "Invalid email or password" });

  const device = deviceName(req);
  const existing = userSessions(user.id);

  // Step 5: a device we haven't seen before? Tell the user (the classic "New sign-in to your account" email)
  if (existing.length > 0 && !existing.some((s) => s.device === device)) {
    console.log(`📧 To: ${user.email}: "New sign-in on ${device} from ${req.ip}. Not you? Log it out from Your devices and change your password."`);
  }

  // Step 6: device limit. Too many? Log out the one used LEAST recently.
  if (existing.length >= MAX_DEVICES) {
    const oldest = existing.reduce((a, b) => (a.lastUsedAt <= b.lastUsedAt ? a : b));
    revokeSession(oldest.id);
    console.log(`🔌 Device limit (${MAX_DEVICES}) reached: logged out "${oldest.device}"`);
  }

  const refreshToken = crypto.randomBytes(32).toString("hex");
  const now = Date.now();
  const session = { id: crypto.randomUUID(), userId: user.id, refreshTokenHash: sha256(refreshToken), device, ip: req.ip, createdAt: now, lastUsedAt: now, expiresAt: now + REFRESH_TTL_MS };
  sessions.set(session.id, session);
  res.cookie(REFRESH_COOKIE, refreshToken, { ...REFRESH_COOKIE_OPTIONS, maxAge: REFRESH_TTL_MS });
  res.json(accessTokenResponse(user, session));
});

// Step 2: REFRESH also updates "last active". Access tokens are checked without the DB, so this is the
// only moment we see the device: "last active" is accurate to one access token lifetime (15 min).
app.post("/auth/refresh", (req, res) => {
  const refreshToken = readCookie(req, REFRESH_COOKIE);
  const hash = /^[a-f0-9]{64}$/.test(refreshToken ?? "") && sha256(refreshToken);
  // shortcut: a scan. A real DB has an index on refresh_token_hash.
  const session = hash && [...sessions.values()].find((s) => s.refreshTokenHash === hash);
  const user = session && findUserById(session.userId);
  if (!session || Date.now() > session.expiresAt || !user) {
    if (session) revokeSession(session.id);
    res.clearCookie(REFRESH_COOKIE, REFRESH_COOKIE_OPTIONS);
    return res.status(401).json({ error: "This device is logged out, please log in" });
  }
  session.lastUsedAt = Date.now();
  session.ip = req.ip;
  // shortcut: no rotation here. Topic 23 rotates the refresh token on every use.
  res.json(accessTokenResponse(user, session));
});

app.post("/auth/logout", requireAuth, (req, res) => {
  revokeSession(req.auth.sid);
  res.clearCookie(REFRESH_COOKIE, REFRESH_COOKIE_OPTIONS);
  res.json({ message: "Logged out on this device" });
});

// Step 3: "Your devices"
app.get("/sessions", requireAuth, (req, res) => {
  const list = userSessions(req.auth.sub).sort((a, b) => b.lastUsedAt - a.lastUsedAt).map((s) => publicSession(s, req.auth.sid));
  res.json({ devices: list });
});

// Step 4: log out ONE other device. Only your own: someone else's id gets the same 404 as a made-up one.
app.delete("/sessions/:id", requireAuth, (req, res) => {
  const session = sessions.get(req.params.id);
  if (!session || session.userId !== req.auth.sub) return res.status(404).json({ error: "Device not found" });
  revokeSession(session.id);
  res.json({ message: `Logged out "${session.device}"` });
});

// "Log out all OTHER devices" (keep this one)
app.post("/sessions/revoke-others", requireAuth, (req, res) => {
  const others = userSessions(req.auth.sub).filter((s) => s.id !== req.auth.sid);
  others.forEach((s) => revokeSession(s.id));
  res.json({ message: `Logged out ${others.length} other device(s)` });
});

app.get("/me", requireAuth, (req, res) => {
  res.json({ email: req.auth.email, sessionId: req.auth.sid });
});

app.use((req, res) => res.status(404).json({ error: "Not found" }));

// Errors (bad JSON, body too big, bugs) come here. Never send the stack trace to the client.
app.use((err, req, res, next) => {
  if (err.type === "entity.parse.failed") return res.status(400).json({ error: "Body must be valid JSON" });
  if (err.type === "entity.too.large") return res.status(413).json({ error: "Request body too large" });
  console.error(err);
  res.status(500).json({ error: "Something went wrong" });
});

app.listen(PORT, () => console.log(`Multi-device sessions API on ${BASE_URL} (max ${MAX_DEVICES} devices per user)`));

// Forget expired sessions, and revoked-session entries whose access tokens have all expired
setInterval(() => {
  const now = Date.now();
  for (const [id, s] of sessions) if (now > s.expiresAt) sessions.delete(id);
  for (const [id, until] of revokedSessions) if (now > until) revokedSessions.delete(id);
}, 60_000).unref();
