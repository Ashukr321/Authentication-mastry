const express = require("express");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const { promisify } = require("util");

const scrypt = promisify(crypto.scrypt);
const SCRYPT_OPTIONS = { N: 2 ** 17, r: 8, p: 1, maxmem: 256 * 1024 * 1024 };

const PORT = Number(process.env.PORT) || 3000;
const BASE_URL = `http://localhost:${PORT}`;
const ACCESS_TTL_SECONDS = Number(process.env.ACCESS_TTL_SECONDS) || 15 * 60; // 15 minutes
const REFRESH_TTL_MS = 7 * 24 * 60 * 60 * 1000;                              // 7 days, counted from LOGIN

// shortcut: a new random secret on every start (all tokens die on restart). A real app loads it from an env var / secret manager.
const ACCESS_SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString("hex");

const REFRESH_COOKIE = "refreshToken";
const REFRESH_COOKIE_OPTIONS = { httpOnly: true, sameSite: "strict", path: "/auth", secure: process.env.NODE_ENV === "production" };

// ---------- "Database" ----------
// shortcut: in-memory Maps, lost on restart. A real app uses database tables.
const users = new Map(); // email -> { id, email, passwordHash }
// sha256(refreshToken) -> { userId, familyId, expiresAt, usedAt }
// USED tokens are KEPT (usedAt set) until the family expires: that's how we recognize them when they come back.
const refreshTokens = new Map();

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

const tokenResponse = (user) => ({
  accessToken: jwt.sign({ sub: user.id, email: user.email }, ACCESS_SECRET, { algorithm: "HS256", expiresIn: ACCESS_TTL_SECONDS }),
  tokenType: "Bearer",
  expiresIn: ACCESS_TTL_SECONDS,
});

// Step 1: every refresh token belongs to a FAMILY = one login on one device.
// Login starts a new family. Each rotation adds a new token to the SAME family, with the SAME end date.
function issueRefreshToken(res, userId, familyId, expiresAt) {
  const refreshToken = crypto.randomBytes(32).toString("hex");
  refreshTokens.set(sha256(refreshToken), { userId, familyId, expiresAt, usedAt: null });
  res.cookie(REFRESH_COOKIE, refreshToken, { ...REFRESH_COOKIE_OPTIONS, maxAge: expiresAt - Date.now() });
}

function revokeFamily(familyId) {
  for (const [key, t] of refreshTokens) if (t.familyId === familyId) refreshTokens.delete(key);
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

function requireAuth(req, res, next) {
  const [scheme, token] = (req.headers.authorization ?? "").split(" ");
  if (scheme !== "Bearer" || !token) return res.status(401).json({ error: "Missing access token" });
  try {
    req.auth = jwt.verify(token, ACCESS_SECRET, { algorithms: ["HS256"] });
    next();
  } catch (err) {
    if (err.name === "TokenExpiredError") return res.status(401).json({ error: "Access token expired", code: "token_expired" });
    res.status(401).json({ error: "Invalid access token", code: "invalid_token" });
  }
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

// LOGIN: a brand-new family for this device
app.post("/auth/login", async (req, res) => {
  const { email, password } = req.body ?? {};
  if (typeof email !== "string" || typeof password !== "string" || !email || !password) {
    return res.status(400).json({ error: "Email and password are required" });
  }
  const user = users.get(email.trim().toLowerCase());
  const ok = await verifyPassword(password, user ? user.passwordHash : await DUMMY_HASH_PROMISE);
  if (!user || !ok) return res.status(401).json({ error: "Invalid email or password" });

  issueRefreshToken(res, user.id, crypto.randomUUID(), Date.now() + REFRESH_TTL_MS);
  res.json(tokenResponse(user));
});

// REFRESH with ROTATION: every refresh token works exactly ONCE
app.post("/auth/refresh", (req, res) => {
  const refreshToken = readCookie(req, REFRESH_COOKIE);
  if (!/^[a-f0-9]{64}$/.test(refreshToken ?? "")) return res.status(401).json({ error: "Missing refresh token, please log in" });

  const key = sha256(refreshToken);
  const stored = refreshTokens.get(key);
  const user = stored && findUserById(stored.userId);
  if (!stored || Date.now() > stored.expiresAt || !user) {
    if (stored) revokeFamily(stored.familyId);
    res.clearCookie(REFRESH_COOKIE, REFRESH_COOKIE_OPTIONS);
    return res.status(401).json({ error: "Refresh token is invalid or expired, please log in" });
  }

  // Step 3: REUSE DETECTION. This token was already exchanged once. Only two people could have it:
  // the real user and a thief. We can't tell who is sending it now, so we kill the WHOLE family:
  // the thief's new token AND the user's new token both stop working.
  if (stored.usedAt) {
    revokeFamily(stored.familyId);
    res.clearCookie(REFRESH_COOKIE, REFRESH_COOKIE_OPTIONS);
    console.log(`\n🚨 Refresh token reuse for ${user.email} (family ${stored.familyId}). Family revoked.\n📧 To: ${user.email}: "Someone may have stolen your login on one device. We logged that device out. Please log in again."\n`);
    return res.status(401).json({ error: "Refresh token reuse detected. This login was revoked, please log in again.", code: "token_reused" });
  }

  // Step 2: ROTATE. Mark the old token as used (don't delete it, step 3 needs it), issue a new one in the same family.
  // shortcut: in a real DB, do "UPDATE ... SET usedAt = now WHERE id = ? AND usedAt IS NULL" so two parallel requests can't both pass.
  stored.usedAt = Date.now();
  issueRefreshToken(res, user.id, stored.familyId, stored.expiresAt); // SAME end date: rotation can't extend the login forever
  res.json(tokenResponse(user));
});

// LOGOUT: revoke this device's whole family (topic 24 goes further)
app.post("/auth/logout", (req, res) => {
  const refreshToken = readCookie(req, REFRESH_COOKIE);
  const stored = refreshToken && refreshTokens.get(sha256(refreshToken));
  if (stored) revokeFamily(stored.familyId);
  res.clearCookie(REFRESH_COOKIE, REFRESH_COOKIE_OPTIONS);
  res.json({ message: "Logged out" });
});

app.get("/me", requireAuth, (req, res) => {
  res.json({ email: req.auth.email });
});

app.use((req, res) => res.status(404).json({ error: "Not found" }));

// Errors (bad JSON, body too big, bugs) come here. Never send the stack trace to the client.
app.use((err, req, res, next) => {
  if (err.type === "entity.parse.failed") return res.status(400).json({ error: "Body must be valid JSON" });
  if (err.type === "entity.too.large") return res.status(413).json({ error: "Request body too large" });
  console.error(err);
  res.status(500).json({ error: "Something went wrong" });
});

app.listen(PORT, () => console.log(`Refresh token rotation API on ${BASE_URL}`));

// Delete expired tokens (used or not) every minute. Used tokens must live until then, or reuse goes unnoticed.
setInterval(() => {
  const now = Date.now();
  for (const [key, t] of refreshTokens) if (now > t.expiresAt) refreshTokens.delete(key);
}, 60_000).unref();
