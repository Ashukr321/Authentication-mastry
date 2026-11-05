const express = require("express");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const { promisify } = require("util");

const scrypt = promisify(crypto.scrypt);
const SCRYPT_OPTIONS = { N: 2 ** 17, r: 8, p: 1, maxmem: 256 * 1024 * 1024 };

const PORT = Number(process.env.PORT) || 3000;
const BASE_URL = `http://localhost:${PORT}`;
// Access token = SHORT (set ACCESS_TTL_SECONDS=5 to watch it expire). Refresh token = LONG.
const ACCESS_TTL_SECONDS = Number(process.env.ACCESS_TTL_SECONDS) || 15 * 60; // 15 minutes
const REFRESH_TTL_MS = 7 * 24 * 60 * 60 * 1000;                              // 7 days

// shortcut: a new random secret on every start (all tokens die on restart). A real app loads it from an env var / secret manager.
const ACCESS_SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString("hex");

// The refresh cookie is sent ONLY to /auth/* (Path), never readable by JavaScript (HttpOnly),
// never sent from other sites (SameSite=Strict). In production: secure: true (topic 10).
const REFRESH_COOKIE = "refreshToken";
const REFRESH_COOKIE_OPTIONS = { httpOnly: true, sameSite: "strict", path: "/auth", secure: process.env.NODE_ENV === "production" };

// ---------- "Database" ----------
// shortcut: in-memory Maps, lost on restart. A real app uses database tables.
const users = new Map();         // email -> { id, email, passwordHash }
const refreshTokens = new Map(); // sha256(refreshToken) -> { userId, expiresAt }

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

// ---------- Step 1: the ACCESS token (topic 20): a short-lived JWT, checked without the database ----------
function issueAccessToken(user) {
  return jwt.sign({ sub: user.id, email: user.email }, ACCESS_SECRET, { algorithm: "HS256", expiresIn: ACCESS_TTL_SECONDS });
}

// ---------- Step 2: the REFRESH token: a long-lived RANDOM string, stored only as a hash ----------
// Not a JWT on purpose: it's only ever checked by OUR server against OUR database, so it needs no claims.
function issueRefreshToken(res, user) {
  const refreshToken = crypto.randomBytes(32).toString("hex");
  const expiresAt = Date.now() + REFRESH_TTL_MS;
  refreshTokens.set(sha256(refreshToken), { userId: user.id, expiresAt }); // a leaked DB can't be used to refresh
  res.cookie(REFRESH_COOKIE, refreshToken, { ...REFRESH_COOKIE_OPTIONS, maxAge: REFRESH_TTL_MS });
}

const tokenResponse = (user) => ({ accessToken: issueAccessToken(user), tokenType: "Bearer", expiresIn: ACCESS_TTL_SECONDS });

// ---------- App ----------
const app = express();
app.use(express.json({ limit: "10kb" }));
app.use((req, res, next) => { res.set("Cache-Control", "no-store"); next(); }); // never cache tokens

// CSRF defense in depth (topic 11): the refresh cookie is sent automatically, so block other sites' POSTs
app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (["POST", "PUT", "PATCH", "DELETE"].includes(req.method) && origin && origin !== BASE_URL) {
    return res.status(403).json({ error: "Request from another site was blocked" });
  }
  next();
});

// Protected routes read ONLY the access token (Authorization: Bearer ..., topic 19). No database lookup.
function requireAuth(req, res, next) {
  const [scheme, token] = (req.headers.authorization ?? "").split(" ");
  if (scheme !== "Bearer" || !token) return res.status(401).json({ error: "Missing access token" });
  try {
    req.auth = jwt.verify(token, ACCESS_SECRET, { algorithms: ["HS256"] }); // pin the algorithm (topic 18)
    next();
  } catch (err) {
    // A clear "expired" code tells the client: "call /auth/refresh, then retry" (topic 22 automates this)
    if (err.name === "TokenExpiredError") return res.status(401).json({ error: "Access token expired", code: "token_expired" });
    res.status(401).json({ error: "Invalid access token" });
  }
}

// SIGNUP: same as topic 06, kept short
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

// LOGIN: check the password ONCE, then hand out a PAIR: access token (body) + refresh token (cookie)
app.post("/auth/login", async (req, res) => {
  const { email, password } = req.body ?? {};
  if (typeof email !== "string" || typeof password !== "string" || !email || !password) {
    return res.status(400).json({ error: "Email and password are required" });
  }
  const user = users.get(email.trim().toLowerCase());
  const ok = await verifyPassword(password, user ? user.passwordHash : await DUMMY_HASH_PROMISE);
  if (!user || !ok) return res.status(401).json({ error: "Invalid email or password" });

  issueRefreshToken(res, user);
  res.json(tokenResponse(user));
});

// Step 3: REFRESH: trade the refresh token for a NEW access token, without the password.
// This is the one place a JWT app goes back to the database, so it's where we can say "no".
app.post("/auth/refresh", (req, res) => {
  const refreshToken = readCookie(req, REFRESH_COOKIE);
  if (!/^[a-f0-9]{64}$/.test(refreshToken ?? "")) return res.status(401).json({ error: "Missing refresh token, please log in" });

  const key = sha256(refreshToken);
  const stored = refreshTokens.get(key);
  const user = stored && findUserById(stored.userId);
  if (!stored || Date.now() > stored.expiresAt || !user) {
    if (stored) refreshTokens.delete(key);                  // expired, or the user was deleted (topic 17)
    res.clearCookie(REFRESH_COOKIE, REFRESH_COOKIE_OPTIONS); // dead cookie: tell the browser to drop it
    return res.status(401).json({ error: "Refresh token is invalid or expired, please log in" });
  }

  // shortcut: the SAME refresh token is reused until it expires. Topic 23 rotates it on every use and detects reuse.
  res.json(tokenResponse(user));
});

// Step 4: LOGOUT deletes the refresh token on the SERVER. The access token can't be deleted:
// it keeps working until it expires, which is exactly why it must be short (topic 24).
app.post("/auth/logout", (req, res) => {
  const refreshToken = readCookie(req, REFRESH_COOKIE);
  if (refreshToken) refreshTokens.delete(sha256(refreshToken));
  res.clearCookie(REFRESH_COOKIE, REFRESH_COOKIE_OPTIONS);
  res.json({ message: "Logged out. This device can't get new access tokens anymore." });
});

app.get("/me", requireAuth, (req, res) => {
  res.json({ id: req.auth.sub, email: req.auth.email, accessTokenExpiresAt: new Date(req.auth.exp * 1000).toISOString() });
});

app.use((req, res) => res.status(404).json({ error: "Not found" }));

// Errors (bad JSON, body too big, bugs) come here. Never send the stack trace to the client.
app.use((err, req, res, next) => {
  if (err.type === "entity.parse.failed") return res.status(400).json({ error: "Body must be valid JSON" });
  if (err.type === "entity.too.large") return res.status(413).json({ error: "Request body too large" });
  console.error(err);
  res.status(500).json({ error: "Something went wrong" });
});

app.listen(PORT, () => console.log(`Refresh token API on ${BASE_URL} (access tokens last ${ACCESS_TTL_SECONDS} s, refresh tokens 7 days)`));

// Delete expired refresh tokens every minute
setInterval(() => {
  const now = Date.now();
  for (const [key, t] of refreshTokens) if (now > t.expiresAt) refreshTokens.delete(key);
}, 60_000).unref();
