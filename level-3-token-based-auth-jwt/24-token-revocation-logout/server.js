const express = require("express");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const { promisify } = require("util");

const scrypt = promisify(crypto.scrypt);
const SCRYPT_OPTIONS = { N: 2 ** 17, r: 8, p: 1, maxmem: 256 * 1024 * 1024 };

const PORT = Number(process.env.PORT) || 3000;
const BASE_URL = `http://localhost:${PORT}`;
const ACCESS_TTL_SECONDS = Number(process.env.ACCESS_TTL_SECONDS) || 15 * 60; // 15 minutes
const REFRESH_TTL_MS = 7 * 24 * 60 * 60 * 1000;                              // 7 days

// shortcut: a new random secret on every start (all tokens die on restart). A real app loads it from an env var / secret manager.
const ACCESS_SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString("hex");

const REFRESH_COOKIE = "refreshToken";
const REFRESH_COOKIE_OPTIONS = { httpOnly: true, sameSite: "strict", path: "/auth", secure: process.env.NODE_ENV === "production" };

// ---------- "Database" ----------
// shortcut: in-memory Maps, lost on restart. A real app uses database tables, and Redis for the deny-list.
const users = new Map();          // email -> { id, email, passwordHash, tokenVersion }
const refreshTokens = new Map();  // sha256(refreshToken) -> { userId, expiresAt }
const revokedAccessTokens = new Map(); // jti -> exp (seconds). The DENY-LIST: only needed until the token would expire anyway.

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

// Every access token gets:
//   jti = a unique ID, so ONE token can be put on the deny-list (logout on this device)
//   ver = the user's tokenVersion, so ALL of a user's tokens can be killed at once (bump the number)
function issueTokens(res, user) {
  const refreshToken = crypto.randomBytes(32).toString("hex");
  refreshTokens.set(sha256(refreshToken), { userId: user.id, expiresAt: Date.now() + REFRESH_TTL_MS });
  res.cookie(REFRESH_COOKIE, refreshToken, { ...REFRESH_COOKIE_OPTIONS, maxAge: REFRESH_TTL_MS });
  return accessTokenResponse(user);
}

const accessTokenResponse = (user) => ({
  accessToken: jwt.sign({ sub: user.id, email: user.email, ver: user.tokenVersion }, ACCESS_SECRET,
    { algorithm: "HS256", expiresIn: ACCESS_TTL_SECONDS, jwtid: crypto.randomUUID() }),
  tokenType: "Bearer",
  expiresIn: ACCESS_TTL_SECONDS,
});

function deleteAllRefreshTokens(userId) {
  for (const [key, t] of refreshTokens) if (t.userId === userId) refreshTokens.delete(key);
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

// The price of revocation: after checking the signature, we look up STATE on every request
// (the deny-list and the user's tokenVersion). In production this is one fast Redis/cache lookup.
function requireAuth(req, res, next) {
  const [scheme, token] = (req.headers.authorization ?? "").split(" ");
  if (scheme !== "Bearer" || !token) return res.status(401).json({ error: "Missing access token" });
  let claims;
  try {
    claims = jwt.verify(token, ACCESS_SECRET, { algorithms: ["HS256"] });
  } catch (err) {
    if (err.name === "TokenExpiredError") return res.status(401).json({ error: "Access token expired", code: "token_expired" });
    return res.status(401).json({ error: "Invalid access token", code: "invalid_token" });
  }
  // Step 2: this exact token was logged out
  if (revokedAccessTokens.has(claims.jti)) return res.status(401).json({ error: "Access token was revoked (logged out)", code: "token_revoked" });
  // Step 3: all of this user's tokens were revoked (log out everywhere, password change), or the user is gone
  const user = findUserById(claims.sub);
  if (!user || claims.ver !== user.tokenVersion) return res.status(401).json({ error: "Access token was revoked, please log in again", code: "token_revoked" });
  req.auth = claims;
  req.user = user;
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
  const user = { id: crypto.randomUUID(), email: normalizedEmail, passwordHash, tokenVersion: 1 };
  users.set(normalizedEmail, user);
  res.status(201).json({ id: user.id, email: user.email });
});

app.post("/auth/login", async (req, res) => {
  const { email, password } = req.body ?? {};
  if (typeof email !== "string" || typeof password !== "string" || !email || !password) {
    return res.status(400).json({ error: "Email and password are required" });
  }
  const user = users.get(email.trim().toLowerCase());
  const ok = await verifyPassword(password, user ? user.passwordHash : await DUMMY_HASH_PROMISE);
  if (!user || !ok) return res.status(401).json({ error: "Invalid email or password" });
  res.json(issueTokens(res, user));
});

// Same as topic 21. Revoked refresh tokens are simply GONE from the table, so they fail here.
app.post("/auth/refresh", (req, res) => {
  const refreshToken = readCookie(req, REFRESH_COOKIE);
  if (!/^[a-f0-9]{64}$/.test(refreshToken ?? "")) return res.status(401).json({ error: "Missing refresh token, please log in" });
  const key = sha256(refreshToken);
  const stored = refreshTokens.get(key);
  const user = stored && findUserById(stored.userId);
  if (!stored || Date.now() > stored.expiresAt || !user) {
    if (stored) refreshTokens.delete(key);
    res.clearCookie(REFRESH_COOKIE, REFRESH_COOKIE_OPTIONS);
    return res.status(401).json({ error: "Refresh token is invalid or expired, please log in" });
  }
  // shortcut: no rotation here to keep the focus on revocation. Topic 23 adds rotation + reuse detection.
  res.json(accessTokenResponse(user));
});

// Step 1 + 2: LOGOUT (this device): delete the refresh token AND deny-list the current access token.
// Works even if the access token is missing or expired: logout must never fail.
app.post("/auth/logout", (req, res) => {
  const refreshToken = readCookie(req, REFRESH_COOKIE);
  if (refreshToken) refreshTokens.delete(sha256(refreshToken));

  const [scheme, token] = (req.headers.authorization ?? "").split(" ");
  if (scheme === "Bearer" && token) {
    try {
      // Check the signature (never deny-list garbage), but accept an expired token (nothing to do then)
      const { jti, exp } = jwt.verify(token, ACCESS_SECRET, { algorithms: ["HS256"], ignoreExpiration: true });
      if (exp * 1000 > Date.now()) revokedAccessTokens.set(jti, exp);
    } catch { /* invalid token: nothing to revoke */ }
  }
  res.clearCookie(REFRESH_COOKIE, REFRESH_COOKIE_OPTIONS);
  res.json({ message: "Logged out on this device" });
});

// Step 3: LOG OUT EVERYWHERE: bump tokenVersion (kills every access token) + delete every refresh token
app.post("/auth/logout-all", requireAuth, (req, res) => {
  req.user.tokenVersion++;
  deleteAllRefreshTokens(req.user.id);
  res.clearCookie(REFRESH_COOKIE, REFRESH_COOKIE_OPTIONS);
  res.json({ message: "Logged out on every device" });
});

// Step 4: PASSWORD CHANGE revokes everything too (topic 14), then logs THIS device back in with fresh tokens
app.post("/auth/change-password", requireAuth, async (req, res) => {
  const { currentPassword, newPassword } = req.body ?? {};
  if (typeof currentPassword !== "string" || typeof newPassword !== "string" || newPassword.length < 8 || newPassword.length > 128) {
    return res.status(400).json({ error: "currentPassword and a newPassword of 8-128 characters are required" });
  }
  if (!(await verifyPassword(currentPassword, req.user.passwordHash))) return res.status(401).json({ error: "Current password is wrong" });

  req.user.passwordHash = await hashPassword(newPassword);
  req.user.tokenVersion++;             // every old access token, on every device, is now rejected
  deleteAllRefreshTokens(req.user.id); // and no device can refresh
  console.log(`📧 To: ${req.user.email}: "Your password was changed and all other devices were logged out."`);
  res.json({ message: "Password changed. Other devices were logged out.", ...issueTokens(res, req.user) });
});

app.get("/me", requireAuth, (req, res) => {
  res.json({ email: req.user.email, jti: req.auth.jti, tokenVersion: req.auth.ver });
});

app.use((req, res) => res.status(404).json({ error: "Not found" }));

// Errors (bad JSON, body too big, bugs) come here. Never send the stack trace to the client.
app.use((err, req, res, next) => {
  if (err.type === "entity.parse.failed") return res.status(400).json({ error: "Body must be valid JSON" });
  if (err.type === "entity.too.large") return res.status(413).json({ error: "Request body too large" });
  console.error(err);
  res.status(500).json({ error: "Something went wrong" });
});

app.listen(PORT, () => console.log(`Token revocation API on ${BASE_URL}`));

// Keep the deny-list SMALL: a revoked token can be forgotten once it would have expired anyway
setInterval(() => {
  const now = Date.now();
  for (const [jti, exp] of revokedAccessTokens) if (exp * 1000 < now) revokedAccessTokens.delete(jti);
  for (const [key, t] of refreshTokens) if (now > t.expiresAt) refreshTokens.delete(key);
}, 60_000).unref();
