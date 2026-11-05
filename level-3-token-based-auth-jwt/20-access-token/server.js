const express = require("express");
const crypto = require("crypto");
const { promisify } = require("util");
const jwt = require("jsonwebtoken");

const scrypt = promisify(crypto.scrypt);
const SCRYPT_OPTIONS = { N: 2 ** 17, r: 8, p: 1, maxmem: 256 * 1024 * 1024 };

const PORT = Number(process.env.PORT) || 3000;
const BASE_URL = `http://localhost:${PORT}`;

// How long an access token lives. Short on purpose: a stolen token can't be "logged out" (see the notes).
// Set ACCESS_TOKEN_SECONDS=20 to watch a token expire.
const ACCESS_TOKEN_SECONDS = Number(process.env.ACCESS_TOKEN_SECONDS) || 15 * 60; // 15 minutes

// The signing secret. Anyone who knows it can make tokens for ANY user, so it never goes in the code or in git.
// shortcut: falls back to a random secret per start, so every token dies on restart. A real app reads it from
// a secret manager, and every server that verifies tokens gets the same one.
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString("hex");
if (!process.env.JWT_SECRET) console.warn("⚠️  No JWT_SECRET set: using a random one. Tokens stop working when the server restarts.");
if (JWT_SECRET.length < 32) throw new Error("JWT_SECRET must be at least 32 characters (256 bits) for HS256");

// Who made the token (iss) and who it is for (aud). Checking both stops a token made for
// another app (that happens to share the secret) from working here.
const ISSUER = "auth.example.com";
const AUDIENCE = "api.example.com";

// ---------- "Database" ----------
// shortcut: in-memory Map, lost on restart. A real app uses a users table.
const users = new Map(); // email -> { id, email, passwordHash, role }

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

const findUserById = (id) => [...users.values()].find((u) => u.id === id);
const isValidEmail = (email) => typeof email === "string" && email.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim());
const isValidPassword = (password) => typeof password === "string" && password.length >= 8 && password.length <= 128;

// Step 1: ISSUE (sign) the access token.
// Only what the API needs to decide "who is this and what may they do". The payload is NOT secret:
// anyone holding the token can read it, so no password, no email, no phone number.
function issueAccessToken(user) {
  return jwt.sign(
    { role: user.role },          // custom claim: used for authorization (Step 4)
    JWT_SECRET,
    {
      algorithm: "HS256",
      subject: user.id,           // sub: WHO. A random id that never changes, not the email
      issuer: ISSUER,             // iss
      audience: AUDIENCE,         // aud
      expiresIn: ACCESS_TOKEN_SECONDS, // exp (iat is added automatically)
    },
  );
}

// RFC 6750: a 401 for a bearer token says WHY in the WWW-Authenticate header, so the client knows what to do
function unauthorized(res, description) {
  const header = description ? `Bearer realm="api", error="invalid_token", error_description="${description}"` : 'Bearer realm="api"';
  res.set("WWW-Authenticate", header);
  return res.status(401).json({ error: description || "Missing access token" });
}

// Step 2 + Step 3: READ the token from the Authorization header and VERIFY it on every request.
// No session lookup: the signature alone proves the server made this token and nobody changed it.
function requireAccessToken(req, res, next) {
  const match = /^Bearer (\S+)$/i.exec(req.headers.authorization ?? ""); // the scheme name is case-insensitive
  if (!match) return unauthorized(res);

  try {
    req.token = jwt.verify(match[1], JWT_SECRET, {
      algorithms: ["HS256"], // PIN the algorithm: never trust the "alg" the token says it uses ("none", RS256/HS256 confusion)
      issuer: ISSUER,
      audience: AUDIENCE,
      clockTolerance: 5,     // allow 5 seconds of clock difference between servers
    });
  } catch (err) {
    // Expired is normal (the client should refresh, topics 21-22). Anything else is a bad or forged token.
    if (err.name === "TokenExpiredError") return unauthorized(res, "The access token expired");
    return unauthorized(res, "The access token is invalid");
  }
  next();
}

// Step 4: AUTHORIZE. The token is valid (you are logged in), but are you ALLOWED to do this?
// No → 403, not 401: logging in again won't help.
const requireRole = (role) => (req, res, next) => {
  if (req.token.role !== role) return res.status(403).json({ error: `Requires role: ${role}` });
  next();
};

// ---------- App ----------
const app = express();
app.use(express.json({ limit: "10kb" }));
app.use((req, res, next) => {
  res.set("Cache-Control", "no-store"); // never let a proxy or browser cache a response holding a token
  next();
});

// SIGNUP: same as topic 06. Everyone starts as a normal "user".
app.post("/signup", async (req, res) => {
  const { email, password } = req.body ?? {};
  if (!isValidEmail(email) || !isValidPassword(password)) {
    return res.status(400).json({ error: "A valid email and a password of 8-128 characters are required" });
  }
  const normalizedEmail = email.trim().toLowerCase();
  const passwordHash = await hashPassword(password);
  if (users.has(normalizedEmail)) return res.status(409).json({ error: "Email already registered" });

  const user = { id: crypto.randomUUID(), email: normalizedEmail, passwordHash, role: "user" };
  users.set(normalizedEmail, user);
  res.status(201).json({ id: user.id, email: user.email });
});

// LOGIN: check the password (topic 07), then hand out an access token instead of a session cookie.
// shortcut: no rate limit or lockout here. A real app adds topic 16.
app.post("/login", async (req, res) => {
  const { email, password } = req.body ?? {};
  if (typeof email !== "string" || typeof password !== "string" || !email || !password || password.length > 128) {
    return res.status(400).json({ error: "Email and password are required" });
  }
  const user = users.get(email.trim().toLowerCase());
  const ok = await verifyPassword(password, user ? user.passwordHash : await DUMMY_HASH_PROMISE);
  if (!user || !ok) return res.status(401).json({ error: "Invalid email or password" });

  // The OAuth 2.0 response shape (RFC 6749): every client library understands it
  res.json({ access_token: issueAccessToken(user), token_type: "Bearer", expires_in: ACCESS_TOKEN_SECONDS });
});

// Any valid token can read its own profile
app.get("/me", requireAccessToken, (req, res) => {
  // The token can outlive the user (deleted after it was issued), so load the user when it matters
  const user = findUserById(req.token.sub);
  if (!user) return unauthorized(res, "The user no longer exists");
  res.json({
    id: user.id,
    email: user.email,
    role: user.role,
    tokenExpiresAt: new Date(req.token.exp * 1000).toISOString(),
  });
});

// Only admins. Rahul's token is valid, so he gets 403 (not allowed), not 401 (not logged in).
app.get("/admin/stats", requireAccessToken, requireRole("admin"), (req, res) => {
  res.json({ users: users.size });
});

app.use((req, res) => res.status(404).json({ error: "Not found" }));

// Errors (bad JSON, body too big, bugs) come here. Never send the stack trace to the client.
app.use((err, req, res, next) => {
  if (err.type === "entity.parse.failed") return res.status(400).json({ error: "Body must be valid JSON" });
  if (err.type === "entity.too.large") return res.status(413).json({ error: "Request body too large" });
  console.error(err);
  res.status(500).json({ error: "Something went wrong" });
});

app.listen(PORT, () => console.log(`Access token API on ${BASE_URL} (tokens live ${ACCESS_TOKEN_SECONDS} seconds)`));
