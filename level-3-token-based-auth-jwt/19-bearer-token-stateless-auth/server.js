const express = require("express");
const crypto = require("crypto");
const { promisify } = require("util");
const jwt = require("jsonwebtoken");

const scrypt = promisify(crypto.scrypt);
const SCRYPT_OPTIONS = { N: 2 ** 17, r: 8, p: 1, maxmem: 256 * 1024 * 1024 };

const PORT = Number(process.env.PORT) || 3000;
const BASE_URL = `http://localhost:${PORT}`;

// The ONE secret every server uses to sign and check tokens. Anyone who has it can make tokens for any user.
// HS256 needs at least 256 random bits: generate one with
//   node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
// Without JWT_SECRET we make a random one, so every restart logs everyone out (on purpose: no weak default).
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString("hex");
if (JWT_SECRET.length < 32) throw new Error("JWT_SECRET must be at least 32 characters");
const TOKEN_TTL_SECONDS = Number(process.env.TOKEN_TTL_SECONDS) || 15 * 60; // 15 minutes
const ISSUER = BASE_URL;        // "who made this token"
const AUDIENCE = "notes-api";   // "who this token is for": another API must reject it

// ---------- "Database" ----------
// shortcut: in-memory Map, lost on restart. A real app uses a users table.
// Notice what is NOT here: no sessions Map. The server remembers nothing about who is logged in.
const users = new Map(); // email -> { id, email, passwordHash }

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

const isValidEmail = (email) => typeof email === "string" && email.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim());
const isValidPassword = (password) => typeof password === "string" && password.length >= 8 && password.length <= 128;

// Step 1: SIGN a token. The payload is only base64url, NOT encrypted: anyone can read it, so no secrets in here.
function issueToken(user) {
  return jwt.sign({ email: user.email }, JWT_SECRET, {
    algorithm: "HS256",
    subject: user.id,            // "sub": who this token is about
    issuer: ISSUER,              // "iss"
    audience: AUDIENCE,          // "aud"
    expiresIn: TOKEN_TTL_SECONDS, // "exp": it can't be revoked, so it MUST expire
    jwtid: crypto.randomUUID(),  // "jti": a unique id, useful for logs and a deny-list later (topic 24)
  });
}

// RFC 6750: tell the client HOW to authenticate (WWW-Authenticate), and with error="..." WHY it failed.
// A malformed header is the client's bug (400), a missing / bad / expired token is 401.
function unauthorized(res, error, description, status = 401) {
  const params = error ? `realm="notes-api", error="${error}", error_description="${description}"` : `realm="notes-api"`;
  res.set("WWW-Authenticate", `Bearer ${params}`);
  res.status(status).json({ error: description ?? "Missing bearer token" });
}

// Step 3: the "bouncer" on every protected route. No database, no session store: just maths on the token.
// "Bearer" is case-insensitive, then ONE space, then the token (base64url pieces joined by dots).
const BEARER = /^Bearer ([A-Za-z0-9\-._~+/]+=*)$/i;
function requireAuth(req, res, next) {
  const header = req.get("Authorization");
  if (!header) return unauthorized(res);
  const token = BEARER.exec(header)?.[1];
  if (!token) return unauthorized(res, "invalid_request", "Authorization header must be: Bearer <token>", 400);

  try {
    // ALWAYS pin the algorithm list: never let the token's own header choose ("alg": "none", topic 18)
    const claims = jwt.verify(token, JWT_SECRET, { algorithms: ["HS256"], issuer: ISSUER, audience: AUDIENCE });
    req.user = { id: claims.sub, email: claims.email, expiresAt: new Date(claims.exp * 1000).toISOString() };
    next();
  } catch (err) {
    // Expired, bad signature, wrong issuer/audience, garbage: all 401. Give a hint, never the details of the check.
    const description = err.name === "TokenExpiredError" ? "Token expired" : "Invalid token";
    unauthorized(res, "invalid_token", description);
  }
}

// ---------- App ----------
const app = express();
app.use(express.json({ limit: "10kb" }));
app.use((req, res, next) => {
  res.set("Cache-Control", "no-store"); // tokens and private data must not end up in a cache
  next();
});

app.post("/signup", async (req, res) => {
  const { email, password } = req.body ?? {};
  if (!isValidEmail(email) || !isValidPassword(password)) {
    return res.status(400).json({ error: "A valid email and a password of 8-128 characters are required" });
  }
  const normalizedEmail = email.trim().toLowerCase();
  const passwordHash = await hashPassword(password);
  if (users.has(normalizedEmail)) return res.status(409).json({ error: "Email already registered" });

  const user = { id: crypto.randomUUID(), email: normalizedEmail, passwordHash };
  users.set(normalizedEmail, user);
  res.status(201).json({ id: user.id, email: user.email });
});

// Step 1: LOGIN checks the password once (same as topic 07) and hands out a signed token instead of a session cookie.
// shortcut: no attempt limit. A real app rate-limits login (topic 16).
app.post("/login", async (req, res) => {
  const { email, password } = req.body ?? {};
  if (typeof email !== "string" || typeof password !== "string" || !email || !password || password.length > 128) {
    return res.status(400).json({ error: "Email and password are required" });
  }
  const user = users.get(email.trim().toLowerCase());
  const ok = await verifyPassword(password, user ? user.passwordHash : await DUMMY_HASH_PROMISE);
  if (!user || !ok) return res.status(401).json({ error: "Invalid email or password" });

  // The OAuth 2.0 response shape (RFC 6749). The client keeps the token and sends it back in a header (Step 2).
  res.json({ access_token: issueToken(user), token_type: "Bearer", expires_in: TOKEN_TTL_SECONDS });
});

// Step 4: a protected route. Who you are comes from the token's claims, not from a database lookup.
app.get("/me", requireAuth, (req, res) => {
  res.json(req.user);
});

// Step 5: "logout" in pure stateless auth. The server has nothing to delete, so the CLIENT throws the token away.
// A copy of the token keeps working until it expires: that's why tokens are short-lived (topics 20-24 fix this).
app.post("/logout", requireAuth, (req, res) => {
  res.json({ message: "Delete the token on your side. The server keeps no session, so it can't log the token out." });
});

app.use((req, res) => res.status(404).json({ error: "Not found" }));

// Errors (bad JSON, body too big, bugs) come here. Never send the stack trace to the client.
app.use((err, req, res, next) => {
  if (err.type === "entity.parse.failed") return res.status(400).json({ error: "Body must be valid JSON" });
  if (err.type === "entity.too.large") return res.status(413).json({ error: "Request body too large" });
  console.error(err);
  res.status(500).json({ error: "Something went wrong" });
});

app.listen(PORT, () => {
  console.log(`Bearer token API on ${BASE_URL} (tokens live ${TOKEN_TTL_SECONDS} seconds)`);
  if (!process.env.JWT_SECRET) console.log("⚠️  No JWT_SECRET set: using a random one, so tokens stop working when the server restarts.");
});
