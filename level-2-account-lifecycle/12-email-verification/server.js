const express = require("express");
const crypto = require("crypto");
const { promisify } = require("util");

const scrypt = promisify(crypto.scrypt);
const SCRYPT_OPTIONS = { N: 2 ** 17, r: 8, p: 1, maxmem: 256 * 1024 * 1024 };

const PORT = Number(process.env.PORT) || 3000;
// The link is built from OUR config, never from the request's Host header (host header injection)
const BASE_URL = `http://localhost:${PORT}`;
// How long a verification link works (set VERIFY_TTL_SECONDS=10 to watch a link expire)
const TOKEN_TTL_MS = (Number(process.env.VERIFY_TTL_SECONDS) || 24 * 60 * 60) * 1000; // 24 hours
const RESEND_COOLDOWN_MS = 60 * 1000; // at most one new email per minute per user

// ---------- "Database" ----------
// shortcut: in-memory Maps, lost on restart. A real app uses database tables.
const users = new Map();              // email -> { id, email, passwordHash, emailVerified, verifiedAt, lastEmailSentAt }
const verificationTokens = new Map(); // sha256(token) -> { userId, expiresAt }

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

// ---------- Verification tokens ----------
// Store only the HASH of the token, so a leaked database can't be used to verify emails.
const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");
const findUserById = (id) => [...users.values()].find((u) => u.id === id);

function createVerificationToken(user) {
  // A new link kills every older link for this user
  for (const [key, t] of verificationTokens) if (t.userId === user.id) verificationTokens.delete(key);

  const token = crypto.randomBytes(32).toString("hex"); // 256 random bits: impossible to guess
  verificationTokens.set(sha256(token), { userId: user.id, expiresAt: Date.now() + TOKEN_TTL_MS });
  return token;
}

// shortcut: "sends" the email by printing it in the terminal. Use a real email service (SES, Resend, SendGrid) in production.
function sendVerificationEmail(user) {
  const token = createVerificationToken(user);
  user.lastEmailSentAt = Date.now();
  console.log(`\n📧 To: ${user.email}\n   Subject: Verify your email\n   Click: ${BASE_URL}/verify-email?token=${token}\n   (This link works for ${TOKEN_TTL_MS / 1000} seconds)\n`);
}

const isValidEmail = (email) => typeof email === "string" && email.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim());

// ---------- App ----------
const app = express();
app.use(express.json({ limit: "10kb" })); // parse JSON bodies, reject anything bigger than 10 KB
app.use((req, res, next) => { res.set("Cache-Control", "no-store"); next(); });

// 1. SIGNUP: create the user as NOT verified, then send the link (same checks as topic 06, kept short)
app.post("/signup", async (req, res) => {
  const { email, password } = req.body ?? {}; // pick only the fields we expect
  if (!isValidEmail(email) || typeof password !== "string" || password.length < 8 || password.length > 128) {
    return res.status(400).json({ error: "A valid email and a password of 8-128 characters are required" });
  }
  const normalizedEmail = email.trim().toLowerCase();
  const passwordHash = await hashPassword(password);
  if (users.has(normalizedEmail)) return res.status(409).json({ error: "Email already registered" });

  const user = { id: crypto.randomUUID(), email: normalizedEmail, passwordHash, emailVerified: false, verifiedAt: null, lastEmailSentAt: 0 };
  users.set(normalizedEmail, user);
  sendVerificationEmail(user);
  res.status(201).json({ id: user.id, email: user.email, emailVerified: false, message: "Account created. Check your email to verify it." });
});

// 2. VERIFY: the user clicks the link in the email
app.get("/verify-email", (req, res) => {
  const invalid = () => res.status(400).json({ error: "This link is invalid or has expired" });
  const { token } = req.query;
  if (typeof token !== "string" || !/^[a-f0-9]{64}$/.test(token)) return invalid();

  const key = sha256(token);
  const record = verificationTokens.get(key);
  // Same message for "never existed", "already used" and "expired", so attackers learn nothing
  if (!record) return invalid();

  verificationTokens.delete(key); // single use: deleted before anything else (no `await` in between, so no race)
  if (Date.now() > record.expiresAt) return invalid();

  const user = findUserById(record.userId);
  if (!user) return invalid();

  user.emailVerified = true;
  user.verifiedAt = new Date().toISOString();
  res.json({ message: "Email verified! You can now log in.", email: user.email });
});

// 3. RESEND: the email got lost, or the link expired
app.post("/resend-verification", (req, res) => {
  const { email } = req.body ?? {};
  if (!isValidEmail(email)) return res.status(400).json({ error: "A valid email is required" });

  const user = users.get(email.trim().toLowerCase());
  // Only send if the account exists, isn't verified yet, and we didn't just send one (stops email spam)
  if (user && !user.emailVerified && Date.now() - user.lastEmailSentAt > RESEND_COOLDOWN_MS) {
    sendVerificationEmail(user);
  }
  // ALWAYS the same answer, so this endpoint can't be used to find out who has an account
  res.status(202).json({ message: "If that account exists and isn't verified yet, we've sent a new link." });
});

// 4. LOGIN: blocked until the email is verified
app.post("/login", async (req, res) => {
  const { email, password } = req.body ?? {};
  if (typeof email !== "string" || typeof password !== "string" || !email || !password) {
    return res.status(400).json({ error: "Email and password are required" });
  }
  const user = users.get(email.trim().toLowerCase());
  const ok = await verifyPassword(password, user ? user.passwordHash : await DUMMY_HASH_PROMISE);
  if (!user || !ok) return res.status(401).json({ error: "Invalid email or password" });

  // Checked AFTER the password, so only the real owner learns the account is unverified
  if (!user.emailVerified) {
    return res.status(403).json({ error: "Please verify your email first. Check your inbox or ask for a new link." });
  }
  res.json({ message: "Logged in", id: user.id, email: user.email, emailVerified: true });
});

app.use((req, res) => res.status(404).json({ error: "Not found" }));

// Errors (bad JSON, body too big, bugs) come here. Never send the stack trace to the client.
app.use((err, req, res, next) => {
  if (err.type === "entity.parse.failed") return res.status(400).json({ error: "Body must be valid JSON" });
  if (err.type === "entity.too.large") return res.status(413).json({ error: "Request body too large" });
  console.error(err);
  res.status(500).json({ error: "Something went wrong" });
});

app.listen(PORT, () => console.log(`Email verification API on ${BASE_URL}`));

// Delete expired tokens every minute so the store doesn't grow forever
setInterval(() => {
  const now = Date.now();
  for (const [key, t] of verificationTokens) if (now > t.expiresAt) verificationTokens.delete(key);
}, 60_000).unref();
