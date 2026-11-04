const express = require("express");
const crypto = require("crypto");
const { promisify } = require("util");

const scrypt = promisify(crypto.scrypt);
const SCRYPT_OPTIONS = { N: 2 ** 17, r: 8, p: 1, maxmem: 256 * 1024 * 1024 };

const PORT = Number(process.env.PORT) || 3000;
// The link is built from OUR config, never from the request's Host header (host header injection)
const BASE_URL = `http://localhost:${PORT}`;
// How long a reset link works (set RESET_TTL_SECONDS=10 to watch a link expire)
const TOKEN_TTL_MS = (Number(process.env.RESET_TTL_SECONDS) || 15 * 60) * 1000; // 15 minutes
const RESEND_COOLDOWN_MS = 60 * 1000; // at most one reset email per minute per user

// ---------- "Database" ----------
// shortcut: in-memory Maps, lost on restart. A real app uses database tables.
const users = new Map();       // email -> { id, email, passwordHash, lastResetEmailAt, passwordChangedAt }
const resetTokens = new Map(); // sha256(token) -> { userId, expiresAt }
const sessions = new Map();    // sessionId -> { userId } (from topic 09)

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

// ---------- Reset tokens ----------
// Store only the HASH of the token, so a leaked database can't be used to reset anyone's password.
const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");
const findUserById = (id) => [...users.values()].find((u) => u.id === id);

function deleteResetTokensOf(userId) {
  for (const [key, t] of resetTokens) if (t.userId === userId) resetTokens.delete(key);
}

function deleteSessionsOf(userId) {
  for (const [sid, s] of sessions) if (s.userId === userId) sessions.delete(sid);
}

// shortcut: "sends" emails by printing them in the terminal. Use a real email service (SES, Resend, SendGrid) in production.
function sendResetEmail(user) {
  deleteResetTokensOf(user.id); // a new link kills every older link for this user
  const token = crypto.randomBytes(32).toString("hex"); // 256 random bits: impossible to guess
  resetTokens.set(sha256(token), { userId: user.id, expiresAt: Date.now() + TOKEN_TTL_MS });
  user.lastResetEmailAt = Date.now();
  console.log(`\n📧 To: ${user.email}\n   Subject: Reset your password\n   Click: ${BASE_URL}/reset-password?token=${token}\n   (This link works for ${TOKEN_TTL_MS / 1000} seconds. Didn't ask for it? Ignore this email.)\n`);
}

function sendPasswordChangedNotice(user) {
  console.log(`\n📧 To: ${user.email}\n   Subject: Your password was changed\n   If this wasn't you, contact support right away.\n`);
}

const isValidEmail = (email) => typeof email === "string" && email.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim());
const isValidPassword = (password) => typeof password === "string" && password.length >= 8 && password.length <= 128;
const isTokenShaped = (token) => typeof token === "string" && /^[a-f0-9]{64}$/.test(token);
const readSessionId = (req) => /(?:^|;\s*)sid=([a-f0-9]{64})/.exec(req.headers.cookie ?? "")?.[1];

// ---------- App ----------
const app = express();
app.use(express.json({ limit: "10kb" }));                         // JSON bodies (curl, fetch)
app.use(express.urlencoded({ extended: false, limit: "10kb" }));  // HTML form bodies (the reset page)
app.use((req, res, next) => {
  res.set("Cache-Control", "no-store");
  // The reset URL holds the token: never send it to other sites in the Referer header
  res.set("Referrer-Policy", "no-referrer");
  next();
});

// SIGNUP and LOGIN: same as topics 06, 07 and 09, kept short so we have an account to reset
app.post("/signup", async (req, res) => {
  const { email, password } = req.body ?? {};
  if (!isValidEmail(email) || !isValidPassword(password)) {
    return res.status(400).json({ error: "A valid email and a password of 8-128 characters are required" });
  }
  const normalizedEmail = email.trim().toLowerCase();
  const passwordHash = await hashPassword(password);
  if (users.has(normalizedEmail)) return res.status(409).json({ error: "Email already registered" });

  const user = { id: crypto.randomUUID(), email: normalizedEmail, passwordHash, lastResetEmailAt: 0, passwordChangedAt: null };
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

  const sid = crypto.randomBytes(32).toString("hex");
  sessions.set(sid, { userId: user.id });
  res.cookie("sid", sid, { httpOnly: true, sameSite: "lax", path: "/" });
  res.json({ message: "Logged in", email: user.email });
});

app.get("/me", (req, res) => {
  const session = sessions.get(readSessionId(req));
  const user = session && findUserById(session.userId);
  if (!user) return res.status(401).json({ error: "Not logged in" });
  res.json({ id: user.id, email: user.email });
});

// 1. FORGOT: the user types their email on the "Forgot password?" page
app.post("/forgot-password", (req, res) => {
  const { email } = req.body ?? {};
  if (!isValidEmail(email)) return res.status(400).json({ error: "A valid email is required" });

  const user = users.get(email.trim().toLowerCase());
  // Only send if the account exists and we didn't just send one (stops email spam)
  // shortcut: sent inline. A real app puts it on a job queue so both paths take the same time.
  if (user && Date.now() - user.lastResetEmailAt > RESEND_COOLDOWN_MS) sendResetEmail(user);

  // ALWAYS the same answer, so this endpoint can't be used to find out who has an account
  res.status(202).json({ message: "If an account exists for that email, we've sent a reset link." });
});

// 2. OPEN THE LINK: show the "choose a new password" form.
// It only LOOKS at the token, it doesn't use it up: email scanners and link previews open links on their own.
app.get("/reset-password", (req, res) => {
  const { token } = req.query;
  const record = isTokenShaped(token) && resetTokens.get(sha256(token));
  if (!record || Date.now() > record.expiresAt) {
    return res.status(400).type("html").send("<h1>This link is invalid or has expired</h1><p>Ask for a new one on the Forgot password page.</p>");
  }
  // token is 64 hex characters (checked above), so it's safe to put in the HTML
  res.type("html").send(`<!doctype html>
<meta charset="utf-8"><title>Choose a new password</title>
<h1>Choose a new password</h1>
<form method="post" action="/reset-password">
  <input type="hidden" name="token" value="${token}">
  <label>New password <input type="password" name="newPassword" minlength="8" maxlength="128" required autocomplete="new-password"></label>
  <button>Save</button>
</form>`);
});

// 3. RESET: the form (or an app) sends the token + the new password
app.post("/reset-password", async (req, res) => {
  const invalid = () => res.status(400).json({ error: "This link is invalid or has expired" });
  const { token, newPassword } = req.body ?? {};
  if (!isTokenShaped(token)) return invalid();
  // Check the password BEFORE using up the token, so a too-short password doesn't waste the link
  if (!isValidPassword(newPassword)) return res.status(400).json({ error: "The new password must be 8-128 characters" });

  const key = sha256(token);
  const record = resetTokens.get(key);
  // Same message for "never existed", "already used" and "expired", so attackers learn nothing
  if (!record) return invalid();
  resetTokens.delete(key); // single use: deleted before the `await` below, so two clicks can't both use it
  if (Date.now() > record.expiresAt) return invalid();

  const user = findUserById(record.userId);
  if (!user) return invalid();

  user.passwordHash = await hashPassword(newPassword);
  user.passwordChangedAt = new Date().toISOString();
  deleteResetTokensOf(user.id); // any other reset link still out there dies too
  deleteSessionsOf(user.id);    // log out EVERY device: the attacker may be logged in with the old password
  sendPasswordChangedNotice(user);

  // We don't log the user in here: they log in with the new password, like everyone else
  res.json({ message: "Password changed. Please log in with your new password." });
});

app.use((req, res) => res.status(404).json({ error: "Not found" }));

// Errors (bad JSON, body too big, bugs) come here. Never send the stack trace to the client.
app.use((err, req, res, next) => {
  if (err.type === "entity.parse.failed") return res.status(400).json({ error: "Body must be valid JSON" });
  if (err.type === "entity.too.large") return res.status(413).json({ error: "Request body too large" });
  console.error(err);
  res.status(500).json({ error: "Something went wrong" });
});

app.listen(PORT, () => console.log(`Forgot / reset password API on ${BASE_URL}`));

// Delete expired tokens every minute so the store doesn't grow forever
setInterval(() => {
  const now = Date.now();
  for (const [key, t] of resetTokens) if (now > t.expiresAt) resetTokens.delete(key);
}, 60_000).unref();
