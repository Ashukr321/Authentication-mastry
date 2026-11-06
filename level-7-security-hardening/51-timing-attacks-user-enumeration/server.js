const express = require("express");
const crypto = require("crypto");

const PORT = Number(process.env.PORT) || 3000;
const BASE_URL = `http://localhost:${PORT}`;

// ---------- "Database" ----------
// shortcut: in-memory Maps, lost on restart. A real app uses database tables.
const users = new Map();       // email -> { email, salt, passwordHash }
const resetTokens = new Map(); // sha256(token) -> { email, expiresAt }

// ---------- Helpers ----------
const sha256 = (value) => crypto.createHash("sha256").update(value).digest();
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const str = (v) => (typeof v === "string" ? v : undefined);
const normEmail = (v) => str(v)?.trim().toLowerCase();
const validEmail = (e) => !!e && e.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e);
const hashPassword = (password, salt) => crypto.scryptSync(password, salt, 64); // about 50 ms on purpose (topic 04)

// shortcut: a fake SMTP call that takes 300 ms, like a real mail provider. A real app uses a mail service + a job queue.
async function sendEmail(to, subject, text) {
  await sleep(300);
  console.log(`📧 To: ${to}\n   Subject: ${subject}\n   ${text}\n`);
}

// STEP 2: a fake user to hash against when the email doesn't exist, so "no such user" costs the same scrypt work
const DUMMY_SALT = crypto.randomBytes(16);
const DUMMY_HASH = hashPassword("not-a-real-password", DUMMY_SALT);

// shortcut: test accounts with known passwords. A real app has a signup (topic 06).
for (const [email, password] of [["rahul@mail.com", "chai-and-code-42"], ["priya@mail.com", "masala-dosa-77"]]) {
  const salt = crypto.randomBytes(16);
  users.set(email, { email, salt, passwordHash: hashPassword(password, salt) });
}

// STEP 4: a secret the server compares against (think: an admin API key). 6 hex chars so the crack demo is quick.
// shortcut: a real key is 32 random bytes (topic 32). This one is tiny so you can watch the timing attack finish.
const VAULT_KEY = crypto.randomBytes(3).toString("hex");

// ---------- App ----------
const app = express();
app.use(express.json({ limit: "10kb" }));
app.use((req, res, next) => {
  res.set("Cache-Control", "no-store");
  next();
});

app.get("/", (req, res) => res.json({
  app: "ChaiWallet",
  vulnerable: ["POST /vulnerable/login", "POST /vulnerable/signup", "POST /vulnerable/forgot-password", "GET /vulnerable/vault?key="],
  safe: ["POST /login", "POST /signup", "POST /forgot-password", "GET /vault?key="],
}));

// ======================================================================
// ❌ VULNERABLE versions: each one tells an attacker "this email has an account"
// ======================================================================

// Leak 1 (message): two different errors. Leak 2 (timing): unknown emails skip the slow scrypt, so they return in about 1 ms.
app.post("/vulnerable/login", (req, res) => {
  const email = normEmail(req.body?.email);
  const password = str(req.body?.password) ?? "";
  const user = email && users.get(email);
  if (!user) return res.status(404).json({ error: "No account with this email" }); // ❌ fast AND tells you
  if (!crypto.timingSafeEqual(hashPassword(password, user.salt), user.passwordHash)) {
    return res.status(401).json({ error: "Wrong password" }); // ❌ "the email was right, keep guessing the password"
  }
  res.json({ message: `Welcome back, ${user.email}` });
});

// Leak 3: signup says "already registered". Anyone can check a list of emails against your user base.
app.post("/vulnerable/signup", (req, res) => {
  const email = normEmail(req.body?.email);
  const password = str(req.body?.password) ?? "";
  if (!validEmail(email) || password.length < 8) return res.status(400).json({ error: "Valid email and a password of 8+ characters required" });
  if (users.has(email)) return res.status(409).json({ error: "This email is already registered" }); // ❌
  const salt = crypto.randomBytes(16);
  users.set(email, { email, salt, passwordHash: hashPassword(password, salt) });
  res.status(201).json({ message: "Account created" });
});

// Leak 4 (timing only): the MESSAGE was fixed, but the email is sent BEFORE replying, so real users take 300 ms longer
app.post("/vulnerable/forgot-password", async (req, res) => {
  const email = normEmail(req.body?.email);
  if (email && users.has(email)) await sendEmail(email, "Reset your ChaiWallet password", `${BASE_URL}/reset?token=…`); // ❌ awaited
  res.status(202).json({ message: "If an account exists for this email, we've sent a reset link" });
});

// Leak 5: comparing a secret character by character and stopping at the first difference.
// shortcut: the sleep makes each matching character cost 40 ms so you can SEE the leak over HTTP. In real code `===`
// leaks nanoseconds per character, which attackers average out over thousands of requests. Same bug, smaller numbers.
async function leakyEquals(guess, secret) {
  if (guess.length !== secret.length) return false; // ❌ also leaks the LENGTH of the secret
  for (let i = 0; i < secret.length; i++) {
    if (guess[i] !== secret[i]) return false; // ❌ stops early: a better guess takes longer
    await sleep(40);
  }
  return true;
}
app.get("/vulnerable/vault", async (req, res) => {
  const key = str(req.query.key) ?? "";
  if (!(await leakyEquals(key, VAULT_KEY))) return res.status(403).json({ error: "Wrong key" });
  res.json({ message: "🔓 Vault open", balance: "₹12,40,000" });
});

// ======================================================================
// ✅ SAFE versions: same status, same body, about the same time, whether or not the account exists
// ======================================================================

// STEP 1 + 2: one generic message, and the scrypt work always happens
app.post("/login", (req, res) => {
  const email = normEmail(req.body?.email);
  const password = str(req.body?.password) ?? "";
  const user = email ? users.get(email) : undefined;
  // Hash even for unknown emails (against a dummy hash) so both paths cost the same ~50 ms
  const hash = hashPassword(password, user?.salt ?? DUMMY_SALT);
  const ok = crypto.timingSafeEqual(hash, user?.passwordHash ?? DUMMY_HASH) && !!user;
  // shortcut: no rate limit here, to keep the demo short. A real login also has per-IP and per-account limits (topic 16).
  if (!ok) return res.status(401).json({ error: "Wrong email or password" });
  res.json({ message: `Welcome back, ${user.email}` });
});

// STEP 3: signup always gives the same answer. The DIFFERENCE goes to the inbox, which only the owner can read.
app.post("/signup", (req, res) => {
  const email = normEmail(req.body?.email);
  const password = str(req.body?.password) ?? "";
  // Validation errors are fine to show: they're about the input, not about who has an account
  if (!validEmail(email) || password.length < 8) return res.status(400).json({ error: "Valid email and a password of 8+ characters required" });

  const salt = crypto.randomBytes(16);
  const passwordHash = hashPassword(password, salt); // always hash, so both paths take the same time
  if (users.has(email)) {
    // Fire and forget: the reply doesn't wait for the email, so its timing can't leak
    sendEmail(email, "Someone tried to sign up with your email",
      `You already have a ChaiWallet account. Forgot your password? ${BASE_URL}/forgot-password`).catch(console.error);
  } else {
    // shortcut: a real app saves the account as "unverified" and sends a verification link (topic 12)
    users.set(email, { email, salt, passwordHash });
    sendEmail(email, "Welcome to ChaiWallet", "Click the link to verify your email: …").catch(console.error);
  }
  res.status(202).json({ message: "Check your email to finish signing up" });
});

// STEP 3: forgot-password replies BEFORE doing the slow work
app.post("/forgot-password", (req, res) => {
  const email = normEmail(req.body?.email);
  if (email && users.has(email)) {
    const token = crypto.randomBytes(32).toString("base64url");
    resetTokens.set(sha256(token).toString("hex"), { email, expiresAt: Date.now() + 15 * 60 * 1000 }); // topic 13
    // shortcut: setImmediate + no await. A real app pushes a job to a queue (BullMQ, SQS) and a worker sends it.
    setImmediate(() => sendEmail(email, "Reset your ChaiWallet password", `${BASE_URL}/reset?token=${token}`).catch(console.error));
  }
  res.status(202).json({ message: "If an account exists for this email, we've sent a reset link" });
});

// STEP 4: hash both sides (equal length, so length doesn't leak) and compare with timingSafeEqual (no early exit)
app.get("/vault", (req, res) => {
  const key = str(req.query.key) ?? "";
  if (!crypto.timingSafeEqual(sha256(key), sha256(VAULT_KEY))) return res.status(403).json({ error: "Wrong key" });
  res.json({ message: "🔓 Vault open", balance: "₹12,40,000" });
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
  console.log(`☕ ChaiWallet on ${BASE_URL}`);
  console.log(`🤫 Vault key this run: ${VAULT_KEY} (printed only so you can check the timing attack found it)`);
});
