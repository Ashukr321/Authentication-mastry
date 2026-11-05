const express = require("express");
const crypto = require("crypto");
const { promisify } = require("util");

const scrypt = promisify(crypto.scrypt);
const SCRYPT_OPTIONS = { N: 2 ** 17, r: 8, p: 1, maxmem: 256 * 1024 * 1024 };

const PORT = Number(process.env.PORT) || 3000;

// Layer 1: per-IP rate limit on /login
const IP_LIMIT = 20;                // login attempts...
const IP_WINDOW_MS = 60 * 1000;     // ...per IP per minute
// Layer 2: per-account lockout
const MAX_FAILURES = 5;                                              // wrong passwords in a row before a lock
const FAILURE_WINDOW_MS = 15 * 60 * 1000;                            // failures older than this are forgotten
const BASE_LOCK_MS = (Number(process.env.LOCK_SECONDS) || 60) * 1000; // first lock: 1 minute (LOCK_SECONDS=5 for the demo)
const MAX_LOCK_MS = 60 * 60 * 1000;                                  // locks double each time, up to 1 hour

// ---------- "Database" ----------
// shortcut: in-memory Maps, lost on restart and NOT shared between servers.
// With 2+ servers, keep these counters in Redis (INCR + EXPIRE) so every server sees the same numbers.
const users = new Map();          // email -> { id, email, passwordHash }
const ipCounters = new Map();     // ip -> { count, resetAt }
const loginFailures = new Map();  // email -> { failures, lastFailureAt, lockedUntil, lockCount }

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

// ---------- Layer 1: a fixed-window rate limiter (reusable for any route) ----------
// shortcut: fixed window lets a burst of 2x through at the window edge. Sliding window or token bucket smooths that.
function rateLimit({ limit, windowMs, keyOf }) {
  return (req, res, next) => {
    const key = keyOf(req);
    const now = Date.now();
    let counter = ipCounters.get(key);
    if (!counter || now >= counter.resetAt) {
      counter = { count: 0, resetAt: now + windowMs };
      ipCounters.set(key, counter);
    }
    counter.count++;

    // Standard headers so well-behaved clients can slow down by themselves
    const secondsLeft = Math.ceil((counter.resetAt - now) / 1000);
    res.set({ "RateLimit-Limit": String(limit), "RateLimit-Remaining": String(Math.max(limit - counter.count, 0)), "RateLimit-Reset": String(secondsLeft) });

    if (counter.count > limit) {
      res.set("Retry-After", String(secondsLeft));
      return res.status(429).json({ error: `Too many requests. Try again in ${secondsLeft} seconds.` });
    }
    next();
  };
}

// req.ip is the address of whoever opened the TCP connection.
// Behind a load balancer, that's the load balancer. Then set app.set("trust proxy", 1) so Express reads
// X-Forwarded-For. But ONLY behind a proxy you control: otherwise attackers send a fake X-Forwarded-For
// and get a "new IP" on every request.
const loginLimiter = rateLimit({ limit: IP_LIMIT, windowMs: IP_WINDOW_MS, keyOf: (req) => `login:${req.ip}` });

// ---------- Layer 2: per-account lockout ----------
// Keyed by the EMAIL TYPED, whether the account exists or not.
// So "nobody@mail.com" gets locked exactly like a real account, and the lock doesn't reveal who has an account.
function lockStatus(email) {
  const entry = loginFailures.get(email);
  if (!entry) return 0;
  return Math.max(entry.lockedUntil - Date.now(), 0); // ms left, 0 = not locked
}

function recordFailure(email, user) {
  const now = Date.now();
  let entry = loginFailures.get(email);
  if (!entry) entry = { failures: 0, lastFailureAt: 0, lockedUntil: 0, lockCount: 0 };
  if (now - entry.lastFailureAt > FAILURE_WINDOW_MS) entry.failures = 0; // old failures don't count
  entry.failures++;
  entry.lastFailureAt = now;

  if (entry.failures >= MAX_FAILURES) {
    // Exponential backoff: 1 min, 2 min, 4 min... up to 1 hour. Never forever: that would let anyone lock out anyone.
    const lockMs = Math.min(BASE_LOCK_MS * 2 ** entry.lockCount, MAX_LOCK_MS);
    entry.lockedUntil = now + lockMs;
    entry.lockCount++;
    entry.failures = 0;
    // Tell the REAL owner (only if the account exists). Never tell the person at the login form anything extra.
    if (user) console.log(`\n📧 To: ${user.email}\n   Subject: Someone is trying to log in to your account\n   ${MAX_FAILURES} wrong passwords. Login is paused for ${lockMs / 1000} seconds. If this wasn't you, consider changing your password.\n`);
  }
  loginFailures.set(email, entry);
}

// ---------- App ----------
const app = express();
app.use(express.json({ limit: "10kb" }));
app.use((req, res, next) => { res.set("Cache-Control", "no-store"); next(); });

// SIGNUP: same as topic 06, kept short (real apps rate-limit this too)
app.post("/signup", async (req, res) => {
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

// LOGIN, protected by both layers
app.post("/login", loginLimiter, async (req, res) => {
  const { email, password } = req.body ?? {};
  if (typeof email !== "string" || typeof password !== "string" || !email || !password) {
    return res.status(400).json({ error: "Email and password are required" });
  }
  const normalizedEmail = email.trim().toLowerCase();

  // 1. Locked? Refuse BEFORE checking the password, even if it's correct.
  //    Otherwise the lock is useless: the attacker could keep guessing and spot the one "success".
  const lockedMs = lockStatus(normalizedEmail);
  if (lockedMs > 0) {
    const seconds = Math.ceil(lockedMs / 1000);
    res.set("Retry-After", String(seconds));
    return res.status(429).json({ error: `Too many failed attempts. Try again in ${seconds} seconds, or reset your password.` });
  }

  // 2. Check the password (dummy hash for unknown emails, so timing doesn't leak who exists: topic 07)
  const user = users.get(normalizedEmail);
  const ok = await verifyPassword(password, user ? user.passwordHash : await DUMMY_HASH_PROMISE);

  // 3. Wrong: count it (maybe lock), same answer as always
  if (!user || !ok) {
    recordFailure(normalizedEmail, user);
    return res.status(401).json({ error: "Invalid email or password" });
  }

  // 4. Right: forget the failures and the backoff
  loginFailures.delete(normalizedEmail);
  res.json({ message: "Logged in", email: user.email });
});

app.use((req, res) => res.status(404).json({ error: "Not found" }));

// Errors (bad JSON, body too big, bugs) come here. Never send the stack trace to the client.
app.use((err, req, res, next) => {
  if (err.type === "entity.parse.failed") return res.status(400).json({ error: "Body must be valid JSON" });
  if (err.type === "entity.too.large") return res.status(413).json({ error: "Request body too large" });
  console.error(err);
  res.status(500).json({ error: "Something went wrong" });
});

app.listen(PORT, () => console.log(`Lockout + rate limiting API on http://localhost:${PORT} (first lock: ${BASE_LOCK_MS / 1000} s)`));

// Forget old counters every minute so memory doesn't grow forever
setInterval(() => {
  const now = Date.now();
  for (const [key, c] of ipCounters) if (now >= c.resetAt) ipCounters.delete(key);
  for (const [email, e] of loginFailures) {
    if (now >= e.lockedUntil && now - e.lastFailureAt > FAILURE_WINDOW_MS) loginFailures.delete(email);
  }
}, 60_000).unref();
