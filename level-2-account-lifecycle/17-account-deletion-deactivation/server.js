const express = require("express");
const crypto = require("crypto");
const { promisify } = require("util");

const scrypt = promisify(crypto.scrypt);
const SCRYPT_OPTIONS = { N: 2 ** 17, r: 8, p: 1, maxmem: 256 * 1024 * 1024 };

const PORT = Number(process.env.PORT) || 3000;
const BASE_URL = `http://localhost:${PORT}`;
// Grace period before a deleted account is really erased (set DELETION_GRACE_SECONDS=10 to watch it happen)
const GRACE_MS = (Number(process.env.DELETION_GRACE_SECONDS) || 30 * 24 * 60 * 60) * 1000; // 30 days
const GRACE_TEXT = GRACE_MS >= 86_400_000 ? `${GRACE_MS / 86_400_000} days` : `${GRACE_MS / 1000} seconds`;

// ---------- "Database" ----------
// shortcut: in-memory Maps, lost on restart. A real app uses database tables.
// status is one of: "active" | "deactivated" | "pending_deletion"
const users = new Map();    // email -> { id, email, passwordHash, status, deactivatedAt, deleteAfter }
const sessions = new Map(); // sessionId -> { userId } (from topic 09)
// What we KEEP after erasing someone: only the random id and what happened. No email, no name.
const auditLog = [];        // { event, userId, at }

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

function deleteSessionsOf(userId) {
  for (const [sid, s] of sessions) if (s.userId === userId) sessions.delete(sid);
}

// shortcut: "sends" emails by printing them in the terminal. Use a real email service (SES, Resend, SendGrid) in production.
function sendEmail(to, subject, body) {
  console.log(`\n📧 To: ${to}\n   Subject: ${subject}\n   ${body}\n`);
}

const isValidEmail = (email) => typeof email === "string" && email.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim());
const isValidPassword = (password) => typeof password === "string" && password.length >= 8 && password.length <= 128;
const readSessionId = (req) => /(?:^|;\s*)sid=([a-f0-9]{64})/.exec(req.headers.cookie ?? "")?.[1];

// Only ACTIVE users count as logged in. Sessions are deleted on deactivate/delete anyway,
// but checking the status here too means a forgotten session can never sneak through.
function requireAuth(req, res, next) {
  const session = sessions.get(readSessionId(req));
  const user = session && findUserById(session.userId);
  if (!user || user.status !== "active") return res.status(401).json({ error: "Not logged in" });
  req.user = user;
  next();
}

// Step 1: RE-AUTHENTICATE. A stolen session cookie must not be enough to destroy the account.
// shortcut: no attempt limit here. A real app rate-limits this like login (topic 16).
async function passwordMatches(user, password) {
  return typeof password === "string" && password.length <= 128 && verifyPassword(password, user.passwordHash);
}

// ---------- App ----------
const app = express();
app.use(express.json({ limit: "10kb" }));
app.use((req, res, next) => {
  res.set("Cache-Control", "no-store");
  next();
});

// SIGNUP and LOGIN: same as topics 06, 07 and 09, plus what to do with a deactivated / pending account
app.post("/signup", async (req, res) => {
  const { email, password } = req.body ?? {};
  if (!isValidEmail(email) || !isValidPassword(password)) {
    return res.status(400).json({ error: "A valid email and a password of 8-128 characters are required" });
  }
  const normalizedEmail = email.trim().toLowerCase();
  const passwordHash = await hashPassword(password);
  // A deactivated or pending-deletion account still owns its email, so nobody can take it over
  if (users.has(normalizedEmail)) return res.status(409).json({ error: "Email already registered" });

  const user = { id: crypto.randomUUID(), email: normalizedEmail, passwordHash, status: "active", deactivatedAt: null, deleteAfter: null };
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
  // An erased account simply doesn't exist any more: same reply as a wrong password
  if (!user || !ok) return res.status(401).json({ error: "Invalid email or password" });

  // Step 3 / Step 5: logging in with the right password brings the account back.
  // We only say WHY after the password is checked, so strangers learn nothing about the account.
  let notice;
  if (user.status === "deactivated") {
    notice = "Welcome back! Your account is active again.";
    sendEmail(user.email, "Your account was reactivated", "If this wasn't you, change your password right away.");
  } else if (user.status === "pending_deletion") {
    notice = "Your account deletion was cancelled.";
    sendEmail(user.email, "Your account deletion was cancelled", "If this wasn't you, change your password right away.");
  }
  user.status = "active";
  user.deactivatedAt = null;
  user.deleteAfter = null;

  const sid = crypto.randomBytes(32).toString("hex");
  sessions.set(sid, { userId: user.id });
  res.cookie("sid", sid, { httpOnly: true, sameSite: "lax", path: "/" });
  res.json({ message: "Logged in", email: user.email, ...(notice && { notice }) });
});

app.get("/me", requireAuth, (req, res) => {
  res.json({ id: req.user.id, email: req.user.email, status: req.user.status });
});

// 2. DEACTIVATE: "take a break". Nothing is deleted, the account is just switched off.
app.post("/account/deactivate", requireAuth, async (req, res) => {
  const user = req.user;
  if (!(await passwordMatches(user, req.body?.password))) return res.status(403).json({ error: "Wrong password" });

  user.status = "deactivated";
  user.deactivatedAt = new Date().toISOString();
  deleteSessionsOf(user.id); // log out every device
  res.clearCookie("sid", { path: "/" });
  sendEmail(user.email, "Your account was deactivated", "Log in any time to turn it back on. If this wasn't you, log in and change your password.");
  res.json({ message: "Account deactivated. Log in any time to reactivate it." });
});

// 4. DELETE: "I'm leaving". POST, not DELETE: a body on DELETE has no defined meaning (RFC 9110) and some proxies drop it.
app.post("/account/delete", requireAuth, async (req, res) => {
  const user = req.user;
  const { password, confirm } = req.body ?? {};
  // Typing the words on purpose stops a mis-click (and a sloppy script) from deleting the account
  if (confirm !== "DELETE") return res.status(400).json({ error: 'Type "DELETE" in the confirm field to delete your account' });
  if (!(await passwordMatches(user, password))) return res.status(403).json({ error: "Wrong password" });

  // Soft delete first: the account is switched off now and really erased after the grace period
  user.status = "pending_deletion";
  user.deleteAfter = Date.now() + GRACE_MS;
  deleteSessionsOf(user.id);
  res.clearCookie("sid", { path: "/" });
  auditLog.push({ event: "deletion_requested", userId: user.id, at: new Date().toISOString() });
  sendEmail(user.email, "Your account will be deleted", `It will be erased in ${GRACE_TEXT}. Changed your mind, or wasn't you? Just log in before then to cancel.`);
  res.status(202).json({
    message: `Your account will be permanently deleted in ${GRACE_TEXT}. Log in before then to cancel.`,
    deleteAfter: new Date(user.deleteAfter).toISOString(),
  });
});

app.use((req, res) => res.status(404).json({ error: "Not found" }));

// Errors (bad JSON, body too big, bugs) come here. Never send the stack trace to the client.
app.use((err, req, res, next) => {
  if (err.type === "entity.parse.failed") return res.status(400).json({ error: "Body must be valid JSON" });
  if (err.type === "entity.too.large") return res.status(413).json({ error: "Request body too large" });
  console.error(err);
  res.status(500).json({ error: "Something went wrong" });
});

app.listen(PORT, () => console.log(`Account deletion / deactivation API on ${BASE_URL} (deletion grace period: ${GRACE_TEXT})`));

// 6. PURGE JOB: really erase accounts whose grace period is over.
// shortcut: a setInterval in the web server. A real app runs a scheduled job (cron, a queue worker)
// that also deletes the user's rows in every other table and files in storage.
function purgeExpiredAccounts() {
  const now = Date.now();
  for (const user of users.values()) {
    if (user.status !== "pending_deletion" || now < user.deleteAfter) continue;
    sendEmail(user.email, "Your account has been deleted", "All your personal data has been erased. Goodbye!"); // the last email, sent while we still have the address
    deleteSessionsOf(user.id);
    users.delete(user.email); // the personal data is gone and the email can be used for a new signup
    auditLog.push({ event: "account_erased", userId: user.id, at: new Date().toISOString() }); // no email, no name
    console.log(`🗑️  Erased account ${user.id}. Audit log now has ${auditLog.length} entries (ids only, no personal data).`);
  }
}
setInterval(purgeExpiredAccounts, Math.min(60_000, GRACE_MS)).unref();
