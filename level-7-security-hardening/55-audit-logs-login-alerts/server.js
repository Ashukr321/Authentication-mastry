const express = require("express");
const crypto = require("crypto");

const PORT = Number(process.env.PORT) || 3000;
const BASE_URL = `http://localhost:${PORT}`; // links in emails are built from this, never from the Host header
const SESSION_TTL_MS = 7 * 24 * 60 * 60 * 1000;         // 7 days
const DEVICE_COOKIE_TTL_MS = 365 * 24 * 60 * 60 * 1000; // the "I've seen this browser before" cookie lives a year
const NOT_ME_LINK_TTL_MS = 7 * 24 * 60 * 60 * 1000;     // people read security emails late, so give the link a week
const FAILED_WINDOW_MS = 15 * 60 * 1000;                // count wrong passwords over the last 15 minutes
const FAILED_ALERT_AT = 5;                              // ...and alert the owner at 5
const FAILED_ALERT_COOLDOWN_MS = 60 * 60 * 1000;        // at most one "failed logins" email per hour, or alerts become spam

// ---------- "Database" ----------
// shortcut: in-memory Maps and an array, lost on restart. A real app uses database tables,
// and ships the audit log to separate write-once storage (a SIEM, S3 Object Lock) that the app can't edit.
const users = new Map();        // email -> { email, role, salt, passwordHash, lastLoginAt, devices: Map(deviceKey -> {...}) }
const sessions = new Map();     // sha256(sid) -> { email, deviceKey, expiresAt }
const notMeTokens = new Map();  // sha256(token) -> { email, expiresAt }   the "This wasn't me" link in alert emails
const lastAlertAt = new Map();  // email -> time of the last failed-login alert
const auditLog = [];            // append-only: the app has no code that edits or deletes entries
let nextAuditId = 1;

// ---------- Helpers ----------
const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");
const randomToken = () => crypto.randomBytes(32).toString("base64url");
const str = (v) => (typeof v === "string" ? v : undefined);
const hashPassword = (password, salt) => crypto.scryptSync(password, salt, 64);
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
const parseCookies = (req) => Object.fromEntries((req.headers.cookie ?? "").split(";").filter((c) => c.includes("="))
  .map((c) => [c.slice(0, c.indexOf("=")).trim(), c.slice(c.indexOf("=") + 1).trim()]));

// Headers are attacker-controlled: cap the length so a 5 MB User-Agent can't become a 5 MB log line
const clip = (s, max = 200) => (typeof s === "string" ? s.slice(0, max) : null);

// shortcut: the country comes from a demo header because everything here is localhost.
// A real app looks up req.ip in a GeoIP database (for example MaxMind GeoLite2) and never trusts a client header for this.
const countryOf = (req) => {
  const c = req.get("x-demo-country") ?? "";
  return /^[A-Z]{2}$/.test(c) ? c : "IN";
};

// ---------- Step 1: what goes into an audit entry ----------
// Who did what, to whom, when, from where, and did it work. NEVER the password, token or OTP itself.
const SECRET_FIELDS = /pass|token|secret|otp|code|cookie|authorization/i;
const redact = (details) => Object.fromEntries(Object.entries(details).filter(([key]) => !SECRET_FIELDS.test(key)));

// ---------- Step 3: tamper-evident chain ----------
// Every entry stores the hash of the one before it. Edit or delete an old entry and every later link breaks.
// shortcut: someone who can rewrite the WHOLE array can recompute every hash. Real systems also copy the latest
// hash somewhere the app can't write (another account, a daily email), or sign entries with a key the app server doesn't hold.
const GENESIS = "0".repeat(64);
const chainHash = (prevHash, entry) => sha256(prevHash + JSON.stringify(entry));

function audit(req, event, outcome, { actor = null, target = null, ...details } = {}) {
  const entry = {
    id: nextAuditId++,
    at: new Date().toISOString(),
    event,                       // dotted names you can filter on: login.success, password.changed, audit.view
    outcome,                     // success | failure | denied
    actor,                       // who did it (null if not signed in)
    target,                      // whose account it was about (an admin can act on someone else)
    ip: req?.ip ?? null,
    userAgent: clip(req?.get("user-agent")),
    country: req ? countryOf(req) : null,
    requestId: req?.id ?? null,  // the same id is in the X-Request-Id response header and the app logs: support can link them
    details: redact(details),
  };
  const prevHash = auditLog.at(-1)?.hash ?? GENESIS;
  const record = Object.freeze({ ...entry, prevHash, hash: chainHash(prevHash, entry) });
  auditLog.push(record);
  // shortcut: a real app writes the full entry as one JSON line to stdout or a log shipper. JSON also stops "log injection":
  // a User-Agent containing a newline can't fake a second log line, because JSON.stringify escapes it as \n.
  console.log(`📝 audit #${record.id} ${event} ${outcome}${target ? ` target=${target}` : ""}${actor && actor !== target ? ` actor=${actor}` : ""}`);
  return record;
}

function verifyChain() {
  let prev = GENESIS;
  for (const record of auditLog) {
    const { prevHash, hash, ...entry } = record;
    if (prevHash !== prev) return { ok: false, brokenAt: record.id, problem: "the entry before this one is missing or was changed" };
    if (hash !== chainHash(prevHash, entry)) return { ok: false, brokenAt: record.id, problem: "this entry was changed" };
    prev = hash;
  }
  return { ok: true, entries: auditLog.length, head: prev };
}

// ---------- Step 4: login alerts ----------
// The email goes to the account owner, says what/when/where, and has ONE action: "This wasn't me".
function sendAlert(req, email, subject, lines) {
  const token = randomToken();
  notMeTokens.set(sha256(token), { email, expiresAt: Date.now() + NOT_ME_LINK_TTL_MS }); // store only the hash, like a reset token
  console.log(`📧 To: ${email}\n   Subject: ${subject}\n   ${lines.join("\n   ")}`
    + `\n   Wasn't you? Secure your account: ${BASE_URL}/security/not-me?token=${token}`
    + `\n   (ChaiPay will never ask for your password or OTP by email or phone.)`);
  audit(req, "alert.sent", "success", { target: email, subject });
}

// The audit log is also your detection data: count recent failures straight from it.
// shortcut: filtering the whole array is fine for a demo. A real app queries an indexed table or its SIEM.
function maybeAlertFailedLogins(req, email) {
  const since = Date.now() - FAILED_WINDOW_MS;
  const failures = auditLog.filter((e) => e.event === "login.failure" && e.target === email && Date.parse(e.at) >= since).length;
  if (failures < FAILED_ALERT_AT) return;
  if (Date.now() - (lastAlertAt.get(email) ?? 0) < FAILED_ALERT_COOLDOWN_MS) return; // already told them this hour
  lastAlertAt.set(email, Date.now());
  sendAlert(req, email, "Several failed sign-in attempts on your ChaiPay account", [
    `${failures} wrong passwords in the last 15 minutes. Latest from IP ${req.ip} (${countryOf(req)}).`,
    "Your account is safe as long as nobody knows your password. Turning on 2FA makes it safer.",
  ]);
}

// ---------- Users ----------
const DUMMY_SALT = crypto.randomBytes(16);
// shortcut: test accounts with known passwords. A real app has a signup (topic 06).
for (const [email, password, role] of [["rahul@mail.com", "chai-and-code-42", "user"], ["priya@mail.com", "admin-priya-77", "admin"]]) {
  const salt = crypto.randomBytes(16);
  users.set(email, { email, role, salt, passwordHash: hashPassword(password, salt), lastLoginAt: null, devices: new Map() });
}

// shortcut: no Secure flag because the demo runs on http://localhost. In production add `secure: true` (topic 10).
const COOKIE = { httpOnly: true, sameSite: "lax", path: "/" };

function requireLogin(req, res, next) {
  const sid = parseCookies(req).sid;
  const key = sid && sha256(sid);
  const s = key && sessions.get(key);
  if (!s || Date.now() > s.expiresAt) return res.status(401).json({ error: "Not signed in" });
  req.auth = { sessionKey: key, ...s };
  req.user = users.get(s.email);
  next();
}

// ---------- App ----------
const app = express();
// Behind a load balancer, req.ip is the balancer's address unless you set `app.set("trust proxy", 1)`.
// Get this wrong and every audit entry has the same IP (or an attacker can fake theirs with X-Forwarded-For).
app.use(express.json({ limit: "10kb" }));
app.use(express.urlencoded({ extended: false, limit: "10kb" }));
app.use((req, res, next) => {
  req.id = crypto.randomUUID(); // our own id: never trust a client-sent request id in an audit trail
  res.set("X-Request-Id", req.id);
  res.set("Cache-Control", "no-store");
  next();
});

// ---------- Step 2: log every security event ----------
app.post("/login", (req, res) => {
  const email = str(req.body?.email)?.trim().toLowerCase();
  if (!email || email.length > 254) return res.status(400).json({ error: "Email is required" });
  const user = users.get(email);
  // Hash even for unknown emails so the response time doesn't reveal who has an account (topic 51)
  const hash = hashPassword(str(req.body?.password) ?? "", user?.salt ?? DUMMY_SALT);

  if (!user || !crypto.timingSafeEqual(hash, user.passwordHash)) {
    if (!user) {
      // Don't store what was typed: people paste their password into the email box by mistake.
      // A short hash still lets you see "the same unknown name tried from 300 IPs" (credential stuffing, topic 52).
      audit(req, "login.failure", "failure", { reason: "unknown_user", attemptedHash: sha256(email).slice(0, 12) });
    } else {
      audit(req, "login.failure", "failure", { target: user.email, reason: "wrong_password" });
      maybeAlertFailedLogins(req, user.email);
    }
    return res.status(401).json({ error: "Wrong email or password" }); // same message either way (topic 51)
  }

  // Step 4: is this a device and place we've seen before? The `did` cookie is a random id per browser.
  let did = parseCookies(req).did;
  if (!did || did.length > 100) did = randomToken();
  const deviceKey = sha256(did);
  const country = countryOf(req);
  const known = user.devices.get(deviceKey);
  const knownCountries = new Set([...user.devices.values()].map((d) => d.country));
  const firstLogin = !user.lastLoginAt; // nothing to compare with yet, so no alert on the very first login

  const reasons = [];
  if (!firstLogin && !known) reasons.push("a new device");
  if (!firstLogin && !knownCountries.has(country)) reasons.push(`a new country (${country})`);

  const now = new Date().toISOString();
  user.devices.set(deviceKey, { label: clip(req.get("user-agent"), 60) ?? "Unknown device", country, firstSeen: known?.firstSeen ?? now, lastSeen: now });
  user.lastLoginAt = now;

  const sid = randomToken();
  sessions.set(sha256(sid), { email: user.email, deviceKey, expiresAt: Date.now() + SESSION_TTL_MS });
  res.cookie("did", did, { ...COOKIE, maxAge: DEVICE_COOKIE_TTL_MS });
  res.cookie("sid", sid, { ...COOKIE, maxAge: SESSION_TTL_MS });
  // `device` is a short hash, so you can say "same browser as last week" without logging the cookie itself
  audit(req, "login.success", "success", { actor: user.email, target: user.email, device: deviceKey.slice(0, 8), newDevice: !known, firstLogin });

  if (reasons.length) {
    sendAlert(req, user.email, "New sign-in to your ChaiPay account", [
      `Signed in from ${reasons.join(" and ")}.`,
      `When: ${now}  Device: ${clip(req.get("user-agent"), 60) ?? "unknown"}  Location: ${country} (IP ${req.ip})`,
      "If this was you, you can ignore this email.",
    ]);
  }
  res.json({ message: `Logged in as ${user.email}` });
});

app.post("/logout", requireLogin, (req, res) => {
  sessions.delete(req.auth.sessionKey);
  audit(req, "logout", "success", { actor: req.user.email, target: req.user.email });
  res.clearCookie("sid", COOKIE);
  res.json({ message: "Logged out" });
});

// The user's own security page: "Recent activity" + "Your devices" (Google, GitHub and banks all have one)
const USER_VISIBLE = new Set(["login.success", "login.failure", "logout", "alert.sent", "password.changed", "account.secured"]);
app.get("/me/activity", requireLogin, (req, res) => {
  const email = req.user.email;
  const activity = auditLog.filter((e) => e.target === email && USER_VISIBLE.has(e.event)).slice(-20).reverse()
    .map((e) => ({ at: e.at, event: e.event, outcome: e.outcome, ip: e.ip, country: e.country, device: clip(e.userAgent, 60) }));
  const devices = [...req.user.devices.entries()].map(([key, d]) => ({ ...d, thisDevice: key === req.auth.deviceKey }));
  res.json({ email, devices, activity });
});

// ---------- Step 5: "This wasn't me" ----------
// GET only shows a page. Email scanners and link previews OPEN links automatically, so GET must never change anything.
app.get("/security/not-me", (req, res) => {
  const token = str(req.query.token) ?? "";
  const entry = notMeTokens.get(sha256(token));
  if (!entry || Date.now() > entry.expiresAt) return res.status(400).send("<p>This link is invalid or has expired. Sign in and change your password instead.</p>");
  res.send(`<!doctype html><meta charset="utf-8"><title>Secure your account</title>
<h1>Secure your ChaiPay account</h1>
<p>We'll sign out <b>every</b> device, forget all remembered devices and set your new password.</p>
<form method="post" action="/security/not-me"><input type="hidden" name="token" value="${esc(token)}">
<input type="password" name="newPassword" placeholder="New password (12+ characters)" autocomplete="new-password" required minlength="12">
<button>Secure my account</button></form>`);
});

app.post("/security/not-me", (req, res) => {
  const token = str(req.body?.token) ?? "";
  const newPassword = str(req.body?.newPassword) ?? "";
  const key = sha256(token);
  const entry = notMeTokens.get(key);
  if (!entry || Date.now() > entry.expiresAt) {
    audit(req, "account.secured", "failure", { reason: "invalid_or_expired_link" });
    return res.status(400).json({ error: "This link is invalid or has expired" });
  }
  if (newPassword.length < 12 || newPassword.length > 128) return res.status(400).json({ error: "New password must be 12 to 128 characters" });

  const owner = users.get(entry.email);
  // One click does everything: new password, every session gone (including the attacker's), every device forgotten
  for (const [k, t] of notMeTokens) if (t.email === owner.email) notMeTokens.delete(k); // all of this user's links are now used up
  owner.salt = crypto.randomBytes(16);
  owner.passwordHash = hashPassword(newPassword, owner.salt);
  let sessionsRevoked = 0;
  for (const [k, s] of sessions) if (s.email === owner.email) { sessions.delete(k); sessionsRevoked++; }
  const devicesForgotten = owner.devices.size;
  owner.devices.clear(); // lastLoginAt stays, so the NEXT login from anywhere alerts again

  audit(req, "password.changed", "success", { target: owner.email, via: "not-me link" });
  audit(req, "account.secured", "success", { target: owner.email, sessionsRevoked, devicesForgotten });
  // A "your password was changed" email has NO action link: if this wasn't them either, they contact support
  console.log(`📧 To: ${owner.email}\n   Subject: Your ChaiPay password was changed\n   All ${sessionsRevoked} sessions were signed out. If you didn't do this, contact support.`);
  res.json({ message: "Account secured", sessionsRevoked, devicesForgotten });
});

// ---------- Admin: read the audit log ----------
function requireAdmin(req, res, next) {
  if (req.user.role === "admin") return next();
  audit(req, "audit.view", "denied", { actor: req.user.email }); // a user poking at admin pages is itself worth recording
  res.status(403).json({ error: "Admins only" });
}

app.get("/admin/audit", requireLogin, requireAdmin, (req, res) => {
  const event = str(req.query.event);
  const who = str(req.query.user);
  const outcome = str(req.query.outcome);
  const limit = Math.min(Math.max(Number(req.query.limit) || 20, 1), 100);
  const entries = auditLog.filter((e) => (!event || e.event === event) && (!outcome || e.outcome === outcome)
    && (!who || e.actor === who || e.target === who)).slice(-limit).reverse()
    .map(({ prevHash, hash, ...e }) => ({ ...e, hash: hash.slice(0, 12) }));
  // Who watches the watchers: reading the audit log is audited too (it's full of personal data)
  audit(req, "audit.view", "success", { actor: req.user.email, filters: { event, user: who, outcome } });
  res.json({ count: entries.length, entries });
});

app.get("/admin/audit/verify", requireLogin, requireAdmin, (req, res) => res.json(verifyChain()));

// 🧪 DEMO ONLY: plays an insider with database access who deletes one row to hide their tracks.
// A real app has no such route. That's the point: the attacker goes around the app, and only the hash chain notices.
app.post("/demo/tamper", (req, res) => {
  const index = auditLog.findIndex((e) => e.id === Number(req.body?.id));
  if (index === -1) return res.status(404).json({ error: "No audit entry with that id" });
  const [removed] = auditLog.splice(index, 1);
  res.json({ message: `Deleted audit entry #${removed.id} (${removed.event}) without going through audit()` });
});

app.use((req, res) => res.status(404).json({ error: "Not found" }));

// Errors (bad JSON, body too big, bugs) come here. Never send the stack trace to the client.
app.use((err, req, res, next) => {
  if (err.type === "entity.parse.failed") return res.status(400).json({ error: "Body must be valid JSON" });
  if (err.type === "entity.too.large") return res.status(413).json({ error: "Request body too large" });
  console.error(err);
  res.status(500).json({ error: "Something went wrong" });
});

app.listen(PORT, () => console.log(`☕ ChaiPay on ${BASE_URL}`));

setInterval(() => {
  const now = Date.now();
  for (const [k, s] of sessions) if (now > s.expiresAt) sessions.delete(k);
  for (const [k, t] of notMeTokens) if (now > t.expiresAt) notMeTokens.delete(k);
  // shortcut: the audit log is never trimmed here. A real app keeps it for a fixed period (often 1 year or more,
  // as your compliance rules say), then deletes or archives it, because it is full of personal data (IPs, emails).
}, 60_000).unref();
