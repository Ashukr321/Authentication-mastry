const express = require("express");
const crypto = require("crypto");

const PORT = Number(process.env.PORT) || 3000;
const BASE_URL = `http://localhost:${PORT}`;
const SITE_DOMAIN = new URL(BASE_URL).hostname; // goes into the SMS so phones can bind the code to OUR site
// shortcut: a hard-coded secret. A real app loads it from a secret manager (topic 54).
const OTP_SECRET = process.env.OTP_SECRET || "dev-only-otp-secret-change-me";
// How long a code works (set OTP_TTL_SECONDS=10 to watch a code expire)
const CODE_TTL_MS = (Number(process.env.OTP_TTL_SECONDS) || 5 * 60) * 1000; // 5 minutes
const MAX_ATTEMPTS = 5;                          // wrong guesses per code, then the code is dead
const RESEND_COOLDOWN_MS = 60 * 1000;            // one code per minute per email/phone
const MAX_FAILS_PER_HOUR = 10;                   // wrong guesses per email/phone per hour, across ALL its codes
const IP_LIMIT = 10;                             // code requests per IP...
const IP_WINDOW_MS = 15 * 60 * 1000;             // ...per 15 minutes
const SMS_ALLOWED_PREFIXES = ["+91"];            // only send SMS to countries we serve (stops SMS pumping fraud)
const SESSION_TTL_MS = 7 * 24 * 60 * 60 * 1000;

// ---------- "Database" ----------
// shortcut: in-memory Maps, lost on restart. A real app uses database tables (and Redis for the counters).
const users = new Map();       // "email:rahul@mail.com" or "sms:+919876543210" -> { id, channel, destination, createdAt, lastLoginAt }
const challenges = new Map();  // challengeId -> { channel, destination, codeHash, attempts, expiresAt }
const sessions = new Map();    // sha256(sid) -> { userId, expiresAt }
const lastSentAt = new Map();  // destination key -> timestamp
const failures = new Map();    // destination key -> { count, windowStart }
const ipHits = new Map();      // ip -> { count, windowStart }

// ---------- Helpers ----------
const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");
const randomId = () => crypto.randomBytes(32).toString("base64url");
const ID_RE = /^[A-Za-z0-9_-]{43}$/;
const parseCookies = (req) => Object.fromEntries((req.headers.cookie ?? "").split(";").filter((c) => c.includes("="))
  .map((c) => [c.slice(0, c.indexOf("=")).trim(), c.slice(c.indexOf("=") + 1).trim()]));
// shortcut: no Secure flag because the demo runs on http://localhost. In production (HTTPS) add `secure: true` (topic 10).
const COOKIE = { httpOnly: true, sameSite: "lax", path: "/" };

// 6 digits = only 1,000,000 possible codes. A plain sha256 of the code is cracked from a DB leak in milliseconds,
// so we use an HMAC with a server secret, bound to this challenge (the same code in another challenge hashes differently).
const hashCode = (challengeId, code) => crypto.createHmac("sha256", OTP_SECRET).update(`${challengeId}:${code}`).digest();

// Count something in a fixed time window. Returns the new count.
function bump(map, key, windowMs) {
  const now = Date.now();
  const entry = map.get(key);
  if (!entry || now - entry.windowStart > windowMs) { map.set(key, { count: 1, windowStart: now }); return 1; }
  return ++entry.count;
}
const failCount = (key) => {
  const f = failures.get(key);
  return f && Date.now() - f.windowStart <= 60 * 60 * 1000 ? f.count : 0;
};

// Check and normalize the destination. Returns { channel, destination, key } or an error message.
function parseDestination(channel, to) {
  if (typeof to !== "string") return { error: "`to` is required" };
  if (channel === "email") {
    const email = to.trim().toLowerCase();
    if (email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return { error: "A valid email is required" };
    return { channel, destination: email, key: `email:${email}` };
  }
  if (channel === "sms") {
    const phone = to.replace(/[\s()-]/g, ""); // "+91 98765-43210" -> "+919876543210"
    if (!/^\+[1-9]\d{7,14}$/.test(phone)) return { error: "Phone must be in international format, like +919876543210" };
    if (!SMS_ALLOWED_PREFIXES.some((p) => phone.startsWith(p))) return { error: "We can't send SMS to this country" };
    return { channel, destination: phone, key: `sms:${phone}` };
  }
  return { error: '`channel` must be "email" or "sms"' };
}

// shortcut: "sends" by printing. A real app queues it for SES/Resend (email) or Twilio/MSG91 (SMS).
function deliver(channel, destination, code) {
  if (channel === "email") {
    console.log(`\n📧 To: ${destination}\n   Subject: ${code} is your PrintKaro sign-in code\n   Your code is ${code}. It works for ${CODE_TTL_MS / 1000} seconds.\n   PrintKaro will never call you to ask for it. Didn't ask? Ignore this email.\n`);
  } else {
    // The last line is the "origin-bound one-time code" format: phones autofill it only on SITE_DOMAIN
    console.log(`\n📱 SMS to: ${destination}\n   ${code} is your PrintKaro code. Don't share it with anyone, not even PrintKaro staff.\n\n   @${SITE_DOMAIN} #${code}\n`);
  }
}

// ---------- App ----------
const app = express();
// Only JSON bodies are parsed. A cross-site HTML form can't send JSON, and a cross-site fetch with JSON
// needs a CORS preflight we never allow, so another site can't submit codes in your browser (login CSRF).
app.use(express.json({ limit: "10kb" }));
app.use((req, res, next) => { res.set("Cache-Control", "no-store"); next(); });

// 1. REQUEST A CODE: { channel: "email" | "sms", to }
app.post("/auth/otp/request", (req, res) => {
  const { channel, to } = req.body ?? {};
  const dest = parseDestination(channel, to);
  if (dest.error) return res.status(400).json({ error: dest.error });

  // Per IP: one bot can't make us send thousands of emails / SMS (each SMS costs real money)
  if (bump(ipHits, req.ip, IP_WINDOW_MS) > IP_LIMIT) return res.status(429).json({ error: "Too many requests. Try again later." });

  // Too many wrong guesses for this email/phone lately: no new codes for a while
  if (failCount(dest.key) >= MAX_FAILS_PER_HOUR) return res.status(429).json({ error: "Too many wrong codes. Try again in an hour." });

  // Resend cooldown per destination (the "Resend code in 60s" timer in the UI)
  const waitMs = RESEND_COOLDOWN_MS - (Date.now() - (lastSentAt.get(dest.key) ?? 0));
  if (waitMs > 0) {
    res.set("Retry-After", String(Math.ceil(waitMs / 1000)));
    return res.status(429).json({ error: `Please wait ${Math.ceil(waitMs / 1000)} seconds before asking for a new code` });
  }

  // 2. CREATE THE CODE: a new code kills every older code for this destination
  for (const [id, c] of challenges) if (c.destination === dest.destination) challenges.delete(id);
  const code = crypto.randomInt(0, 1_000_000).toString().padStart(6, "0"); // secure random, never Math.random()
  const challengeId = randomId();
  challenges.set(challengeId, { channel: dest.channel, destination: dest.destination, codeHash: hashCode(challengeId, code), attempts: 0, expiresAt: Date.now() + CODE_TTL_MS });
  lastSentAt.set(dest.key, Date.now());

  // 3. SEND IT. We send to new AND existing users (sign-in or sign-up), so this reply says nothing about who has an account.
  deliver(dest.channel, dest.destination, code);
  res.status(202).json({ challengeId, message: `We sent a 6-digit code to ${dest.destination}`, expiresInSeconds: CODE_TTL_MS / 1000 });
});

// 4. VERIFY: { challengeId, code }
app.post("/auth/otp/verify", (req, res) => {
  const { challengeId, code } = req.body ?? {};
  const invalid = (extra = {}) => res.status(400).json({ error: "Wrong or expired code", ...extra });
  if (typeof challengeId !== "string" || !ID_RE.test(challengeId) || typeof code !== "string") return invalid();

  const challenge = challenges.get(challengeId);
  if (!challenge) return invalid();
  const key = `${challenge.channel}:${challenge.destination}`;
  if (Date.now() > challenge.expiresAt) { challenges.delete(challengeId); return invalid(); }
  if (failCount(key) >= MAX_FAILS_PER_HOUR) { challenges.delete(challengeId); return res.status(429).json({ error: "Too many wrong codes. Try again in an hour." }); }

  // Count the attempt BEFORE comparing, so parallel guesses can't sneak past the limit
  challenge.attempts += 1;
  const cleaned = code.replace(/\s/g, ""); // people paste "482 913"
  const ok = /^\d{6}$/.test(cleaned) && crypto.timingSafeEqual(hashCode(challengeId, cleaned), challenge.codeHash);

  if (!ok) {
    bump(failures, key, 60 * 60 * 1000);
    const attemptsLeft = MAX_ATTEMPTS - challenge.attempts;
    if (attemptsLeft <= 0) challenges.delete(challengeId); // 5 wrong guesses: this code is dead, ask for a new one
    return invalid({ attemptsLeft: Math.max(attemptsLeft, 0) });
  }

  // 5. SUCCESS: single use, so delete it first
  challenges.delete(challengeId);
  failures.delete(key);
  // Receiving the code PROVES they own this email/phone, so a new user is created already verified
  let user = users.get(key);
  const isNewUser = !user;
  if (!user) {
    user = { id: crypto.randomUUID(), channel: challenge.channel, destination: challenge.destination, createdAt: new Date().toISOString(), lastLoginAt: null };
    users.set(key, user);
  }
  user.lastLoginAt = new Date().toISOString();

  // 6. START A SESSION: a new random id (no session fixation, topic 50), stored as a hash
  const oldSid = parseCookies(req).sid;
  if (oldSid) sessions.delete(sha256(oldSid));
  const sid = randomId();
  sessions.set(sha256(sid), { userId: user.id, expiresAt: Date.now() + SESSION_TTL_MS });
  res.cookie("sid", sid, { ...COOKIE, maxAge: SESSION_TTL_MS });
  res.json({ message: "Signed in", isNewUser, user: { id: user.id, [user.channel === "email" ? "email" : "phone"]: user.destination } });
});

function currentUser(req) {
  const sid = parseCookies(req).sid;
  const session = sid && sessions.get(sha256(sid));
  if (!session || Date.now() > session.expiresAt) return null;
  return [...users.values()].find((u) => u.id === session.userId) ?? null;
}

app.get("/me", (req, res) => {
  const user = currentUser(req);
  if (!user) return res.status(401).json({ error: "Not signed in" });
  res.json(user);
});

app.post("/logout", (req, res) => {
  const sid = parseCookies(req).sid;
  if (sid) sessions.delete(sha256(sid)); // kill it on the server, not just in the browser (topic 11)
  res.clearCookie("sid", COOKIE);
  res.json({ message: "Logged out" });
});

// A tiny browser UI for the demo
app.get("/", (req, res) => {
  res.type("html").send(`<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>PrintKaro sign-in</title>
<style>body{font-family:system-ui,sans-serif;max-width:420px;margin:48px auto;padding:0 16px;line-height:1.5}
input,select,button{font:inherit;padding:8px 12px;margin:4px 0}input{width:100%;box-sizing:border-box}
#code{letter-spacing:.4em;font-size:1.4em;text-align:center}</style></head><body>
<h1>🖨️ PrintKaro</h1><p id="who"></p>
<form id="ask"><label>Send my code by <select name="channel"><option value="email">Email</option><option value="sms">SMS</option></select></label>
<input name="to" placeholder="rahul@mail.com or +919876543210" required autocomplete="username"><button>Send code</button></form>
<form id="check" hidden><label for="code">Enter the 6-digit code</label>
<input id="code" name="code" inputmode="numeric" autocomplete="one-time-code" maxlength="7" required><button>Verify</button></form>
<p id="out"></p>
<script>
let challengeId;
const out = (t) => (document.getElementById("out").textContent = t);
const post = (url, body) => fetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) })
  .then(async (r) => ({ ok: r.ok, data: await r.json() }));
const me = () => fetch("/me").then((r) => r.json()).then((d) => { document.getElementById("who").textContent = d.id ? "✅ Signed in as " + d.destination : "Not signed in"; });
document.getElementById("ask").onsubmit = async (e) => {
  e.preventDefault();
  const { ok, data } = await post("/auth/otp/request", { channel: e.target.channel.value, to: e.target.to.value });
  out(data.message ?? data.error);
  if (ok) { challengeId = data.challengeId; document.getElementById("check").hidden = false; document.getElementById("code").focus(); }
};
document.getElementById("check").onsubmit = async (e) => {
  e.preventDefault();
  const { data } = await post("/auth/otp/verify", { challengeId, code: e.target.code.value });
  out(data.message ?? data.error + (data.attemptsLeft !== undefined ? " (" + data.attemptsLeft + " tries left)" : ""));
  me();
};
me();
</script></body></html>`);
});

app.use((req, res) => res.status(404).json({ error: "Not found" }));

// Errors (bad JSON, body too big, bugs) come here. Never send the stack trace to the client.
app.use((err, req, res, next) => {
  if (err.type === "entity.parse.failed") return res.status(400).json({ error: "Body must be valid JSON" });
  if (err.type === "entity.too.large") return res.status(413).json({ error: "Request body too large" });
  console.error(err);
  res.status(500).json({ error: "Something went wrong" });
});

app.listen(PORT, () => console.log(`🖨️  PrintKaro OTP login on ${BASE_URL}  ← open this one`));

// Every minute, delete expired codes, sessions and old counters so the Maps don't grow forever
setInterval(() => {
  const now = Date.now();
  for (const [id, c] of challenges) if (now > c.expiresAt) challenges.delete(id);
  for (const [k, s] of sessions) if (now > s.expiresAt) sessions.delete(k);
  for (const [k, t] of lastSentAt) if (now - t > RESEND_COOLDOWN_MS) lastSentAt.delete(k);
  for (const [k, f] of failures) if (now - f.windowStart > 60 * 60 * 1000) failures.delete(k);
  for (const [ip, h] of ipHits) if (now - h.windowStart > IP_WINDOW_MS) ipHits.delete(ip);
}, 60_000).unref();
