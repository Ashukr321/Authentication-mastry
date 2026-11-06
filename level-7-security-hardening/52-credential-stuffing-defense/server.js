const express = require("express");
const crypto = require("crypto");

const PORT = Number(process.env.PORT) || 3000;
// A mini "Have I Been Pwned" Pwned Passwords API runs from this same file on the next port
const PWNED_PORT = PORT + 1;
const BASE_URL = `http://localhost:${PORT}`;
const PWNED_URL = `http://127.0.0.1:${PWNED_PORT}`;

const SESSION_TTL_MS = 7 * 24 * 60 * 60 * 1000; // 7 days
const DEVICE_TTL_MS = 90 * 24 * 60 * 60 * 1000; // a trusted-device cookie lasts 90 days
const IP_LIMIT = 10;                            // topic 16: 10 failed logins per IP…
const IP_WINDOW_MS = 15 * 60 * 1000;            // …per 15 minutes
const ACCOUNT_LIMIT = 5;                        // topic 16: 5 failures on one account…
const LOCK_MS = 15 * 60 * 1000;                 // …lock it for 15 minutes
// shortcut: a fixed tiny threshold so the demo trips it. A real site compares to its normal baseline
// (for example "3x the usual failures per minute") and watches the success rate too.
const ATTACK_THRESHOLD = 5;                     // failed logins across the WHOLE site…
const ATTACK_WINDOW_MS = 5 * 60 * 1000;         // …within 5 minutes = "we're under attack"
const ATTACK_MODE_MS = 15 * 60 * 1000;          // stay in attack mode for 15 minutes
const POW_PREFIX = "0000";                      // proof of work: about 65,000 hashes on average
const CHALLENGE_TTL_MS = 2 * 60 * 1000;
const CODE_TTL_MS = 10 * 60 * 1000;

// ---------- "Database" ----------
// shortcut: in-memory Maps, lost on restart. A real app uses database tables (and Redis for the counters, topic 16).
const users = new Map();           // email -> { email, name, address, salt, passwordHash }
const sessions = new Map();        // sha256(sid) -> { email, expiresAt }
const devices = new Map();         // sha256(did) -> { email, expiresAt }   the "trusted device" cookie
const ipFailures = new Map();      // ip -> [timestamps of failed logins]
const accountFailures = new Map(); // email -> { count, lockedUntil }
const challenges = new Map();      // challenge -> expiresAt
const pendingLogins = new Map();   // pendingId -> { email, codeHash, expiresAt, attempts, breached }
const recentFailures = [];         // { at, ip, email, knownUser }   site-wide, for the attack detector
let attackModeUntil = 0;

// ---------- Helpers ----------
const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");
const randomToken = () => crypto.randomBytes(32).toString("base64url");
const str = (v) => (typeof v === "string" ? v : undefined);
const hashPassword = (password, salt) => crypto.scryptSync(password, salt, 64);
const parseCookies = (req) => Object.fromEntries((req.headers.cookie ?? "").split(";").filter((c) => c.includes("="))
  .map((c) => [c.slice(0, c.indexOf("=")).trim(), c.slice(c.indexOf("=") + 1).trim()]));
const isAttackMode = () => Date.now() < attackModeUntil;
const DUMMY_SALT = crypto.randomBytes(16);

// shortcut: test accounts. Rahul's account is older than our breach check, and he reused his password on a
// site that got hacked. Priya uses a long, unique passphrase.
for (const [email, password, name, address] of [
  ["rahul@mail.com", "rahul@1995", "Rahul", "Flat 302, Koramangala, Bengaluru"],
  ["priya@mail.com", "masala-dosa-on-sunday-7", "Priya", "B-14, Aundh, Pune"],
]) {
  const salt = crypto.randomBytes(16);
  users.set(email, { email, name, address, salt, passwordHash: hashPassword(password, salt) });
}

// shortcut: no Secure flag because the demo runs on http://localhost. In production add `secure: true` (topic 10).
const COOKIE = { httpOnly: true, sameSite: "lax", path: "/" };

// ---------- DEFENSE 1: breached-password check (k-anonymity) ----------
// We send only the first 5 characters of the SHA-1 hash. The API answers with every hash suffix that starts
// with those 5 characters, and we look for ours locally. The API never learns the password or even its full hash.
async function pwnedCount(password) {
  const hash = crypto.createHash("sha1").update(password).digest("hex").toUpperCase();
  const prefix = hash.slice(0, 5);
  const suffix = hash.slice(5);
  const res = await fetch(`${PWNED_URL}/range/${prefix}`, {
    headers: { "Add-Padding": "true" }, // fake 0-count lines so even the response SIZE doesn't hint at the password
    signal: AbortSignal.timeout(2000),
  });
  if (!res.ok) throw new Error(`Pwned API answered ${res.status}`);
  const lines = (await res.text()).split("\r\n");
  const count = Number(lines.find((l) => l.startsWith(`${suffix}:`))?.split(":")[1] ?? 0);
  console.log(`🔎 Pwned check: sent only "${prefix}", got ${lines.length} suffixes back, breached: ${count > 0 ? `yes (${count})` : "no"}`);
  return count;
}
// shortcut: if the API is down we "fail open" (allow the password) so signups keep working. Log it and alert.
const pwnedCountSafe = (password) => pwnedCount(password).catch((err) => {
  console.warn(`⚠️  Pwned check skipped: ${err.message}`);
  return 0;
});

// ---------- DEFENSE 2: rate limits per IP and per account (topic 16) ----------
// Needed, but NOT enough: a stuffing bot tries each account once, from thousands of IPs.
function ipBlocked(ip) {
  const now = Date.now();
  const recent = (ipFailures.get(ip) ?? []).filter((t) => now - t < IP_WINDOW_MS);
  ipFailures.set(ip, recent);
  return recent.length >= IP_LIMIT;
}
const accountLocked = (email) => (accountFailures.get(email)?.lockedUntil ?? 0) > Date.now();

function recordFailure(ip, email) {
  ipFailures.set(ip, [...(ipFailures.get(ip) ?? []), Date.now()]);
  const a = accountFailures.get(email) ?? { count: 0, lockedUntil: 0 };
  if (++a.count >= ACCOUNT_LIMIT) Object.assign(a, { count: 0, lockedUntil: Date.now() + LOCK_MS });
  accountFailures.set(email, a);
}

// ---------- DEFENSE 3: watch the WHOLE site, not one IP or one account ----------
// Stuffing looks like "many IPs, many different accounts, mostly emails we've never seen, all failing at once".
function pruneRecentFailures() {
  while (recentFailures.length && Date.now() - recentFailures[0].at > ATTACK_WINDOW_MS) recentFailures.shift();
}
function recordSiteFailure(ip, email, knownUser) {
  recentFailures.push({ at: Date.now(), ip, email, knownUser });
  pruneRecentFailures();
  if (!isAttackMode() && recentFailures.length >= ATTACK_THRESHOLD) {
    attackModeUntil = Date.now() + ATTACK_MODE_MS;
    console.log(`🚨 ATTACK MODE ON: ${recentFailures.length} failed logins from ${new Set(recentFailures.map((f) => f.ip)).size} IPs in 5 min. New devices must now solve a challenge.`);
  }
}

// ---------- DEFENSE 4: a challenge for unknown devices while under attack ----------
// Proof of work: costs a human's browser a fraction of a second, but makes every one of a bot's millions of
// guesses cost CPU. shortcut: real sites use a bot-detection service or CAPTCHA (Turnstile, reCAPTCHA) here.
function challengeOk(challenge, solution) {
  if (!challenge || !solution || solution.length > 20) return false;
  const expiresAt = challenges.get(challenge);
  challenges.delete(challenge); // single use: one solved challenge = one login attempt
  return !!expiresAt && Date.now() <= expiresAt && sha256(challenge + solution).startsWith(POW_PREFIX);
}

// ---------- DEFENSE 5: trusted-device cookie ----------
// After a successful login we give the browser a long-lived random cookie. A login that carries it for the SAME
// email skips the challenge and the "new device" check, so real users aren't punished during an attack.
function trustedDevice(req, email) {
  const did = parseCookies(req).did;
  const d = did && devices.get(sha256(did));
  return !!d && d.email === email && Date.now() <= d.expiresAt;
}

function startSession(res, email, trustThisDevice) {
  const sid = randomToken();
  sessions.set(sha256(sid), { email, expiresAt: Date.now() + SESSION_TTL_MS });
  res.cookie("sid", sid, { ...COOKIE, maxAge: SESSION_TTL_MS });
  if (trustThisDevice) {
    const did = randomToken();
    devices.set(sha256(did), { email, expiresAt: Date.now() + DEVICE_TTL_MS });
    res.cookie("did", did, { ...COOKIE, maxAge: DEVICE_TTL_MS });
  }
}

function getSessionEmail(req) {
  const sid = parseCookies(req).sid;
  const s = sid && sessions.get(sha256(sid));
  return s && Date.now() <= s.expiresAt ? s.email : null;
}

// ---------- App ----------
const app = express();
// shortcut: trusts X-Forwarded-For from ANYONE so you can fake "a bot with many IPs" with curl -H.
// Never do this in production: trust only your own proxy (app.set("trust proxy", 1)), see topic 16.
app.set("trust proxy", true);
app.use(express.json({ limit: "10kb" }));
app.use((req, res, next) => {
  res.set("Cache-Control", "no-store");
  next();
});

// Signup: refuse passwords that are already in attackers' lists (NIST SP 800-63B asks for exactly this)
app.post("/signup", async (req, res) => {
  const email = str(req.body?.email)?.trim().toLowerCase();
  const password = str(req.body?.password) ?? "";
  if (!email || email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ error: "Enter a valid email" });
  if (password.length < 8 || password.length > 128) return res.status(400).json({ error: "Password must be 8 to 128 characters" });

  const breaches = await pwnedCountSafe(password);
  if (breaches > 0) {
    return res.status(400).json({ error: `This password has appeared in ${breaches.toLocaleString("en-IN")} data breaches. Attackers try it first. Choose another.` });
  }
  // Same answer whether or not the email exists, so signup can't be used to find accounts (topic 51)
  if (users.has(email)) {
    console.log(`📧 To: ${email}\n   Someone tried to sign up with your email. If it was you, just log in.`);
  } else {
    const salt = crypto.randomBytes(16);
    users.set(email, { email, name: email.split("@")[0], address: null, salt, passwordHash: hashPassword(password, salt) });
  }
  res.status(201).json({ message: "Account created. You can log in now." });
});

// A challenge for /login (used only while the site is under attack)
app.get("/login/challenge", (req, res) => {
  const challenge = crypto.randomBytes(16).toString("hex");
  challenges.set(challenge, Date.now() + CHALLENGE_TTL_MS);
  res.json({ challenge, task: `Find a number n so that sha256(challenge + n) starts with "${POW_PREFIX}"`, expiresIn: CHALLENGE_TTL_MS / 1000 });
});

async function handleLogin(req, res, layered) {
  const ip = req.ip;
  const email = str(req.body?.email)?.trim().toLowerCase() ?? "";
  const password = str(req.body?.password) ?? "";
  if (!email || !password || email.length > 254 || password.length > 128) return res.status(400).json({ error: "Email and password are required" });

  // Step 1 (topic 16): per-IP and per-account limits
  if (ipBlocked(ip) || accountLocked(email)) return res.status(429).json({ error: "Too many attempts. Try again later." });

  // Step 2: under attack? Unknown devices must solve a challenge BEFORE we even look at the password,
  // so the bot learns nothing and we don't spend a slow scrypt hash on every guess.
  const trusted = layered && trustedDevice(req, email);
  if (layered && isAttackMode() && !trusted && !challengeOk(str(req.body?.challenge), str(req.body?.solution))) {
    return res.status(403).json({ error: "Unusual login activity. Get a challenge from /login/challenge, solve it, and try again.", challengeRequired: true });
  }

  // Step 3: check the password. Always hash, even for unknown emails, so timing doesn't reveal accounts (topic 51).
  const user = users.get(email);
  const hash = hashPassword(password, user?.salt ?? DUMMY_SALT);
  if (!user || !crypto.timingSafeEqual(hash, user.passwordHash)) {
    recordFailure(ip, email);
    if (layered) recordSiteFailure(ip, email, !!user);
    return res.status(401).json({ error: "Wrong email or password" });
  }
  accountFailures.delete(email);

  // Step 4: right password from a NEW device. The password alone may be the attacker's copy from a breach.
  // If it's a known-breached password, or we're under attack, the owner must confirm with a code from their email.
  if (layered && !trusted) {
    const breaches = await pwnedCountSafe(password);
    if (breaches > 0 || isAttackMode()) {
      const pendingId = randomToken();
      const code = String(crypto.randomInt(0, 1_000_000)).padStart(6, "0");
      pendingLogins.set(pendingId, { email, codeHash: sha256(code), expiresAt: Date.now() + CODE_TTL_MS, attempts: 0, breached: breaches > 0 });
      console.log(`📧 To: ${email}\n   New sign-in from IP ${ip}. Your code: ${code} (valid 10 minutes).\n   Not you? Someone has your password: change it now.${breaches > 0 ? " It appeared in a data breach." : ""}`);
      return res.status(202).json({ status: "verify_email", message: "New device. We sent a 6-digit code to your email.", pendingId });
    }
  }

  startSession(res, user.email, layered);
  res.json({ message: `Logged in as ${user.email}` });
}

// ✅ The protected login: every layer
app.post("/login", (req, res) => handleLogin(req, res, true));
// ❌ Only topic 16's per-IP and per-account limits. Credential stuffing walks right through them.
app.post("/vulnerable/login", (req, res) => handleLogin(req, res, false));

// Step 5: the email code. Only the real owner reads that inbox.
app.post("/login/verify", (req, res) => {
  const pendingId = str(req.body?.pendingId);
  const code = str(req.body?.code) ?? "";
  const p = pendingId && pendingLogins.get(pendingId);
  if (!p || Date.now() > p.expiresAt) return res.status(400).json({ error: "Code expired. Log in again." });
  if (!crypto.timingSafeEqual(Buffer.from(sha256(code), "hex"), Buffer.from(p.codeHash, "hex"))) {
    if (++p.attempts >= 5) pendingLogins.delete(pendingId); // a 6-digit code can't survive guessing for long
    return res.status(401).json({ error: "Wrong code" });
  }
  pendingLogins.delete(pendingId);
  startSession(res, p.email, true);
  res.json({
    message: `Logged in as ${p.email}. This device is now trusted.`,
    ...(p.breached && { warning: "Your password appeared in a data breach. Change it now (topic 14)." }),
  });
});

app.get("/me", (req, res) => {
  const email = getSessionEmail(req);
  if (!email) return res.status(401).json({ error: "Not signed in" });
  const { name, address } = users.get(email);
  res.json({ email, name, address });
});

// What the security team's dashboard would show. shortcut: no auth here; a real app puts this behind admin login.
app.get("/security/status", (req, res) => {
  pruneRecentFailures();
  const f = recentFailures;
  res.json({
    attackMode: isAttackMode(),
    attackModeUntil: isAttackMode() ? new Date(attackModeUntil).toISOString() : null,
    failedLoginsLast5Min: f.length,
    distinctIps: new Set(f.map((x) => x.ip)).size,
    distinctAccounts: new Set(f.map((x) => x.email)).size,
    unknownEmailShare: `${f.length ? Math.round((100 * f.filter((x) => !x.knownUser).length) / f.length) : 0}%`,
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

app.listen(PORT, () => console.log(`🛒 ChaiKart on ${BASE_URL}`));

// ---------- The mini Pwned Passwords API ----------
// Works like api.pwnedpasswords.com/range/{first 5 chars of SHA-1}. The counts below are made up for the demo.
const BREACHED = {
  "123456": 4_200_000, "password": 2_100_000, "password1": 1_300_000, "qwerty123": 690_000, "iloveyou": 470_000,
  "Password@123": 120_000, "sunshine": 95_000, "welcome@1": 18_000, "dragon2020": 2_400, "priya@123": 1_700, "rahul@1995": 37,
};
const pwnedHashes = Object.entries(BREACHED).map(([p, count]) => [crypto.createHash("sha1").update(p).digest("hex").toUpperCase(), count]);

const pwned = express();
pwned.get("/range/:prefix", (req, res) => {
  const prefix = req.params.prefix.toUpperCase();
  if (!/^[0-9A-F]{5}$/.test(prefix)) return res.status(400).send("The prefix must be 5 hex characters");
  const lines = pwnedHashes.filter(([h]) => h.startsWith(prefix)).map(([h, count]) => `${h.slice(5)}:${count}`);
  // The real API returns about 800 suffixes per prefix. Padding adds fake ones (count 0) so the answer always looks alike.
  if (req.get("add-padding") === "true") {
    for (let i = 0; i < 10; i++) lines.push(`${crypto.randomBytes(18).toString("hex").slice(0, 35).toUpperCase()}:0`);
  }
  console.log(`🌐 Pwned API: someone asked for prefix ${prefix} (that's all it ever sees)`);
  res.type("text/plain").send(lines.sort().join("\r\n"));
});
pwned.use((req, res) => res.status(404).send("Not found"));
// Bind to 127.0.0.1 exactly: if another program already has this port, we crash with EADDRINUSE instead of silently sharing it
pwned.listen(PWNED_PORT, "127.0.0.1", () => console.log(`🌐 Pwned Passwords API (mock) on ${PWNED_URL}/range/{prefix}`));

// Clean up expired entries every minute
setInterval(() => {
  const now = Date.now();
  for (const map of [sessions, devices, pendingLogins]) for (const [k, v] of map) if (now > v.expiresAt) map.delete(k);
  for (const [k, exp] of challenges) if (now > exp) challenges.delete(k);
  for (const [ip, list] of ipFailures) if (!list.some((t) => now - t < IP_WINDOW_MS)) ipFailures.delete(ip);
}, 60_000).unref();
