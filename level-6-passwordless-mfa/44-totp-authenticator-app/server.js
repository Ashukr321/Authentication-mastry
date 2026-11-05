const express = require("express");
const crypto = require("crypto");
const assert = require("assert");
const { promisify } = require("util");

const scrypt = promisify(crypto.scrypt);
const PORT = Number(process.env.PORT) || 3000;
const ISSUER = "PrintKaro";                    // the name shown in the authenticator app
const STEP_SECONDS = 30;                       // a new code every 30 seconds (the standard)
const DIGITS = 6;
const WINDOW = 1;                              // also accept the previous and next code (phone clocks drift)
const MFA_TOKEN_TTL_MS = 5 * 60 * 1000;        // time to type the code after the password
const MAX_ATTEMPTS = 5;                        // wrong codes per login attempt
const MAX_FAILS_PER_HOUR = 10;                 // wrong codes per user per hour, across all login attempts
const SESSION_TTL_MS = 7 * 24 * 60 * 60 * 1000;
// The TOTP secret must be READABLE by the server (it computes codes from it), so it can't be hashed.
// It's encrypted at rest instead. shortcut: a dev key from the environment; a real app uses a KMS / secret manager (topic 54).
const ENC_KEY = crypto.createHash("sha256").update(process.env.TOTP_ENC_KEY || "dev-only-totp-key-change-me").digest();

// =====================================================================================
// PART 1: TOTP from scratch (RFC 4226 HOTP + RFC 6238 TOTP). Libraries like otplib do exactly this.
// =====================================================================================
const BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"; // authenticator apps expect the secret in base32

function base32Encode(buf) {
  let bits = 0, value = 0, out = "";
  for (const byte of buf) {
    value = (value << 8) | byte; bits += 8;
    while (bits >= 5) { out += BASE32[(value >>> (bits - 5)) & 31]; bits -= 5; }
  }
  if (bits > 0) out += BASE32[(value << (5 - bits)) & 31];
  return out;
}

function base32Decode(str) {
  const clean = str.toUpperCase().replace(/[\s=-]/g, "");
  let bits = 0, value = 0;
  const out = [];
  for (const ch of clean) {
    const idx = BASE32.indexOf(ch);
    if (idx === -1) throw new Error("Invalid base32 character");
    value = (value << 5) | idx; bits += 5;
    if (bits >= 8) { out.push((value >>> (bits - 8)) & 255); bits -= 8; }
  }
  return Buffer.from(out);
}

// HOTP: HMAC-SHA1(secret, counter) → pick 4 bytes ("dynamic truncation") → last 6 digits
function hotp(secret, counter, digits = DIGITS) {
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(counter));
  const hmac = crypto.createHmac("sha1", secret).update(msg).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;           // the last 4 bits say where to read
  const number = hmac.readUInt32BE(offset) & 0x7fffffff; // 31 bits (drop the sign bit)
  return String(number % 10 ** digits).padStart(digits, "0");
}

// TOTP = HOTP where the counter is "how many 30-second steps since 1970"
const timeStep = (ms = Date.now()) => Math.floor(ms / 1000 / STEP_SECONDS);
const totp = (secret, ms = Date.now()) => hotp(secret, timeStep(ms));

// Returns the matching time step, or null. Refuses steps at or before `lastUsedStep` (no replay).
function verifyTotp(secret, code, lastUsedStep = -1) {
  if (typeof code !== "string" || !/^\d{6}$/.test(code)) return null;
  const now = timeStep();
  for (let step = now - WINDOW; step <= now + WINDOW; step++) {
    if (step <= lastUsedStep) continue; // this code (or an older one) was already used
    if (crypto.timingSafeEqual(Buffer.from(hotp(secret, step)), Buffer.from(code))) return step;
  }
  return null;
}

// Self-check against the official test vectors, so a bug here can never ship silently
assert.strictEqual(hotp(Buffer.from("12345678901234567890"), 0), "755224");          // RFC 4226
assert.strictEqual(hotp(Buffer.from("12345678901234567890"), 1), "287082");          // RFC 4226
assert.strictEqual(hotp(Buffer.from("12345678901234567890"), timeStep(59_000), 8), "94287082"); // RFC 6238
assert.strictEqual(base32Encode(Buffer.from("foobar")), "MZXW6YTBOI");               // RFC 4648
assert.strictEqual(base32Decode("MZXW6YTBOI").toString(), "foobar");

// Testing helper: `node server.js code <BASE32 SECRET>` prints the current code, like the app on your phone would
if (process.argv[2] === "code") {
  const secret = base32Decode(process.argv[3] ?? "");
  console.log(`${totp(secret)}  (changes in ${STEP_SECONDS - (Math.floor(Date.now() / 1000) % STEP_SECONDS)} s)`);
  process.exit(0);
}

// =====================================================================================
// PART 2: PrintKaro with password login + optional TOTP 2FA
// =====================================================================================

// ---------- Helpers ----------
const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");
const randomId = () => crypto.randomBytes(32).toString("base64url");
const ID_RE = /^[A-Za-z0-9_-]{43}$/;
const parseCookies = (req) => Object.fromEntries((req.headers.cookie ?? "").split(";").filter((c) => c.includes("="))
  .map((c) => [c.slice(0, c.indexOf("=")).trim(), c.slice(c.indexOf("=") + 1).trim()]));
// shortcut: no Secure flag because the demo runs on http://localhost. In production (HTTPS) add `secure: true` (topic 10).
const COOKIE = { httpOnly: true, sameSite: "lax", path: "/" };

// AES-256-GCM: encrypts AND detects tampering. A new random IV for every encryption.
function encrypt(plain) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", ENC_KEY, iv);
  const data = Buffer.concat([cipher.update(plain), cipher.final()]);
  return [iv, cipher.getAuthTag(), data].map((b) => b.toString("base64url")).join(".");
}
function decrypt(stored) {
  const [iv, tag, data] = stored.split(".").map((s) => Buffer.from(s, "base64url"));
  const decipher = crypto.createDecipheriv("aes-256-gcm", ENC_KEY, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(data), decipher.final()]);
}

const SCRYPT_OPTIONS = { N: 2 ** 17, r: 8, p: 1, maxmem: 256 * 1024 * 1024 };
async function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  return `${salt.toString("hex")}:${(await scrypt(password, salt, 64, SCRYPT_OPTIONS)).toString("hex")}`;
}
async function verifyPassword(password, stored) {
  const [saltHex, hashHex] = stored.split(":");
  const attempt = await scrypt(password, Buffer.from(saltHex, "hex"), 64, SCRYPT_OPTIONS);
  return crypto.timingSafeEqual(attempt, Buffer.from(hashHex, "hex"));
}
const DUMMY_HASH_PROMISE = hashPassword("dummy-password-never-used");

// Recovery codes: 80 random bits each, shown ONCE, stored as sha256 (random enough that a fast hash is fine)
const newRecoveryCode = () => base32Encode(crypto.randomBytes(10)).match(/.{4}/g).join("-"); // "K7QM-2XRA-9PLD-W4EN"
const normalizeRecovery = (code) => code.toUpperCase().replace(/[\s-]/g, "");

// ---------- "Database" ----------
// shortcut: in-memory Maps, lost on restart. A real app uses database tables.
const users = new Map();        // email -> { id, email, passwordHash, totp: { secretEnc, enabled, lastUsedStep } | null, recoveryHashes: [] }
const mfaTokens = new Map();    // sha256(mfaToken) -> { userId, expiresAt, attempts }
const sessions = new Map();     // sha256(sid) -> { userId, expiresAt }
const failures = new Map();     // userId -> { count, windowStart }
const findUserById = (id) => [...users.values()].find((u) => u.id === id);

// Demo user (signup is topic 06): rahul@mail.com / correct horse battery
hashPassword("correct horse battery").then((passwordHash) => {
  users.set("rahul@mail.com", { id: crypto.randomUUID(), email: "rahul@mail.com", passwordHash, totp: null, recoveryHashes: [] });
});

function startSession(res, user) {
  const sid = randomId();
  sessions.set(sha256(sid), { userId: user.id, expiresAt: Date.now() + SESSION_TTL_MS });
  res.cookie("sid", sid, { ...COOKIE, maxAge: SESSION_TTL_MS });
}
function requireSession(req, res, next) {
  const sid = parseCookies(req).sid;
  const session = sid && sessions.get(sha256(sid));
  const user = session && Date.now() <= session.expiresAt && findUserById(session.userId);
  if (!user) return res.status(401).json({ error: "Not signed in" });
  req.user = user;
  next();
}
const failCount = (userId) => {
  const f = failures.get(userId);
  return f && Date.now() - f.windowStart <= 60 * 60 * 1000 ? f.count : 0;
};
function addFailure(userId) {
  const f = failures.get(userId);
  if (!f || Date.now() - f.windowStart > 60 * 60 * 1000) failures.set(userId, { count: 1, windowStart: Date.now() });
  else f.count++;
}

// Checks a TOTP code OR a recovery code for this user. Recovery codes are deleted when used.
function checkSecondFactor(user, { code, recoveryCode }) {
  if (typeof recoveryCode === "string") {
    const i = user.recoveryHashes.indexOf(sha256(normalizeRecovery(recoveryCode)));
    if (i === -1) return null;
    user.recoveryHashes.splice(i, 1); // single use
    return "recovery_code";
  }
  const step = verifyTotp(decrypt(user.totp.secretEnc), code, user.totp.lastUsedStep);
  if (step === null) return null;
  user.totp.lastUsedStep = step; // this code can never be used again (stops a shoulder-surfer or phisher replaying it)
  return "totp";
}

// ---------- App ----------
const app = express();
app.use(express.json({ limit: "10kb" }));
app.use((req, res, next) => { res.set("Cache-Control", "no-store"); next(); });

// 1. LOGIN, step one: the password (same checks as topic 07, kept short)
app.post("/login", async (req, res) => {
  const { email, password } = req.body ?? {};
  if (typeof email !== "string" || typeof password !== "string" || !email || !password) {
    return res.status(400).json({ error: "Email and password are required" });
  }
  const user = users.get(email.trim().toLowerCase());
  const ok = await verifyPassword(password, user ? user.passwordHash : await DUMMY_HASH_PROMISE);
  if (!user || !ok) return res.status(401).json({ error: "Invalid email or password" });

  if (!user.totp?.enabled) {
    startSession(res, user);
    return res.json({ message: "Logged in (no 2FA yet: turn it on with POST /2fa/setup)" });
  }
  // Password is right, but NO session yet. Only a short-lived ticket that is good for one thing: the code.
  const mfaToken = randomId();
  mfaTokens.set(sha256(mfaToken), { userId: user.id, expiresAt: Date.now() + MFA_TOKEN_TTL_MS, attempts: 0 });
  res.json({ mfaRequired: true, mfaToken, methods: ["totp", "recovery_code"], message: "Enter the 6-digit code from your authenticator app" });
});

// 2. LOGIN, step two: the code from the app (or a recovery code)
app.post("/login/2fa", (req, res) => {
  const { mfaToken } = req.body ?? {};
  if (typeof mfaToken !== "string" || !ID_RE.test(mfaToken)) return res.status(400).json({ error: "Login expired, start again" });
  const key = sha256(mfaToken);
  const pending = mfaTokens.get(key);
  if (!pending || Date.now() > pending.expiresAt) { mfaTokens.delete(key); return res.status(400).json({ error: "Login expired, start again" }); }
  const user = findUserById(pending.userId);
  if (failCount(user.id) >= MAX_FAILS_PER_HOUR) {
    mfaTokens.delete(key);
    return res.status(429).json({ error: "Too many wrong codes. Try again in an hour." });
  }

  pending.attempts += 1; // counted BEFORE checking
  const method = checkSecondFactor(user, req.body);
  if (!method) {
    addFailure(user.id);
    const attemptsLeft = MAX_ATTEMPTS - pending.attempts;
    if (attemptsLeft <= 0) mfaTokens.delete(key); // back to the password step
    return res.status(401).json({ error: "Wrong code", attemptsLeft: Math.max(attemptsLeft, 0) });
  }

  mfaTokens.delete(key); // single use
  failures.delete(user.id);
  startSession(res, user);
  res.json({
    message: "Logged in with 2FA",
    method,
    ...(method === "recovery_code" && { recoveryCodesLeft: user.recoveryHashes.length }),
  });
});

// 3. SETUP: make a secret and show it to the user (QR code / setup key). 2FA is NOT on yet.
app.post("/2fa/setup", requireSession, (req, res) => {
  if (req.user.totp?.enabled) return res.status(409).json({ error: "2FA is already on" });
  const secret = crypto.randomBytes(20); // 160 bits, the size RFC 4226 recommends for SHA-1
  const secretBase32 = base32Encode(secret);
  req.user.totp = { secretEnc: encrypt(secret), enabled: false, lastUsedStep: -1 };

  const label = `${encodeURIComponent(ISSUER)}:${encodeURIComponent(req.user.email)}`;
  const otpauthUrl = `otpauth://totp/${label}?secret=${secretBase32}&issuer=${encodeURIComponent(ISSUER)}&algorithm=SHA1&digits=${DIGITS}&period=${STEP_SECONDS}`;
  // A real app turns otpauthUrl into a QR code IN THE SERVER or browser (never with an online QR website: that leaks the secret)
  res.json({ secret: secretBase32, otpauthUrl, message: "Add this to your authenticator app, then send a code to POST /2fa/enable" });
});

// 4. ENABLE: the first code proves the app was set up correctly. Only now is 2FA switched on.
app.post("/2fa/enable", requireSession, (req, res) => {
  const t = req.user.totp;
  if (!t) return res.status(400).json({ error: "Call POST /2fa/setup first" });
  if (t.enabled) return res.status(409).json({ error: "2FA is already on" });
  const step = verifyTotp(decrypt(t.secretEnc), req.body?.code, t.lastUsedStep);
  if (step === null) return res.status(400).json({ error: "Wrong code. Check the time on your phone and try again." });

  t.enabled = true;
  t.lastUsedStep = step;
  const recoveryCodes = Array.from({ length: 10 }, newRecoveryCode);
  req.user.recoveryHashes = recoveryCodes.map((c) => sha256(normalizeRecovery(c)));
  // shortcut: a real app also emails "2FA was turned on" and logs out the user's OTHER sessions
  res.json({ message: "2FA is on. Save these recovery codes somewhere safe: each works once, and we can't show them again.", recoveryCodes });
});

// 5. DISABLE: needs a current code, so someone at an unlocked laptop can't just switch it off
app.post("/2fa/disable", requireSession, (req, res) => {
  if (!req.user.totp?.enabled) return res.status(400).json({ error: "2FA is not on" });
  if (failCount(req.user.id) >= MAX_FAILS_PER_HOUR) return res.status(429).json({ error: "Too many wrong codes. Try again in an hour." });
  if (!checkSecondFactor(req.user, req.body ?? {})) { addFailure(req.user.id); return res.status(401).json({ error: "Wrong code" }); }
  req.user.totp = null;
  req.user.recoveryHashes = [];
  res.json({ message: "2FA is off" });
});

app.get("/me", requireSession, (req, res) => {
  res.json({ id: req.user.id, email: req.user.email, twoFactorEnabled: !!req.user.totp?.enabled, recoveryCodesLeft: req.user.recoveryHashes.length });
});

app.post("/logout", (req, res) => {
  const sid = parseCookies(req).sid;
  if (sid) sessions.delete(sha256(sid));
  res.clearCookie("sid", COOKIE);
  res.json({ message: "Logged out" });
});

app.use((req, res) => res.status(404).json({ error: "Not found" }));

// Errors (bad JSON, body too big, bugs) come here. Never send the stack trace to the client.
app.use((err, req, res, next) => {
  if (err.type === "entity.parse.failed") return res.status(400).json({ error: "Body must be valid JSON" });
  if (err.type === "entity.too.large") return res.status(413).json({ error: "Request body too large" });
  console.error(err);
  res.status(500).json({ error: "Something went wrong" });
});

app.listen(PORT, () => console.log(`🖨️  PrintKaro TOTP 2FA on http://localhost:${PORT}  (login: rahul@mail.com / correct horse battery)`));

// Every minute, delete expired login tickets and sessions
setInterval(() => {
  const now = Date.now();
  for (const [k, t] of mfaTokens) if (now > t.expiresAt) mfaTokens.delete(k);
  for (const [k, s] of sessions) if (now > s.expiresAt) sessions.delete(k);
}, 60_000).unref();
