const express = require("express");
const crypto = require("crypto");
const { promisify } = require("util");

const scrypt = promisify(crypto.scrypt);
const PORT = Number(process.env.PORT) || 3000;
const MFA_TOKEN_TTL_MS = 5 * 60 * 1000;          // time between the password and the second factor
const EMAIL_OTP_TTL_MS = 5 * 60 * 1000;
const EMAIL_COOLDOWN_MS = 60 * 1000;             // one email code per minute per user
const MAX_ATTEMPTS = 5;                          // wrong codes per login (or per step-up) attempt
const MAX_FAILS_PER_HOUR = 10;                   // wrong codes per user per hour, across everything
const TRUSTED_DEVICE_TTL_MS = 30 * 24 * 60 * 60 * 1000; // "remember this device for 30 days"
// How recent the last MFA must be for sensitive actions (set STEP_UP_SECONDS=20 to watch it run out)
const STEP_UP_MAX_AGE_MS = (Number(process.env.STEP_UP_SECONDS) || 5 * 60) * 1000;
const SESSION_TTL_MS = 7 * 24 * 60 * 60 * 1000;
// shortcut: hard-coded secret. A real app loads it from a secret manager (topic 54).
const OTP_SECRET = process.env.OTP_SECRET || "dev-only-otp-secret-change-me";

// =====================================================================================
// PART 1: TOTP, the same code as topic 44 (trimmed: see that topic for the line-by-line explanation)
// =====================================================================================
const BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
function base32Encode(buf) {
  let bits = 0, value = 0, out = "";
  for (const byte of buf) {
    value = (value << 8) | byte; bits += 8;
    while (bits >= 5) { out += BASE32[(value >>> (bits - 5)) & 31]; bits -= 5; }
  }
  return bits > 0 ? out + BASE32[(value << (5 - bits)) & 31] : out;
}
function base32Decode(str) {
  let bits = 0, value = 0;
  const out = [];
  for (const ch of str.toUpperCase().replace(/[\s=-]/g, "")) {
    const idx = BASE32.indexOf(ch);
    if (idx === -1) throw new Error("Invalid base32 character");
    value = (value << 5) | idx; bits += 5;
    if (bits >= 8) { out.push((value >>> (bits - 8)) & 255); bits -= 8; }
  }
  return Buffer.from(out);
}
function hotp(secret, counter) {
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(counter));
  const hmac = crypto.createHmac("sha1", secret).update(msg).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  return String((hmac.readUInt32BE(offset) & 0x7fffffff) % 1_000_000).padStart(6, "0");
}
const timeStep = (ms = Date.now()) => Math.floor(ms / 30_000);
function verifyTotp(secret, code, lastUsedStep) {
  if (typeof code !== "string" || !/^\d{6}$/.test(code)) return null;
  for (let step = timeStep() - 1; step <= timeStep() + 1; step++) {
    if (step > lastUsedStep && crypto.timingSafeEqual(Buffer.from(hotp(secret, step)), Buffer.from(code))) return step;
  }
  return null;
}
if (hotp(Buffer.from("12345678901234567890"), 1) !== "287082") throw new Error("HOTP self-check failed"); // RFC 4226

// Testing helper: `node server.js code <BASE32 SECRET>` prints the current code, like an authenticator app
if (process.argv[2] === "code") {
  console.log(hotp(base32Decode(process.argv[3] ?? ""), timeStep()));
  process.exit(0);
}

// =====================================================================================
// PART 2: The MFA flow: choose a factor, remember this device, step-up for sensitive actions
// =====================================================================================

// ---------- Helpers ----------
const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");
const randomId = () => crypto.randomBytes(32).toString("base64url");
const ID_RE = /^[A-Za-z0-9_-]{43}$/;
const parseCookies = (req) => Object.fromEntries((req.headers.cookie ?? "").split(";").filter((c) => c.includes("="))
  .map((c) => [c.slice(0, c.indexOf("=")).trim(), c.slice(c.indexOf("=") + 1).trim()]));
// shortcut: no Secure flag because the demo runs on http://localhost. In production (HTTPS) add `secure: true` (topic 10).
const COOKIE = { httpOnly: true, sameSite: "lax", path: "/" };
// The trusted-device cookie is only ever needed by the login endpoints, so the browser sends it nowhere else
const DEVICE_COOKIE = { httpOnly: true, sameSite: "lax", path: "/login" };
const hmacCode = (ctxId, code) => crypto.createHmac("sha256", OTP_SECRET).update(`${ctxId}:${code}`).digest(); // topic 43
const normalizeRecovery = (code) => code.toUpperCase().replace(/[\s-]/g, "");

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

// ---------- "Database" ----------
// shortcut: in-memory Maps, lost on restart. A real app uses database tables.
const users = new Map();          // email -> { id, email, passwordHash, mfa: { totpSecret, lastUsedStep, emailOtp, recoveryHashes }, payoutUpi, lastEmailOtpAt }
const mfaTokens = new Map();      // sha256(mfaToken) -> { userId, expiresAt, ctx }
const sessions = new Map();       // sha256(sid) -> { userId, expiresAt, amr, mfaAt, viaTrustedDevice, ctx }
const trustedDevices = new Map(); // sha256(deviceToken) -> { userId, label, createdAt, expiresAt }
const failures = new Map();       // userId -> { count, windowStart }
const findUserById = (id) => [...users.values()].find((u) => u.id === id);

// Demo user, already enrolled in TOTP (topic 44) + email codes + recovery codes
const DEMO_TOTP_SECRET = crypto.randomBytes(20);
const DEMO_RECOVERY_CODES = Array.from({ length: 3 }, () => base32Encode(crypto.randomBytes(10)).match(/.{4}/g).join("-"));
const seeded = hashPassword("correct horse battery").then((passwordHash) => {
  users.set("rahul@mail.com", {
    id: crypto.randomUUID(), email: "rahul@mail.com", passwordHash, payoutUpi: null, lastEmailOtpAt: 0,
    // shortcut: secret kept as a plain Buffer in memory. Topic 44 shows how to encrypt it at rest.
    mfa: { totpSecret: DEMO_TOTP_SECRET, lastUsedStep: -1, emailOtp: true, recoveryHashes: DEMO_RECOVERY_CODES.map((c) => sha256(normalizeRecovery(c))) },
  });
});

// Which second factors this user can use, strongest first (the UI shows them in this order)
function availableMethods(user) {
  return [
    user.mfa.totpSecret && "totp",
    user.mfa.emailOtp && "email_otp",
    user.mfa.recoveryHashes.length > 0 && "recovery_code",
  ].filter(Boolean);
}

// A "context" is one attempt at proving the second factor: for a login (inside an mfaToken) or a step-up (inside a session)
const newCtx = () => ({ id: randomId(), attempts: 0, emailOtp: null });

const failCount = (userId) => {
  const f = failures.get(userId);
  return f && Date.now() - f.windowStart <= 60 * 60 * 1000 ? f.count : 0;
};
function addFailure(userId) {
  const f = failures.get(userId);
  if (!f || Date.now() - f.windowStart > 60 * 60 * 1000) failures.set(userId, { count: 1, windowStart: Date.now() });
  else f.count++;
}

// Sends a 6-digit email code for this context. Returns an error message, or null when sent.
function sendEmailOtp(user, ctx, purpose) {
  if (!user.mfa.emailOtp) return "Email codes are not enabled for this account";
  const wait = EMAIL_COOLDOWN_MS - (Date.now() - user.lastEmailOtpAt);
  if (wait > 0) return `Please wait ${Math.ceil(wait / 1000)} seconds before asking for a new code`;
  const code = crypto.randomInt(0, 1_000_000).toString().padStart(6, "0");
  ctx.emailOtp = { hash: hmacCode(ctx.id, code), expiresAt: Date.now() + EMAIL_OTP_TTL_MS };
  user.lastEmailOtpAt = Date.now();
  // shortcut: "sends" the email by printing it. Note the warning: getting this email means someone knows the password.
  console.log(`\n📧 To: ${user.email}\n   Subject: ${code} is your PrintKaro code (${purpose})\n   Didn't just enter your password? Someone else knows it: change it now.\n`);
  return null;
}

// Checks one second factor. Returns { ok: true, method } or { ok: false, status, body }.
function verifyFactor(user, ctx, { method, code, recoveryCode } = {}) {
  if (!availableMethods(user).includes(method)) {
    return { ok: false, status: 400, body: { error: "Unknown method", methods: availableMethods(user) } };
  }
  if (failCount(user.id) >= MAX_FAILS_PER_HOUR) {
    return { ok: false, status: 429, dead: true, body: { error: "Too many wrong codes. Try again in an hour." } };
  }
  ctx.attempts += 1; // counted BEFORE checking, so parallel guesses can't sneak past the limit

  let ok = false;
  if (method === "totp") {
    const step = verifyTotp(user.mfa.totpSecret, code, user.mfa.lastUsedStep);
    if (step !== null) { ok = true; user.mfa.lastUsedStep = step; } // no replay (topic 44)
  } else if (method === "email_otp") {
    const e = ctx.emailOtp;
    ok = !!e && Date.now() <= e.expiresAt && typeof code === "string" && /^\d{6}$/.test(code) &&
      crypto.timingSafeEqual(hmacCode(ctx.id, code), e.hash);
    if (ok) ctx.emailOtp = null; // single use
  } else if (method === "recovery_code" && typeof recoveryCode === "string") {
    const i = user.mfa.recoveryHashes.indexOf(sha256(normalizeRecovery(recoveryCode)));
    if (i !== -1) { ok = true; user.mfa.recoveryHashes.splice(i, 1); } // single use
  }

  if (ok) { failures.delete(user.id); return { ok: true, method }; }
  addFailure(user.id);
  const attemptsLeft = Math.max(MAX_ATTEMPTS - ctx.attempts, 0);
  return { ok: false, status: 401, dead: attemptsLeft === 0, body: { error: "Wrong code", attemptsLeft } };
}

function startSession(res, user, fields) {
  const sid = randomId(); // always a NEW id after login (no session fixation, topic 50)
  sessions.set(sha256(sid), { userId: user.id, expiresAt: Date.now() + SESSION_TTL_MS, ctx: null, ...fields });
  res.cookie("sid", sid, { ...COOKIE, maxAge: SESSION_TTL_MS });
}

function requireSession(req, res, next) {
  const sid = parseCookies(req).sid;
  const session = sid && sessions.get(sha256(sid));
  const user = session && Date.now() <= session.expiresAt && findUserById(session.userId);
  if (!user) return res.status(401).json({ error: "Not signed in" });
  req.session = session;
  req.user = user;
  next();
}

// 6. STEP-UP: sensitive actions need a RECENT second factor, not just "logged in a week ago"
function requireRecentMfa(req, res, next) {
  if (req.session.mfaAt && Date.now() - req.session.mfaAt <= STEP_UP_MAX_AGE_MS) return next();
  res.status(403).json({
    error: "Please confirm it's you",
    stepUpRequired: true,
    methods: availableMethods(req.user),
    reason: req.session.viaTrustedDevice && !req.session.mfaAt ? "You skipped 2FA on a trusted device" : "Your last 2FA check was too long ago",
  });
}

// ---------- App ----------
const app = express();
app.use(express.json({ limit: "10kb" })); // JSON only: a cross-site HTML form can't post here (login CSRF)
app.use((req, res, next) => { res.set("Cache-Control", "no-store"); next(); });

// 1. PASSWORD (first factor). Then: trusted device → session, otherwise → mfaToken.
app.post("/login", async (req, res) => {
  const { email, password } = req.body ?? {};
  if (typeof email !== "string" || typeof password !== "string" || !email || !password) {
    return res.status(400).json({ error: "Email and password are required" });
  }
  await seeded;
  const user = users.get(email.trim().toLowerCase());
  const ok = await verifyPassword(password, user ? user.passwordHash : await DUMMY_HASH_PROMISE);
  if (!user || !ok) return res.status(401).json({ error: "Invalid email or password" });

  if (availableMethods(user).length === 0) { // no MFA set up: password is enough (a policy could force setup here)
    startSession(res, user, { amr: ["pwd"], mfaAt: null, viaTrustedDevice: false });
    return res.json({ message: "Logged in (password only)" });
  }

  // "Remember this device": the cookie must exist, be unexpired AND belong to THIS user
  const deviceToken = parseCookies(req).td;
  const device = deviceToken && trustedDevices.get(sha256(deviceToken));
  if (device && device.userId === user.id && Date.now() <= device.expiresAt) {
    startSession(res, user, { amr: ["pwd"], mfaAt: null, viaTrustedDevice: true });
    return res.json({ message: "Logged in. Trusted device: 2FA skipped", trustedDevice: device.label });
  }

  // Password OK, but NO session yet: a short ticket that can only be traded (with a second factor) for a session
  const mfaToken = randomId();
  mfaTokens.set(sha256(mfaToken), { userId: user.id, expiresAt: Date.now() + MFA_TOKEN_TTL_MS, ctx: newCtx() });
  res.json({ mfaRequired: true, mfaToken, methods: availableMethods(user) });
});

function findMfaToken(req, res) {
  const { mfaToken } = req.body ?? {};
  const record = typeof mfaToken === "string" && ID_RE.test(mfaToken) && mfaTokens.get(sha256(mfaToken));
  if (!record || Date.now() > record.expiresAt) { res.status(400).json({ error: "Login expired, start again" }); return null; }
  return { key: sha256(mfaToken), record, user: findUserById(record.userId) };
}

// 2. "Email me a code instead": only possible with a valid mfaToken, so nobody can spam a user without the password
app.post("/login/mfa/email", (req, res) => {
  const found = findMfaToken(req, res);
  if (!found) return;
  const error = sendEmailOtp(found.user, found.record.ctx, "sign-in");
  if (error) return res.status(429).json({ error });
  res.status(202).json({ message: "We emailed you a 6-digit code" });
});

// 3. SECOND FACTOR: { mfaToken, method: "totp" | "email_otp" | "recovery_code", code | recoveryCode, rememberDevice }
app.post("/login/mfa", (req, res) => {
  const found = findMfaToken(req, res);
  if (!found) return;
  const { key, record, user } = found;

  const result = verifyFactor(user, record.ctx, req.body);
  if (!result.ok) {
    if (result.dead) mfaTokens.delete(key); // out of tries: back to the password
    return res.status(result.status).json(result.body);
  }
  mfaTokens.delete(key); // single use

  // 4. SESSION: remember HOW the user logged in (amr) and WHEN they last passed MFA (mfaAt)
  startSession(res, user, { amr: ["pwd", result.method], mfaAt: Date.now(), viaTrustedDevice: false });

  // 5. REMEMBER THIS DEVICE (only if asked, and never after a recovery code: the user is probably on a stranger's device or lost their phone)
  let rememberedFor = null;
  if (req.body.rememberDevice === true && result.method !== "recovery_code") {
    const deviceToken = randomId();
    trustedDevices.set(sha256(deviceToken), {
      userId: user.id, label: String(req.get("user-agent") ?? "unknown device").slice(0, 80),
      createdAt: new Date().toISOString(), expiresAt: Date.now() + TRUSTED_DEVICE_TTL_MS,
    });
    res.cookie("td", deviceToken, { ...DEVICE_COOKIE, maxAge: TRUSTED_DEVICE_TTL_MS });
    rememberedFor = "30 days";
  }
  res.json({
    message: "Logged in with 2FA", method: result.method, rememberedFor,
    ...(result.method === "recovery_code" && { recoveryCodesLeft: user.mfa.recoveryHashes.length, tip: "Set up 2FA again on your new phone" }),
  });
});

app.get("/me", requireSession, (req, res) => {
  const s = req.session;
  res.json({
    email: req.user.email,
    amr: s.amr,
    mfaAt: s.mfaAt && new Date(s.mfaAt).toISOString(),
    viaTrustedDevice: s.viaTrustedDevice,
    payoutUpi: req.user.payoutUpi,
  });
});

// A SENSITIVE action: where PrintKaro sends Rahul's money. Logged in is not enough: it needs a recent MFA.
app.post("/account/payout", requireSession, requireRecentMfa, (req, res) => {
  const { upiId } = req.body ?? {};
  if (typeof upiId !== "string" || !/^[\w.-]{2,64}@[a-zA-Z]{2,32}$/.test(upiId)) return res.status(400).json({ error: "A valid UPI ID is required, like rahul@okaxis" });
  req.user.payoutUpi = upiId;
  console.log(`\n📧 To: ${req.user.email}\n   Subject: Your payout UPI ID was changed to ${upiId}\n   Not you? Contact support right away.\n`);
  res.json({ message: "Payout UPI ID saved", upiId });
});

// 7. STEP-UP: prove the second factor again, on the EXISTING session
app.post("/step-up/email", requireSession, (req, res) => {
  req.session.ctx ??= newCtx();
  const error = sendEmailOtp(req.user, req.session.ctx, "confirm a sensitive action");
  if (error) return res.status(429).json({ error });
  res.status(202).json({ message: "We emailed you a 6-digit code" });
});

app.post("/step-up", requireSession, (req, res) => {
  req.session.ctx ??= newCtx();
  const result = verifyFactor(req.user, req.session.ctx, req.body);
  if (!result.ok) {
    if (result.dead) req.session.ctx = null;
    return res.status(result.status).json(result.body);
  }
  req.session.ctx = null;
  req.session.mfaAt = Date.now(); // fresh for the next STEP_UP_MAX_AGE_MS
  if (!req.session.amr.includes(result.method)) req.session.amr.push(result.method);
  res.json({ message: "Confirmed. You can do sensitive actions for the next few minutes.", validForSeconds: STEP_UP_MAX_AGE_MS / 1000 });
});

// 8. TRUSTED DEVICES: see them, and forget them all (also do this on password change, 2FA reset or "log out everywhere")
app.get("/devices", requireSession, (req, res) => {
  const list = [...trustedDevices.values()].filter((d) => d.userId === req.user.id && Date.now() <= d.expiresAt)
    .map(({ label, createdAt, expiresAt }) => ({ label, createdAt, expiresAt: new Date(expiresAt).toISOString() }));
  res.json({ trustedDevices: list });
});

app.post("/devices/revoke-all", requireSession, requireRecentMfa, (req, res) => {
  let removed = 0;
  for (const [k, d] of trustedDevices) if (d.userId === req.user.id) { trustedDevices.delete(k); removed++; }
  res.json({ message: "Every device will need 2FA again at the next login", removed });
});

app.post("/logout", (req, res) => {
  const sid = parseCookies(req).sid;
  if (sid) sessions.delete(sha256(sid));
  res.clearCookie("sid", COOKIE); // the trusted-device cookie stays: logging out doesn't make the laptop untrusted
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

seeded.then(() => app.listen(PORT, () => {
  console.log(`🖨️  PrintKaro MFA flow on http://localhost:${PORT}`);
  console.log(`   Demo user: rahul@mail.com / correct horse battery`);
  // shortcut: printed for the demo only. A real app shows these ONCE to the user at setup (topic 44).
  console.log(`   TOTP secret: ${base32Encode(DEMO_TOTP_SECRET)}  (add it to your authenticator app, or: node server.js code <secret>)`);
  console.log(`   Recovery codes: ${DEMO_RECOVERY_CODES.join("  ")}`);
}));

// Every minute, delete expired tickets, sessions and trusted devices
setInterval(() => {
  const now = Date.now();
  for (const [k, t] of mfaTokens) if (now > t.expiresAt) mfaTokens.delete(k);
  for (const [k, s] of sessions) if (now > s.expiresAt) sessions.delete(k);
  for (const [k, d] of trustedDevices) if (now > d.expiresAt) trustedDevices.delete(k);
}, 60_000).unref();
