const express = require("express");
const crypto = require("crypto");
const { promisify } = require("util");

const scryptAsync = promisify(crypto.scrypt);

const PORT = Number(process.env.PORT) || 3000;
// Two copies of the same login API run from this file: the SAFE one follows the OWASP cheat sheets,
// the LEGACY one (on the next port) is the 2015 code Priya inherited, which breaks them.
const APPS = { safe: `http://localhost:${PORT}`, legacy: `http://localhost:${PORT + 1}` };

const IDLE_TIMEOUT_MS = 5 * 60 * 1000;           // [Session Management CS] idle timeout: 2-5 min for a money app (15-30 for low-risk apps)
const ABSOLUTE_TIMEOUT_MS = 8 * 60 * 60 * 1000;  // ...and a hard limit of 8 hours, however active the user is
const MAX_FAILURES = 5;                          // [Authentication CS] 5 wrong passwords...
const FAILURE_WINDOW_MS = 15 * 60 * 1000;        // ...within 15 minutes, then that account waits

// [Authentication CS] block passwords that are already in breach lists.
// shortcut: 12 well-known ones. A real app asks Have I Been Pwned's k-anonymity API (topic 52) or ships a big list.
const BREACHED = new Set(["password", "password1", "password123", "12345678", "123456789", "qwerty123", "iloveyou",
  "11111111", "india@123", "admin@123", "welcome@123", "abcd1234"]);

// ---------- Helpers ----------
const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");
const randomToken = () => crypto.randomBytes(32).toString("base64url");
const str = (v) => (typeof v === "string" ? v : undefined);
const parseCookies = (req) => Object.fromEntries((req.headers.cookie ?? "").split(";").filter((c) => c.includes("="))
  .map((c) => [c.slice(0, c.indexOf("=")).trim(), c.slice(c.indexOf("=") + 1).trim()]));
const isEmail = (e) => e.length <= 254 && /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(e);

// [Password Storage CS] scrypt with OWASP's minimum settings: N=2^17 (128 MiB of memory per hash), r=8, p=1.
// "Memory-hard" means a cracker's GPU can't try billions of guesses per second.
// Stored as one self-describing string (algorithm, settings, salt, hash), so the cost can be raised later.
const SCRYPT = { N: 2 ** 17, r: 8, p: 1, maxmem: 256 * 1024 * 1024 };
async function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const hash = await scryptAsync(password, salt, 64, SCRYPT);
  return `$scrypt$N=${SCRYPT.N},r=${SCRYPT.r},p=${SCRYPT.p}$${salt.toString("base64")}$${hash.toString("base64")}`;
}
async function verifyPassword(password, stored) {
  // shortcut: uses today's SCRYPT settings. A real app reads N,r,p from the string and re-hashes old ones at login.
  const [, , , salt, hash] = stored.split("$");
  const actual = await scryptAsync(password, Buffer.from(salt, "base64"), 64, SCRYPT);
  return crypto.timingSafeEqual(actual, Buffer.from(hash, "base64"));
}
// Unknown emails are checked against this, so they take as long as real ones (topic 51)
const DUMMY_HASH = hashPassword("not-a-real-password");

// ❌ The legacy app's "hashing": unsalted MD5. Same password = same hash, and GPUs try billions per second.
const md5 = (password) => crypto.createHash("md5").update(password).digest("hex");

// ---------- The app (one factory, two personalities) ----------
const dbs = {}; // the auditor peeks in here for its one "white-box" check (how passwords are stored)

function createApp(name) {
  const SAFE = name === "safe";
  const BASE_URL = APPS[name];
  // shortcut: in-memory Maps, lost on restart. A real app uses database tables.
  const db = {
    users: new Map(),       // email -> { email, passwordHash }
    sessions: new Map(),    // SAFE: sha256(sid) -> session · LEGACY: the raw sid (a database leak = every session stolen)
    failures: new Map(),    // email -> { count, firstAt }   (SAFE only)
    resetTokens: new Map(), // sha256(token) -> { email, expiresAt }
  };
  dbs[name] = db;

  // shortcut: a test account with a known password. Signup works too.
  if (SAFE) hashPassword("chai-and-code-42").then((h) => db.users.set("rahul@mail.com", { email: "rahul@mail.com", passwordHash: h }));
  else db.users.set("rahul@mail.com", { email: "rahul@mail.com", passwordHash: md5("chai-and-code-42") });

  // [Session Management CS] a generic cookie name (doesn't say "Express"), HttpOnly, SameSite.
  // shortcut: no Secure flag because the demo runs on http://localhost. In production: secure: true and the __Host- prefix.
  const COOKIE_NAME = SAFE ? "sid" : "connect.sid";
  const COOKIE = SAFE ? { httpOnly: true, sameSite: "lax", path: "/" } : { path: "/" };
  const key = (sid) => (SAFE ? sha256(sid) : sid);
  let legacyCounter = 1000; // ❌ legacy session ids are a counter: sess-1001, sess-1002… guess the next one, be that user

  function newSession(res, email) {
    // [Session Management CS] 256 random bits from a CSPRNG. OWASP's minimum is 64 bits of entropy.
    const sid = SAFE ? randomToken() : `sess-${++legacyCounter}`;
    db.sessions.set(key(sid), { email, createdAt: Date.now(), lastSeen: Date.now() });
    res.cookie(COOKIE_NAME, sid, COOKIE);
  }

  function getSession(req) {
    const sid = parseCookies(req)[COOKIE_NAME];
    const s = sid && db.sessions.get(key(sid));
    if (!s) return null;
    if (SAFE) {
      const now = Date.now();
      if (now - s.lastSeen > IDLE_TIMEOUT_MS || now - s.createdAt > ABSOLUTE_TIMEOUT_MS) {
        db.sessions.delete(key(sid)); // expired on the SERVER, whatever the cookie says
        return null;
      }
      s.lastSeen = now;
    }
    return { sid, s };
  }

  const app = express();

  if (SAFE) {
    app.disable("x-powered-by"); // don't announce "Express" to every scanner
    app.use((req, res, next) => {
      // [HTTP Headers CS] (the API returns JSON only, so the CSP can be "nothing at all")
      res.set({
        "Cache-Control": "no-store", // balances and session responses must not sit in a shared cache
        "X-Content-Type-Options": "nosniff",
        "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
        "Referrer-Policy": "no-referrer",
      });
      // shortcut: add Strict-Transport-Security once the app runs on HTTPS (topic 05)

      // [CSRF Prevention CS] refuse state-changing requests that another site's page made the browser send (topic 47)
      if (req.method !== "GET" && req.method !== "HEAD") {
        const origin = req.get("origin");
        if (req.get("sec-fetch-site") === "cross-site" || (origin && origin !== BASE_URL)) {
          return res.status(403).json({ error: "Cross-site request refused" });
        }
      }
      next();
    });
  }

  app.use(express.json({ limit: "10kb" }));

  // A guest session before login (think: a cart). It's what a session-fixation attacker would plant (topic 50).
  app.get("/", (req, res) => {
    const cur = getSession(req);
    if (!cur) newSession(res, null);
    res.json({ app: `PaisaPay (${name})`, signedInAs: cur?.s.email ?? null });
  });

  app.post("/signup", async (req, res) => {
    const email = str(req.body?.email)?.trim().toLowerCase() ?? "";
    const password = str(req.body?.password) ?? "";
    if (!isEmail(email)) return res.status(400).json({ error: "Enter a valid email" });

    if (!SAFE) {
      // ❌ max 12 characters (long passphrases refused) and "must contain a number" (people write Password1)
      if (password.length < 6 || password.length > 12 || !/\d/.test(password)) {
        return res.status(400).json({ error: "Password must be 6-12 characters and contain a number" });
      }
      if (db.users.has(email)) return res.status(409).json({ error: "Email already registered" }); // ❌ tells anyone who has an account
      db.users.set(email, { email, passwordHash: md5(password) });
      return res.status(201).json({ message: "Account created" });
    }

    // [Authentication CS] length is what matters: at least 8, allow long passphrases, no composition rules.
    // (NIST SP 800-63B-4 asks for 15+ when the password is the ONLY factor.) The upper limit stops 1 MB "passwords".
    if (password.length < 8 || password.length > 128) {
      return res.status(400).json({ error: "Password must be 8 to 128 characters" });
    }
    if (BREACHED.has(password.toLowerCase())) {
      return res.status(400).json({ error: "This password has appeared in a data breach. Please choose another one." });
    }
    // Hash even when the email exists, so both answers take the same time (topic 51)
    const passwordHash = await hashPassword(password);
    if (db.users.has(email)) {
      console.log(`📧 To: ${email}: someone tried to sign up with your email. If it was you, just log in or reset your password.`);
    } else {
      // shortcut: the account works immediately. A real app verifies the email first (topic 12).
      db.users.set(email, { email, passwordHash });
      console.log(`📧 To: ${email}: welcome to PaisaPay!`);
    }
    // [Authentication CS] the same answer for a new and an existing email: no account enumeration
    res.status(202).json({ message: "Thanks! Check your email to continue." });
  });

  app.post("/login", async (req, res) => {
    const email = str(req.body?.email)?.trim().toLowerCase() ?? "";
    const password = str(req.body?.password) ?? "";
    const cur = getSession(req);

    if (!SAFE) {
      const user = db.users.get(email);
      if (!user) return res.status(404).json({ error: "No account for that email" }); // ❌ enumeration
      if (md5(password) !== user.passwordHash) return res.status(401).json({ error: "Wrong password" });
      // ❌ no attempt limit, and the guest session id simply becomes a logged-in one (session fixation)
      if (cur) cur.s.email = email;
      else newSession(res, email);
      return res.json({ message: `Welcome back, ${email}` });
    }

    // [Authentication CS / Credential Stuffing CS] slow down guessing, per account.
    // shortcut: per email only. Real apps also limit per IP and per network, and use a shared store like Redis (topics 16, 52).
    const f = db.failures.get(email);
    if (f && Date.now() - f.firstAt < FAILURE_WINDOW_MS && f.count >= MAX_FAILURES) {
      res.set("Retry-After", String(Math.ceil((f.firstAt + FAILURE_WINDOW_MS - Date.now()) / 1000)));
      return res.status(429).json({ error: "Too many attempts. Try again later or reset your password." });
    }

    const user = db.users.get(email);
    const ok = await verifyPassword(password, user?.passwordHash ?? (await DUMMY_HASH));
    if (!user || !ok) {
      // Unknown emails count too, so a 429 doesn't reveal which accounts exist
      if (!f || Date.now() - f.firstAt >= FAILURE_WINDOW_MS) db.failures.set(email, { count: 1, firstAt: Date.now() });
      else f.count++;
      // [Authentication CS] one generic message for "no such user" and "wrong password"
      return res.status(401).json({ error: "Wrong email or password" });
    }

    db.failures.delete(email);
    // [Session Management CS] a NEW session id at login. A guest id an attacker planted is now worthless (topic 50).
    if (cur) db.sessions.delete(key(cur.sid));
    newSession(res, email);
    res.json({ message: `Welcome back, ${email}` });
  });

  app.get("/me", (req, res) => {
    const cur = getSession(req);
    if (!cur?.s.email) return res.status(401).json({ error: "Not signed in" });
    res.json({ email: cur.s.email, balance: "₹12,500" });
  });

  // Something worth forging: CSRF protection is checked here
  app.post("/transfer", (req, res) => {
    const cur = getSession(req);
    if (!cur?.s.email) return res.status(401).json({ error: "Not signed in" });
    const to = str(req.body?.to)?.trim();
    const amount = req.body?.amount;
    if (!to || !Number.isInteger(amount) || amount < 1 || amount > 100000) {
      return res.status(400).json({ error: "Send { to, amount } with a whole amount from 1 to 100000" });
    }
    console.log(`💸 [${name}] ${cur.s.email} sent ₹${amount} to ${to}`);
    res.json({ message: `Sent ₹${amount} to ${to}` });
  });

  app.post("/logout", (req, res) => {
    const cur = getSession(req);
    // [Session Management CS] ✅ kill the session on the SERVER. ❌ The legacy app only asks the browser
    // to forget the cookie, so a copied cookie keeps working.
    if (SAFE && cur) db.sessions.delete(key(cur.sid));
    res.clearCookie(COOKIE_NAME, COOKIE);
    res.json({ message: "Logged out" });
  });

  app.post("/forgot-password", (req, res) => {
    const email = str(req.body?.email)?.trim().toLowerCase() ?? "";
    const user = db.users.get(email);

    if (!SAFE) {
      if (!user) return res.status(404).json({ error: "No account with that email" }); // ❌ enumeration
      console.log(`📧 To: ${email}: reset your password at ${BASE_URL}/reset-password?email=${email}`); // ❌ no token at all
      return res.json({ message: `Reset link sent to ${email}` });
    }

    // [Forgot Password CS] random single-use token, stored hashed, short expiry, and the SAME answer either way.
    // shortcut: the email is "sent" inline. A real app queues it so both paths take the same time (topic 51).
    if (user) {
      const token = randomToken();
      db.resetTokens.set(sha256(token), { email, expiresAt: Date.now() + 15 * 60 * 1000 });
      console.log(`📧 To: ${email}: reset link ${BASE_URL}/reset-password?token=${token} (15 min, single use; the reset flow is topic 13)`);
    }
    res.status(202).json({ message: "If that email has an account, we've sent a reset link." });
  });

  // The auditor lives on the safe app only
  if (SAFE) app.get("/audit/:target", runAudit);

  app.use((req, res) => res.status(404).json({ error: "Not found" }));

  app.use((err, req, res, next) => {
    // ❌ Legacy: the real error message and stack trace (file paths, library versions) go to the client
    if (!SAFE) return res.status(err.status || 500).json({ error: err.message, stack: err.stack });
    // [Error Handling CS] ✅ a generic message to the client, the details only in our own logs
    if (err.type === "entity.parse.failed") return res.status(400).json({ error: "Body must be valid JSON" });
    if (err.type === "entity.too.large") return res.status(413).json({ error: "Request body too large" });
    console.error(err);
    res.status(500).json({ error: "Something went wrong" });
  });

  setInterval(() => {
    const now = Date.now();
    for (const [k, s] of db.sessions) if (SAFE && (now - s.lastSeen > IDLE_TIMEOUT_MS || now - s.createdAt > ABSOLUTE_TIMEOUT_MS)) db.sessions.delete(k);
    for (const [k, f] of db.failures) if (now - f.firstAt >= FAILURE_WINDOW_MS) db.failures.delete(k);
    for (const [k, t] of db.resetTokens) if (now > t.expiresAt) db.resetTokens.delete(k);
  }, 60_000).unref();

  return app;
}

// ---------- The auditor ----------
// Runs the cheat-sheet checks against one of our two apps over real HTTP, the way a pentester's script would.
async function runAudit(req, res) {
  const target = req.params.target;
  // An allow-list of OUR apps. Never fetch a URL the client chose: that's SSRF.
  if (!Object.hasOwn(APPS, target)) return res.status(404).json({ error: "Target must be safe or legacy" });
  const base = APPS[target];

  const call = async (method, path, { body, cookie, headers = {}, raw } = {}) => {
    const r = await fetch(base + path, {
      method,
      redirect: "manual",
      headers: { ...(body !== undefined || raw ? { "Content-Type": "application/json" } : {}), ...(cookie ? { Cookie: cookie } : {}), ...headers },
      body: raw ?? (body !== undefined ? JSON.stringify(body) : undefined),
    });
    return { status: r.status, text: await r.text(), headers: r.headers, cookies: r.headers.getSetCookie() };
  };
  const show = (r) => `${r.status} ${r.text.length > 70 ? r.text.slice(0, 70) + "…" : r.text}`;
  const same = (a, b) => a.status === b.status && a.text === b.text;
  const randomEmail = () => `audit-${crypto.randomBytes(4).toString("hex")}@example.com`;
  // "sid=abc; Path=/; HttpOnly; SameSite=Lax" -> { name, value, attrs: "Path=/; HttpOnly; SameSite=Lax" }
  const cookieOf = (r) => {
    const raw = r.cookies.find((c) => !/^[^=]+=;/.test(c)); // skip "clear this cookie" headers
    if (!raw) return null;
    const [pair, ...attrs] = raw.split(";").map((p) => p.trim());
    return { name: pair.slice(0, pair.indexOf("=")), value: pair.slice(pair.indexOf("=") + 1), attrs: attrs.join("; ") };
  };

  const results = [];
  const check = (sheet, rule, pass, detail, topic) => results.push({ sheet, rule, pass, detail, topic });

  const email = randomEmail();
  const password = "Tiffin-2026x"; // fits BOTH apps' rules, so each app gets a working account

  // 1. Signup must not reveal who has an account
  const s1 = await call("POST", "/signup", { body: { email, password } });
  const s2 = await call("POST", "/signup", { body: { email, password } });
  check("Authentication", "Signup gives the same answer for a new and an existing email", same(s1, s2),
    `new: ${show(s1)} · again: ${show(s2)}`, "06, 51");

  // 2-4. Password rules: length, long passphrases, breached passwords
  const p1 = await call("POST", "/signup", { body: { email: randomEmail(), password: "short12" } });
  check("Authentication", "Rejects passwords shorter than 8 characters", p1.status === 400, `"short12" → ${show(p1)}`, "06");
  const passphrase = "rahul drinks cutting chai at dadar station every morning at seven";
  const p2 = await call("POST", "/signup", { body: { email: randomEmail(), password: passphrase } });
  check("Authentication", "Accepts a 64+ character passphrase (no 'must contain a number' rule)", p2.status < 300,
    `${passphrase.length}-char passphrase → ${show(p2)}`, "06");
  const p3 = await call("POST", "/signup", { body: { email: randomEmail(), password: "password123" } });
  check("Authentication", "Rejects passwords known from data breaches", p3.status === 400, `"password123" → ${show(p3)}`, "52");

  // 5. White-box: how is the password stored? (A real audit reads the code or a database dump.)
  const stored = dbs[target].users.get(email)?.passwordHash ?? "";
  check("Password Storage", "Hashed with a slow, salted algorithm (Argon2id, scrypt, bcrypt, PBKDF2)",
    /^\$(argon2id|scrypt|2[aby]|pbkdf2)/.test(stored), `stored value: ${stored.slice(0, 42)}${stored.length > 42 ? "…" : ""}`, "04");

  // 6. Login must not reveal who has an account
  const l1 = await call("POST", "/login", { body: { email: randomEmail(), password } });
  const l2 = await call("POST", "/login", { body: { email, password: "Wrong-pass-1" } });
  check("Authentication", "Login gives the same error for unknown email and wrong password", same(l1, l2),
    `unknown: ${show(l1)} · wrong pw: ${show(l2)}`, "07, 51");

  // 7-9. The session cookie
  const guest = cookieOf(await call("GET", "/"));
  const login = await call("POST", "/login", { body: { email, password }, cookie: guest && `${guest.name}=${guest.value}` });
  const c = cookieOf(login) ?? guest; // the legacy app doesn't send a new cookie: it reuses the guest one
  const jar = `${c.name}=${c.value}`;
  const generic = !["connect.sid", "phpsessid", "jsessionid", "asp.net_sessionid"].includes(c.name.toLowerCase());
  check("Session Management", "Session cookie is HttpOnly + SameSite with a generic name",
    /httponly/i.test(c.attrs) && /samesite/i.test(c.attrs) && generic,
    `${c.name}=…; ${c.attrs || "(no flags)"}  (Secure is off on http://localhost; turn it on in production)`, "10");
  check("Session Management", "Session ID is long and random (128+ bits)", c.value.length >= 22 && !/^sess-\d+$/.test(c.value),
    `"${c.value.length > 20 ? c.value.slice(0, 12) + "…" : c.value}" (${c.value.length} chars)`, "09");
  check("Session Management", "Session ID changes at login", login.status === 200 && guest?.value !== c.value,
    `login ${login.status}, before: ${guest?.value.slice(0, 12)}… after: ${c.value.slice(0, 12)}…`, "50");

  // 10-11. Response headers on a private page
  const me = await call("GET", "/me", { cookie: jar });
  const cache = me.headers.get("cache-control");
  check("HTTP Headers", "Private pages send Cache-Control: no-store", /no-store/.test(cache ?? ""),
    `GET /me (${me.status}) → Cache-Control: ${cache ?? "(missing)"}`, "02");
  const nosniff = me.headers.get("x-content-type-options") === "nosniff";
  const noFraming = /frame-ancestors/.test(me.headers.get("content-security-policy") ?? "") || !!me.headers.get("x-frame-options");
  const poweredBy = me.headers.get("x-powered-by");
  check("HTTP Headers", "nosniff + anti-framing headers set, X-Powered-By removed", nosniff && noFraming && !poweredBy,
    `nosniff: ${nosniff ? "yes" : "no"}, framing blocked: ${noFraming ? "yes" : "no"}, X-Powered-By: ${poweredBy ?? "(hidden)"}`, "47, 48");

  // 12. CSRF: a transfer "from" another site, with the victim's cookie attached
  const t = await call("POST", "/transfer", { cookie: jar, body: { to: "vikram@mail.com", amount: 5000 },
    headers: { Origin: "https://evil.example", "Sec-Fetch-Site": "cross-site" } });
  check("CSRF Prevention", "A cross-site POST is refused", t.status === 403, `POST /transfer from evil.example → ${show(t)}`, "47");

  // 13. Logout must kill the session on the server
  await call("POST", "/logout", { cookie: jar });
  const after = await call("GET", "/me", { cookie: jar });
  check("Session Management", "Logout ends the session on the server", after.status === 401,
    `old cookie after logout → ${show(after)}`, "11");

  // 14. Forgot password must not reveal who has an account
  const f1 = await call("POST", "/forgot-password", { body: { email } });
  const f2 = await call("POST", "/forgot-password", { body: { email: randomEmail() } });
  check("Forgot Password", "Same answer for a known and an unknown email", same(f1, f2),
    `known: ${show(f1)} · unknown: ${show(f2)}`, "13");

  // 15. Errors must not leak internals
  const bad = await call("POST", "/login", { raw: '{"email": ' });
  check("Error Handling", "Broken input gets a generic error, no stack trace", !/node_modules|node:internal|\.js:\d+:\d+/.test(bad.text),
    `broken JSON → ${show(bad)}`);

  // 16. Guessing must be slowed down (last, because it locks the test account)
  let tries = 0;
  let last;
  do last = await call("POST", "/login", { body: { email, password: `guess-${++tries}` } });
  while (last.status !== 429 && tries < 10);
  check("Authentication", "Repeated wrong passwords get blocked", last.status === 429,
    `wrong guess #${tries} → ${show(last)}`, "16, 52");

  const passed = results.filter((r) => r.pass).length;
  const lines = [`OWASP cheat sheet audit of the ${target} app (${base})`, `Test account: ${email}`, ""];
  for (const r of results) {
    lines.push(`${r.pass ? "✅ PASS" : "❌ FAIL"}  [${r.sheet}] ${r.rule}`);
    lines.push(`         ${r.detail}${!r.pass && r.topic ? `  → topic ${r.topic}` : ""}`);
  }
  lines.push("", `Score: ${passed}/${results.length}`);
  res.type("text/plain; charset=utf-8").send(lines.join("\n") + "\n");
}

createApp("safe").listen(PORT, () => console.log(`✅ PaisaPay (safe)   on ${APPS.safe}   audit: ${APPS.safe}/audit/safe`));
createApp("legacy").listen(PORT + 1, () => console.log(`❌ PaisaPay (legacy) on ${APPS.legacy}   audit: ${APPS.safe}/audit/legacy`));
