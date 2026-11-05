const express = require("express");
const crypto = require("crypto");

const PORT = Number(process.env.PORT) || 3000;
// Links are built from OUR config, never from the request's Host header (host header injection, topic 12)
const BASE_URL = `http://localhost:${PORT}`;
// How long a magic link works (set MAGIC_TTL_SECONDS=10 to watch a link expire)
const TOKEN_TTL_MS = (Number(process.env.MAGIC_TTL_SECONDS) || 15 * 60) * 1000; // 15 minutes
const EMAIL_COOLDOWN_MS = 60 * 1000;          // at most one link per minute per email (stops inbox flooding)
const IP_LIMIT = 10;                          // at most 10 link requests per IP...
const IP_WINDOW_MS = 15 * 60 * 1000;          // ...per 15 minutes (stops one bot spraying many emails)
const SESSION_TTL_MS = 7 * 24 * 60 * 60 * 1000; // 7 days

// ---------- "Database" ----------
// shortcut: in-memory Maps, lost on restart. A real app uses database tables (and Redis for the rate limits).
const users = new Map();          // email -> { id, email, emailVerified, createdAt, lastLoginAt }
const magicTokens = new Map();    // sha256(token) -> { email, attemptHash, next, expiresAt, requestedFrom }
const sessions = new Map();       // sha256(sid) -> { userId, expiresAt }
const lastEmailSentAt = new Map(); // email -> timestamp
const ipHits = new Map();          // ip -> { count, windowStart }

// ---------- Helpers ----------
// Store only HASHES of tokens and session ids, so a leaked database can't log anyone in.
const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");
const randomToken = () => crypto.randomBytes(32).toString("base64url"); // 256 random bits → 43 characters
const TOKEN_RE = /^[A-Za-z0-9_-]{43}$/;
const str = (v) => (typeof v === "string" ? v : undefined); // query/body values can be arrays or objects: accept strings only
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
const isValidEmail = (email) => typeof email === "string" && email.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim());
const parseCookies = (req) => Object.fromEntries((req.headers.cookie ?? "").split(";").filter((c) => c.includes("="))
  .map((c) => [c.slice(0, c.indexOf("=")).trim(), c.slice(c.indexOf("=") + 1).trim()]));
// Only same-site paths like "/orders". "//evil.com" and "/\evil.com" are other sites (open redirect).
const safeNext = (next) => (typeof next === "string" && /^\/(?![/\\])[^\s\\]*$/.test(next) && next.length <= 200 ? next : "/");

// shortcut: no Secure flag because the demo runs on http://localhost. In production (HTTPS) add `secure: true` (topic 10).
const COOKIE = { httpOnly: true, sameSite: "lax", path: "/" };

function currentUser(req) {
  const sid = parseCookies(req).sid;
  const session = sid && sessions.get(sha256(sid));
  if (!session || Date.now() > session.expiresAt) return null;
  return [...users.values()].find((u) => u.id === session.userId) ?? null;
}

const page = (title, body) => `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>${esc(title)}</title>
<style>body{font-family:system-ui,sans-serif;max-width:480px;margin:48px auto;padding:0 16px;line-height:1.5}
input,button{font:inherit;padding:8px 12px}input{width:100%;box-sizing:border-box;margin:8px 0}
.warn{background:#fef9c3;border:1px solid #ca8a04;padding:8px 12px;border-radius:6px}</style></head>
<body><h1>🖨️ PrintKaro</h1>${body}</body></html>`;

// ---------- App ----------
const app = express();
app.use(express.json({ limit: "10kb" }));                          // for curl / fetch
app.use(express.urlencoded({ extended: false, limit: "10kb" }));   // for the HTML confirm form
app.use((req, res, next) => { res.set("Cache-Control", "no-store"); next(); });

// The home page: a tiny browser UI for the demo
app.get("/", (req, res) => {
  const user = currentUser(req);
  if (user) {
    return res.send(page("PrintKaro", `<p>✅ Signed in as <b>${esc(user.email)}</b></p>
<form method="post" action="/logout"><button>Log out</button></form>`));
  }
  res.send(page("Sign in", `<p>No password needed. We'll email you a sign-in link.</p>
<form id="f"><input type="email" name="email" placeholder="you@mail.com" required autocomplete="email">
<button>Email me a sign-in link</button></form><p id="out"></p>
<script>
document.getElementById("f").onsubmit = async (e) => {
  e.preventDefault();
  const r = await fetch("/auth/magic-link", { method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email: e.target.email.value }) });
  document.getElementById("out").textContent = (await r.json()).message ?? "Too many requests, try later";
};
</script>`));
});

// 1. REQUEST A LINK: the user types their email
app.post("/auth/magic-link", (req, res) => {
  const { email, next } = req.body ?? {};
  if (!isValidEmail(email)) return res.status(400).json({ error: "A valid email is required" });

  // Rate limit per IP first, so one bot can't make us email thousands of people
  const now = Date.now();
  const hit = ipHits.get(req.ip);
  if (!hit || now - hit.windowStart > IP_WINDOW_MS) ipHits.set(req.ip, { count: 1, windowStart: now });
  else if (++hit.count > IP_LIMIT) return res.status(429).json({ error: "Too many requests. Try again later." });

  const normalizedEmail = email.trim().toLowerCase();

  // Bind the link to THIS browser with a random "attempt" cookie. We store only its hash in the token record.
  // Later we can tell "clicked in the same browser" from "clicked somewhere else" (another device, or a planted link).
  let attempt = parseCookies(req).ml_attempt;
  if (!attempt || !TOKEN_RE.test(attempt)) attempt = randomToken();
  res.cookie("ml_attempt", attempt, { ...COOKIE, maxAge: TOKEN_TTL_MS });

  // Cooldown per email: inside it we send nothing, but the reply below is the same
  if (now - (lastEmailSentAt.get(normalizedEmail) ?? 0) > EMAIL_COOLDOWN_MS) {
    // 2. CREATE THE TOKEN: a new link kills every older link for this email
    for (const [key, t] of magicTokens) if (t.email === normalizedEmail) magicTokens.delete(key);
    const token = randomToken();
    magicTokens.set(sha256(token), {
      email: normalizedEmail,
      attemptHash: sha256(attempt),
      next: safeNext(next), // where to go after login is stored on the SERVER, not in the link
      expiresAt: now + TOKEN_TTL_MS,
      requestedFrom: `${req.ip}, ${String(req.get("user-agent") ?? "unknown browser").slice(0, 80)}`,
    });
    lastEmailSentAt.set(normalizedEmail, now);

    // 3. SEND THE EMAIL
    // shortcut: "sends" the email by printing it. A real app queues it for SES / Resend / Postmark.
    // We send to unknown emails too (sign-in OR sign-up), so the reply and timing are the same for everyone.
    const isNew = !users.has(normalizedEmail);
    console.log(`\n📧 To: ${normalizedEmail}\n   Subject: ${isNew ? "Finish creating your PrintKaro account" : "Your PrintKaro sign-in link"}\n   Click: ${BASE_URL}/auth/verify?token=${token}\n   Works once, for ${TOKEN_TTL_MS / 1000} seconds. Requested from: ${magicTokens.get(sha256(token)).requestedFrom}\n   Didn't ask for this? Ignore this email. Nobody can sign in without clicking it.\n`);
  }
  // ALWAYS the same answer, so this endpoint can't be used to find out who has an account
  res.status(202).json({ message: "If that email can sign in, a link is on its way. It works once, for 15 minutes." });
});

// 4. THE CLICK: GET only SHOWS a confirm page. It must NOT log in or use up the token,
// because email security scanners (Outlook Safe Links, antivirus) open every link in an email automatically.
app.get("/auth/verify", (req, res) => {
  // The token is in this page's URL: send only "http://localhost:3000" as Referer, never the path or query.
  // (Not "no-referrer": that makes the browser send `Origin: null` on the form POST, and step 5 would refuse it.)
  res.set("Referrer-Policy", "strict-origin");
  const token = str(req.query.token);
  const record = token && TOKEN_RE.test(token) ? magicTokens.get(sha256(token)) : null;
  if (!record || Date.now() > record.expiresAt) {
    return res.status(400).send(page("Link expired", `<p>❌ This link is invalid or has expired.</p><p><a href="/">Get a new link</a></p>`));
  }
  const sameBrowser = record.attemptHash === sha256(parseCookies(req).ml_attempt ?? "");
  res.send(page("Confirm sign-in", `<p>Sign in to PrintKaro as <b>${esc(record.email)}</b>?</p>
${sameBrowser ? "" : `<p class="warn">⚠️ This link was requested from a different browser or device (${esc(record.requestedFrom)}).
Continue only if <b>you</b> asked for it a moment ago. If someone sent you this link, close this page.</p>`}
<form method="post" action="/auth/verify"><input type="hidden" name="token" value="${esc(token)}">
<button>Sign in as ${esc(record.email)}</button></form>`));
});

// 5. CONFIRM: the button POSTs the token. Now we check it, delete it and log in.
app.post("/auth/verify", (req, res) => {
  // Login CSRF: an attacker's site could auto-submit a form with a link for THEIR account, logging you into it.
  // Browsers always send Origin on a cross-site POST, so a foreign Origin is refused.
  // shortcut: a missing Origin (curl) is allowed so the demo works from the terminal.
  const origin = req.get("origin");
  if (origin && origin !== BASE_URL) return res.status(403).json({ error: "Cross-site request refused" });

  const invalid = () => res.status(400).json({ error: "This link is invalid or has expired" });
  const token = str(req.body?.token);
  if (!token || !TOKEN_RE.test(token)) return invalid();

  const key = sha256(token);
  const record = magicTokens.get(key);
  // Same message for "never existed", "already used" and "expired", so attackers learn nothing
  if (!record) return invalid();
  magicTokens.delete(key); // single use: deleted before anything else (no `await` in between, so no race)
  if (Date.now() > record.expiresAt) return invalid();

  // Clicking the link PROVES the user owns this inbox, so a new user is created already verified
  let user = users.get(record.email);
  if (!user) {
    user = { id: crypto.randomUUID(), email: record.email, emailVerified: true, createdAt: new Date().toISOString(), lastLoginAt: null };
    users.set(user.email, user);
  }
  user.emailVerified = true;
  user.lastLoginAt = new Date().toISOString();
  // Any other link for this email dies too: one login, zero spare links lying in the inbox
  for (const [k, t] of magicTokens) if (t.email === user.email) magicTokens.delete(k);

  // 6. START A SESSION: always a NEW random session id (no session fixation, topic 50), stored as a hash
  const oldSid = parseCookies(req).sid;
  if (oldSid) sessions.delete(sha256(oldSid));
  const sid = randomToken();
  sessions.set(sha256(sid), { userId: user.id, expiresAt: Date.now() + SESSION_TTL_MS });
  res.cookie("sid", sid, { ...COOKIE, maxAge: SESSION_TTL_MS });
  res.clearCookie("ml_attempt", COOKIE);

  // 303 = "now GET this page", so a refresh doesn't re-POST the (already used) token
  res.redirect(303, record.next);
});

// Who am I?
app.get("/me", (req, res) => {
  const user = currentUser(req);
  if (!user) return res.status(401).json({ error: "Not signed in" });
  res.json({ id: user.id, email: user.email, emailVerified: user.emailVerified, createdAt: user.createdAt, lastLoginAt: user.lastLoginAt });
});

app.post("/logout", (req, res) => {
  const sid = parseCookies(req).sid;
  if (sid) sessions.delete(sha256(sid)); // kill it on the server, not just in the browser (topic 11)
  res.clearCookie("sid", COOKIE);
  res.redirect(303, "/");
});

app.use((req, res) => res.status(404).json({ error: "Not found" }));

// Errors (bad JSON, body too big, bugs) come here. Never send the stack trace to the client.
app.use((err, req, res, next) => {
  if (err.type === "entity.parse.failed") return res.status(400).json({ error: "Body must be valid JSON" });
  if (err.type === "entity.too.large") return res.status(413).json({ error: "Request body too large" });
  console.error(err);
  res.status(500).json({ error: "Something went wrong" });
});

app.listen(PORT, () => console.log(`🖨️  PrintKaro magic-link login on ${BASE_URL}  ← open this one`));

// Every minute, delete expired tokens, sessions and rate-limit entries so the Maps don't grow forever
setInterval(() => {
  const now = Date.now();
  for (const [k, t] of magicTokens) if (now > t.expiresAt) magicTokens.delete(k);
  for (const [k, s] of sessions) if (now > s.expiresAt) sessions.delete(k);
  for (const [ip, h] of ipHits) if (now - h.windowStart > IP_WINDOW_MS) ipHits.delete(ip);
  for (const [e, t] of lastEmailSentAt) if (now - t > EMAIL_COOLDOWN_MS) lastEmailSentAt.delete(e);
}, 60_000).unref();
