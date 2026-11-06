const express = require("express");
const crypto = require("crypto");

const PORT = Number(process.env.PORT) || 3000;
// The attacker's site runs from this same file on the next port, so you can attack yourself in the browser
const ATTACKER_PORT = PORT + 1;
// Our own origin, from config. The Origin check (step 3) compares against this, never against the Host header.
const BASE_URL = `http://localhost:${PORT}`;
const SESSION_TTL_MS = 7 * 24 * 60 * 60 * 1000; // 7 days

// ---------- "Database" ----------
// shortcut: in-memory Maps, lost on restart. A real app uses database tables (and Redis for sessions).
const users = new Map();    // email -> { id, email, salt, passwordHash, balance }
const sessions = new Map(); // sha256(sid) -> { email, csrfToken, expiresAt }
const transfers = [];       // { from, to, amount, via, at }

// ---------- Helpers ----------
const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");
const randomToken = () => crypto.randomBytes(32).toString("base64url"); // 256 random bits → 43 characters
const str = (v) => (typeof v === "string" ? v : undefined); // body/query values can be arrays or objects: accept strings only
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
const parseCookies = (req) => Object.fromEntries((req.headers.cookie ?? "").split(";").filter((c) => c.includes("="))
  .map((c) => [c.slice(0, c.indexOf("=")).trim(), c.slice(c.indexOf("=") + 1).trim()]));
// Compare secrets in constant time. Hashing first makes both sides the same length, which timingSafeEqual needs.
const safeEqual = (a, b) => crypto.timingSafeEqual(Buffer.from(sha256(a)), Buffer.from(sha256(b)));

// shortcut: test accounts with known passwords, so you can log in. A real app has a signup (topic 06).
const DUMMY_SALT = crypto.randomBytes(16);
function seedUser(email, password, balance) {
  const salt = crypto.randomBytes(16);
  users.set(email, { id: crypto.randomUUID(), email, salt, passwordHash: crypto.scryptSync(password, salt, 64), balance });
}
seedUser("rahul@mail.com", "chai-and-code-42", 10000); // the victim
seedUser("vikram@mail.com", "vikram-pass-99", 100);    // the attacker's account

// shortcut: no Secure flag because the demo runs on http://localhost.
// In production (HTTPS) use `secure: true` and the name "__Host-sid" (topic 10).
const COOKIE = { httpOnly: true, sameSite: "lax", path: "/" }; // DEFENSE 1: SameSite=Lax

function getSession(req) {
  const sid = parseCookies(req).sid;
  const session = sid && sessions.get(sha256(sid));
  if (!session || Date.now() > session.expiresAt) return null;
  return session;
}

const page = (title, body) => `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>${esc(title)}</title>
<style>body{font-family:system-ui,sans-serif;max-width:560px;margin:48px auto;padding:0 16px;line-height:1.5}
input,button{font:inherit;padding:8px 12px}input{width:100%;box-sizing:border-box;margin:6px 0}
.box{background:#f1f5f9;border:1px solid #cbd5e1;padding:8px 12px;border-radius:6px}</style></head>
<body><h1>🏦 PaisaPay</h1>${body}</body></html>`;

// Browsers (forms, links) get a small HTML page, curl and fetch get JSON
function reply(req, res, status, body) {
  res.status(status);
  if (req.accepts(["json", "html"]) === "html") {
    return res.send(page("PaisaPay", `<p>${body.error ? "❌ " + esc(body.error) : "✅ " + esc(body.message)}</p>
<p><a href="${BASE_URL}/">Back to PaisaPay</a></p>`));
  }
  res.json(body);
}

// ---------- App ----------
const app = express();
app.use(express.json({ limit: "10kb" }));                        // for curl / fetch
app.use(express.urlencoded({ extended: false, limit: "10kb" })); // for HTML forms
app.use((req, res, next) => { res.set("Cache-Control", "no-store"); next(); });

// ---------- The CSRF defenses ----------

// DEFENSE 2 + 3: who STARTED this request? The browser tells us, and a web page can't fake these headers.
// Sec-Fetch-Site: "same-origin" (our own page), "same-site" (a sibling like blog.paisapay.in or another port),
//                 "cross-site" (evil.com), "none" (typed in the address bar, a bookmark).
// Origin: the exact scheme://host:port of the page that sent it. Browsers send it on every cross-site POST.
function checkOrigin(req, res, next) {
  const site = req.get("sec-fetch-site");
  if (site && site !== "same-origin" && site !== "none") {
    return reply(req, res, 403, { error: `CSRF check failed: request came from another site (Sec-Fetch-Site: ${site})` });
  }
  const origin = req.get("origin");
  // "null" (sandboxed iframes, some redirects) is not our origin either, so it's refused too
  if (origin && origin !== BASE_URL) {
    return reply(req, res, 403, { error: `CSRF check failed: Origin ${origin} is not ${BASE_URL}` });
  }
  // Neither header (curl, very old browsers): the token check below still has to pass.
  // shortcut: OWASP also suggests checking Referer when Origin is missing. The token makes that optional here.
  next();
}

// DEFENSE 4: the synchronizer token. A random secret stored in the session and put into our own pages.
// Another site can make the browser SEND our cookie, but it can't READ our pages, so it never learns the token.
function checkCsrfToken(req, res, next) {
  const session = getSession(req);
  if (!session) return reply(req, res, 401, { error: "Not signed in" });
  // Forms send it as a hidden field, fetch/axios as a header
  const sent = str(req.get("x-csrf-token")) ?? str(req.body?._csrf);
  if (!sent || !safeEqual(sent, session.csrfToken)) {
    return reply(req, res, 403, { error: "CSRF check failed: missing or wrong CSRF token" });
  }
  req.session = session;
  next();
}

// Every route that CHANGES something (POST/PUT/PATCH/DELETE) gets both checks
const csrfProtection = [checkOrigin, checkCsrfToken];

// ---------- Pages and routes ----------

app.get("/", (req, res) => {
  const session = getSession(req);
  if (!session) {
    return res.send(page("Sign in", `<form method="post" action="/login">
<input name="email" type="email" placeholder="Email" value="rahul@mail.com" autocomplete="username">
<input name="password" type="password" placeholder="Password" autocomplete="current-password">
<button>Log in</button></form>
<p class="box">Test account: <b>rahul@mail.com</b> / <b>chai-and-code-42</b></p>`));
  }
  const user = users.get(session.email);
  const recent = transfers.filter((t) => t.from === user.email || t.to === user.email).slice(-5).reverse()
    .map((t) => `<li>₹${t.amount} ${esc(t.from)} → ${esc(t.to)} <small>(via ${t.via})</small></li>`).join("");
  // The token goes into OUR page as a hidden field. Only pages served by us can contain it.
  res.send(page("PaisaPay", `<p>Signed in as <b>${esc(user.email)}</b>. Balance: <b>₹${user.balance}</b></p>
<h2>Send money</h2>
<form method="post" action="/transfer">
<input type="hidden" name="_csrf" value="${esc(session.csrfToken)}">
<input name="to" placeholder="To (email)" value="vikram@mail.com"><input name="amount" type="number" placeholder="Amount ₹" value="100">
<button>Send</button></form>
<h2>Recent transfers</h2><ul>${recent || "<li>None yet</li>"}</ul>
<p class="box">🕵️ Now visit the attacker's site in this same browser:<br>
<a href="http://localhost:${ATTACKER_PORT}">http://localhost:${ATTACKER_PORT}</a> (same-site: only the port differs)<br>
<a href="http://127.0.0.1:${ATTACKER_PORT}">http://127.0.0.1:${ATTACKER_PORT}</a> (cross-site: a different host)</p>
<form method="post" action="/logout"><input type="hidden" name="_csrf" value="${esc(session.csrfToken)}"><button>Log out</button></form>`));
});

// LOGIN: no session yet, so there's no token to check. The Origin check stops login CSRF
// (another site logging you into the ATTACKER's account). Big apps also use a pre-login token.
app.post("/login", checkOrigin, (req, res) => {
  const email = str(req.body?.email)?.trim().toLowerCase();
  const password = str(req.body?.password) ?? "";
  const user = email ? users.get(email) : undefined;
  // Hash even for unknown emails, so the response time doesn't reveal who has an account (topic 51)
  const hash = crypto.scryptSync(password, user?.salt ?? DUMMY_SALT, 64);
  if (!user || !crypto.timingSafeEqual(hash, user.passwordHash)) {
    return reply(req, res, 401, { error: "Wrong email or password" });
  }
  // A NEW session id AND a new CSRF token on login (session fixation, topic 50)
  const oldSid = parseCookies(req).sid;
  if (oldSid) sessions.delete(sha256(oldSid));
  const sid = randomToken();
  sessions.set(sha256(sid), { email: user.email, csrfToken: randomToken(), expiresAt: Date.now() + SESSION_TTL_MS });
  res.cookie("sid", sid, { ...COOKIE, maxAge: SESSION_TTL_MS });
  if (req.accepts(["json", "html"]) === "html") return res.redirect(303, "/");
  res.json({ message: `Logged in as ${user.email}` });
});

// For single-page apps: the frontend reads the token once and sends it as the X-CSRF-Token header.
// Safe to expose with GET because another site's JavaScript can't read this response (same-origin policy,
// as long as CORS doesn't allow it, topic 49).
app.get("/api/csrf-token", (req, res) => {
  const session = getSession(req);
  if (!session) return res.status(401).json({ error: "Not signed in" });
  res.json({ csrfToken: session.csrfToken });
});

app.get("/me", (req, res) => {
  const session = getSession(req);
  if (!session) return res.status(401).json({ error: "Not signed in" });
  const user = users.get(session.email);
  res.json({ email: user.email, balance: user.balance, recentTransfers: transfers.filter((t) => t.from === user.email || t.to === user.email).slice(-5) });
});

// The money move itself. Both the safe and the unsafe routes below call this.
function doTransfer(req, res, fromEmail, via) {
  const input = (req.method === "GET" ? req.query : req.body) ?? {};
  const to = str(input.to)?.trim().toLowerCase();
  const amount = typeof input.amount === "number" || typeof input.amount === "string" ? Number(input.amount) : NaN;
  if (!Number.isInteger(amount) || amount < 1 || amount > 50000) return reply(req, res, 400, { error: "Amount must be a whole number from 1 to 50000" });
  if (!to || !users.has(to) || to === fromEmail) return reply(req, res, 400, { error: "Unknown recipient" });
  const from = users.get(fromEmail);
  if (from.balance < amount) return reply(req, res, 400, { error: "Not enough balance" });
  from.balance -= amount;
  users.get(to).balance += amount;
  transfers.push({ from: fromEmail, to, amount, via, at: new Date().toISOString() });
  console.log(`💸 ₹${amount} ${fromEmail} → ${to} (via ${via}, Origin: ${req.get("origin") ?? "none"}, Sec-Fetch-Site: ${req.get("sec-fetch-site") ?? "none"})`);
  reply(req, res, 200, { message: `Sent ₹${amount} to ${to}`, balance: from.balance });
}

// ✅ THE SAFE VERSION: POST only, Origin/Fetch-Metadata check, CSRF token check
app.post("/transfer", csrfProtection, (req, res) => doTransfer(req, res, req.session.email, "/transfer"));

// ❌ THE VULNERABLE VERSION: trusts the cookie alone, and even accepts GET. Never write this.
// It's here so you can watch the attack work, then fail against /transfer.
function vulnerableTransfer(req, res) {
  const session = getSession(req);
  if (!session) return reply(req, res, 401, { error: "Not signed in" });
  doTransfer(req, res, session.email, `${req.method} /vulnerable/transfer`);
}
app.get("/vulnerable/transfer", vulnerableTransfer);
app.post("/vulnerable/transfer", vulnerableTransfer);

app.post("/logout", csrfProtection, (req, res) => {
  sessions.delete(sha256(parseCookies(req).sid)); // kill it on the server, not just in the browser (topic 11)
  res.clearCookie("sid", COOKIE);
  if (req.accepts(["json", "html"]) === "html") return res.redirect(303, "/");
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

app.listen(PORT, () => console.log(`🏦 PaisaPay (the bank) on ${BASE_URL}  ← open this one`));

// ---------- The attacker's site ----------
// Vikram's "you won a prize" page. It only knows our URLs and field names (anyone can see those),
// never Rahul's CSRF token.
const evil = express();
evil.get("/", (req, res) => {
  res.set("Cache-Control", "no-store").send(`<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>You won!</title>
<style>body{font-family:system-ui,sans-serif;max-width:560px;margin:48px auto;padding:0 16px;line-height:1.5;background:#fff7ed}
button{font:inherit;padding:8px 12px;margin:4px 0}code{background:#fde68a;padding:0 4px}</style></head><body>
<h1>🎁 Congratulations! You won ₹500!</h1>
<p>You are on <code id="here"></code>. PaisaPay is on <code>${BASE_URL}</code>.</p>

<p><b>Trap A</b>: a hidden form to the vulnerable route. (A real attack submits it automatically with
<code>onload</code>; here you press the button.)</p>
<form method="post" action="${BASE_URL}/vulnerable/transfer">
  <input type="hidden" name="to" value="vikram@mail.com"><input type="hidden" name="amount" value="5000">
  <button>Claim prize (A)</button></form>

<p><b>Trap B</b>: the same form to the protected route. Vikram can't add the CSRF token: he doesn't know it.</p>
<form method="post" action="${BASE_URL}/transfer">
  <input type="hidden" name="to" value="vikram@mail.com"><input type="hidden" name="amount" value="5000">
  <button>Claim prize (B)</button></form>

<p><b>Trap C</b>: a plain link to a route that changes data on GET. SameSite=Lax sends cookies on link clicks.</p>
<p><a href="${BASE_URL}/vulnerable/transfer?to=vikram@mail.com&amp;amount=1000">🐱 See cute cat photos (C)</a></p>

<p><b>Trap D</b>: try to READ Rahul's CSRF token with fetch (runs on page load):</p>
<p><code id="steal">trying…</code></p>
<script>
document.getElementById("here").textContent = location.origin;
fetch("${BASE_URL}/api/csrf-token", { credentials: "include" })
  .then((r) => r.json())
  .then((d) => { document.getElementById("steal").textContent = "Stole it: " + JSON.stringify(d); })
  .catch((e) => { document.getElementById("steal").textContent = "Blocked by the browser (no CORS): " + e.message; });
</script>
</body></html>`);
});
evil.use((req, res) => res.status(404).send("Not found"));
evil.listen(ATTACKER_PORT, () => console.log(`😈 Attacker site on http://localhost:${ATTACKER_PORT} (same-site) and http://127.0.0.1:${ATTACKER_PORT} (cross-site)`));

// Every minute, delete expired sessions so the Map doesn't grow forever
setInterval(() => {
  const now = Date.now();
  for (const [k, s] of sessions) if (now > s.expiresAt) sessions.delete(k);
}, 60_000).unref();
