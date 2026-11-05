const express = require("express");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const { promisify } = require("util");

const scrypt = promisify(crypto.scrypt);
const SCRYPT_OPTIONS = { N: 2 ** 17, r: 8, p: 1, maxmem: 256 * 1024 * 1024 };

const PORT = Number(process.env.PORT) || 3000;
const BASE_URL = `http://localhost:${PORT}`;
// Set ACCESS_TTL_SECONDS=10 to watch tokens expire and get silently refreshed in seconds instead of minutes
const ACCESS_TTL_SECONDS = Number(process.env.ACCESS_TTL_SECONDS) || 15 * 60; // 15 minutes
const REFRESH_TTL_MS = 7 * 24 * 60 * 60 * 1000;                              // 7 days

// shortcut: a new random secret on every start (all tokens die on restart). A real app loads it from an env var / secret manager.
const ACCESS_SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString("hex");

const REFRESH_COOKIE = "refreshToken";
const REFRESH_COOKIE_OPTIONS = { httpOnly: true, sameSite: "strict", path: "/auth", secure: process.env.NODE_ENV === "production" };

// ---------- "Database" ----------
// shortcut: in-memory Maps, lost on restart. A real app uses database tables.
const users = new Map();         // email -> { id, email, passwordHash }
const refreshTokens = new Map(); // sha256(refreshToken) -> { userId, expiresAt }

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

function readCookie(req, name) {
  for (const part of (req.headers.cookie ?? "").split(";")) {
    const [key, ...rest] = part.trim().split("=");
    if (key === name) return rest.join("=");
  }
  return undefined;
}

// ---------- Tokens (same as topic 21) ----------
function issueRefreshToken(res, user) {
  const refreshToken = crypto.randomBytes(32).toString("hex");
  refreshTokens.set(sha256(refreshToken), { userId: user.id, expiresAt: Date.now() + REFRESH_TTL_MS });
  res.cookie(REFRESH_COOKIE, refreshToken, { ...REFRESH_COOKIE_OPTIONS, maxAge: REFRESH_TTL_MS });
}

// Step 1: tell the client WHEN the token expires (expiresIn), so it can refresh BEFORE that (proactive refresh)
const tokenResponse = (user) => ({
  accessToken: jwt.sign({ sub: user.id, email: user.email }, ACCESS_SECRET, { algorithm: "HS256", expiresIn: ACCESS_TTL_SECONDS }),
  tokenType: "Bearer",
  expiresIn: ACCESS_TTL_SECONDS,
});

// ---------- App ----------
const app = express();
app.use(express.json({ limit: "10kb" }));
app.use((req, res, next) => { res.set("Cache-Control", "no-store"); next(); });

// CSRF defense in depth (topic 11). Open the demo at http://localhost:PORT (not 127.0.0.1), or this blocks it.
app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (["POST", "PUT", "PATCH", "DELETE"].includes(req.method) && origin && origin !== BASE_URL) {
    return res.status(403).json({ error: "Request from another site was blocked" });
  }
  next();
});

// Step 2: an expired token gets a DIFFERENT answer than a bad one.
// "token_expired" = refresh and retry. Anything else = don't bother refreshing, the token is just wrong.
function requireAuth(req, res, next) {
  const [scheme, token] = (req.headers.authorization ?? "").split(" ");
  if (scheme !== "Bearer" || !token) return res.status(401).json({ error: "Missing access token" });
  try {
    req.auth = jwt.verify(token, ACCESS_SECRET, { algorithms: ["HS256"] });
    next();
  } catch (err) {
    if (err.name === "TokenExpiredError") {
      res.set("WWW-Authenticate", 'Bearer error="invalid_token", error_description="The access token expired"'); // the standard way (RFC 6750)
      return res.status(401).json({ error: "Access token expired", code: "token_expired" });
    }
    res.status(401).json({ error: "Invalid access token", code: "invalid_token" });
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
  const { email, password } = req.body ?? {};
  if (typeof email !== "string" || typeof password !== "string" || !email || !password) {
    return res.status(400).json({ error: "Email and password are required" });
  }
  const user = users.get(email.trim().toLowerCase());
  const ok = await verifyPassword(password, user ? user.passwordHash : await DUMMY_HASH_PROMISE);
  if (!user || !ok) return res.status(401).json({ error: "Invalid email or password" });
  issueRefreshToken(res, user);
  res.json(tokenResponse(user));
});

let refreshCount = 0; // only so you can SEE in the terminal that 5 parallel calls cause 1 refresh, not 5
app.post("/auth/refresh", (req, res) => {
  const refreshToken = readCookie(req, REFRESH_COOKIE);
  if (!/^[a-f0-9]{64}$/.test(refreshToken ?? "")) return res.status(401).json({ error: "Missing refresh token, please log in" });
  const key = sha256(refreshToken);
  const stored = refreshTokens.get(key);
  const user = stored && findUserById(stored.userId);
  if (!stored || Date.now() > stored.expiresAt || !user) {
    if (stored) refreshTokens.delete(key);
    res.clearCookie(REFRESH_COOKIE, REFRESH_COOKIE_OPTIONS);
    return res.status(401).json({ error: "Refresh token is invalid or expired, please log in" });
  }
  console.log(`🔄 refresh #${++refreshCount} for ${user.email}`);
  res.json(tokenResponse(user));
});

app.post("/auth/logout", (req, res) => {
  const refreshToken = readCookie(req, REFRESH_COOKIE);
  if (refreshToken) refreshTokens.delete(sha256(refreshToken));
  res.clearCookie(REFRESH_COOKIE, REFRESH_COOKIE_OPTIONS);
  res.json({ message: "Logged out" });
});

app.get("/me", requireAuth, (req, res) => {
  res.json({ email: req.auth.email, accessTokenExpiresAt: new Date(req.auth.exp * 1000).toISOString() });
});

// ---------- Step 3: the CLIENT side of silent refresh, as a tiny demo page ----------
// Silent refresh happens in the frontend, so the server just serves this page. Open http://localhost:PORT
const DEMO_PAGE = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>22. Silent refresh demo</title>
<style>
  body { font: 15px/1.5 system-ui, sans-serif; max-width: 760px; margin: 24px auto; padding: 0 16px; }
  input, button { font: inherit; padding: 6px 10px; margin: 2px; }
  #log { background: #111; color: #ddd; padding: 12px; border-radius: 8px; min-height: 200px; white-space: pre-wrap; font: 13px/1.5 ui-monospace, monospace; }
</style></head><body>
<h1>Silent refresh demo</h1>
<p>Access tokens last <b>${ACCESS_TTL_SECONDS} s</b>. Keep this page open and watch the log: you never see a login screen again.</p>
<div id="loggedOut">
  <input id="email" value="rahul@mail.com" aria-label="Email"> <input id="password" type="password" value="correct horse battery" aria-label="Password">
  <button id="signup">Sign up</button> <button id="login">Log in</button>
</div>
<div id="loggedIn" hidden>
  <label><input type="checkbox" id="proactive" checked> Proactive refresh (timer before expiry)</label><br>
  <button id="me">Call /me</button> <button id="five">Call /me 5 times at once</button> <button id="logout">Log out</button>
</div>
<p id="status"></p>
<div id="log" role="log" aria-live="polite"></div>
<script>
const $ = (id) => document.getElementById(id);
const log = (msg) => { $("log").textContent = new Date().toLocaleTimeString() + "  " + msg + "\\n" + $("log").textContent; };

// The access token lives ONLY in memory (a variable). A page reload loses it, and that's fine: see restore() below.
let accessToken = null;
let refreshTimer = null;
let refreshPromise = null; // the ONE refresh that is in flight right now (if any)

function setToken({ accessToken: token, expiresIn }) {
  accessToken = token;
  clearTimeout(refreshTimer);
  if (!$("proactive").checked) return;
  // PROACTIVE: refresh a little BEFORE expiry (60 s early, or 20% early for very short tokens)
  const earlyMs = Math.min(60_000, expiresIn * 200);
  refreshTimer = setTimeout(() => { log("⏰ timer: token expires soon, refreshing in the background"); refresh().catch(() => {}); }, expiresIn * 1000 - earlyMs);
}

// SINGLE-FLIGHT: if 5 requests need a new token at once, they all wait for the SAME refresh call
function refresh() {
  if (!refreshPromise) {
    log("🔄 POST /auth/refresh (the browser sends the HttpOnly cookie by itself)");
    refreshPromise = fetch("/auth/refresh", { method: "POST" })
      .then(async (res) => {
        if (!res.ok) { showLoggedOut("Session over, please log in again"); throw new Error("refresh failed"); }
        setToken(await res.json());
        log("✅ new access token received");
      })
      .finally(() => { refreshPromise = null; });
  }
  return refreshPromise;
}

// REACTIVE: every API call goes through here. On 401 token_expired: refresh once, then retry once.
async function api(path) {
  const call = () => fetch(path, { headers: { Authorization: "Bearer " + accessToken } });
  let res = await call();
  if (res.status === 401 && (await res.clone().json()).code === "token_expired") {
    log("⌛ " + path + " → 401 token_expired, refreshing and retrying");
    await refresh();
    res = await call(); // retry ONCE. Never loop forever.
  }
  return res;
}

async function callMe(label) {
  try {
    const res = await api("/me");
    log(label + " /me → " + res.status + " " + JSON.stringify(await res.json()));
  } catch { /* refresh failed: already logged out */ }
}

function showLoggedIn() { $("loggedOut").hidden = true; $("loggedIn").hidden = false; $("status").textContent = "Logged in"; }
function showLoggedOut(msg) { accessToken = null; clearTimeout(refreshTimer); $("loggedOut").hidden = false; $("loggedIn").hidden = true; $("status").textContent = msg; }

async function sendCredentials(path) {
  const res = await fetch(path, { method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email: $("email").value, password: $("password").value }) });
  const body = await res.json();
  log(path + " → " + res.status + (body.error ? " " + body.error : ""));
  if (path === "/auth/login" && res.ok) { setToken(body); showLoggedIn(); }
}

$("signup").onclick = () => sendCredentials("/auth/signup");
$("login").onclick = () => sendCredentials("/auth/login");
$("me").onclick = () => callMe("👤");
$("five").onclick = () => { for (let i = 1; i <= 5; i++) callMe("#" + i); };
$("proactive").onchange = () => { clearTimeout(refreshTimer); log($("proactive").checked ? "timer on (applies after the next token)" : "timer off: only the 401 → refresh → retry path is left"); };
$("logout").onclick = async () => { await fetch("/auth/logout", { method: "POST" }); showLoggedOut("Logged out"); log("👋 logged out"); };

// PAGE LOAD: no token in memory, but maybe a refresh cookie. Try a silent refresh to restore the login.
(async function restore() {
  try { await refresh(); showLoggedIn(); log("page load: login restored from the refresh cookie"); }
  catch { showLoggedOut("Please log in"); log("page load: no valid refresh cookie, please log in"); }
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

app.listen(PORT, () => console.log(`Silent refresh demo on ${BASE_URL} (access tokens last ${ACCESS_TTL_SECONDS} s). Open it in your browser.`));

setInterval(() => {
  const now = Date.now();
  for (const [key, t] of refreshTokens) if (now > t.expiresAt) refreshTokens.delete(key);
}, 60_000).unref();
