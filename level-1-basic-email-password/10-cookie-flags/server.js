const http = require("http");

// Each demo cookie shows off one flag.
// Note: `Secure` cookies work on http://localhost because browsers treat localhost as a secure origin.
// In production, every auth cookie should have Secure and your site should be HTTPS only (topic 05).
const DEMO_COOKIES = [
  "plain=hello",                                              // no flags at all
  "httpOnly=secret; HttpOnly",                                // hidden from document.cookie
  "lax=1; SameSite=Lax",                                      // sent on cross-site links, not cross-site POSTs
  "strict=1; SameSite=Strict",                                // never sent on cross-site requests
  "none=1; SameSite=None; Secure",                            // sent everywhere (None requires Secure)
  "adminOnly=1; Path=/admin",                                 // only sent to /admin/...
  "shortLived=1; Max-Age=20",                                 // the browser deletes it after 20 seconds
  "__Host-session=k9X2fQ; HttpOnly; Secure; SameSite=Lax; Path=/", // the recommended session cookie
];

// To delete a cookie: same name + same Path (+ same Domain), Max-Age=0
const CLEAR_COOKIES = [
  "plain=; Max-Age=0",
  "httpOnly=; Max-Age=0",
  "lax=; Max-Age=0",
  "strict=; Max-Age=0",
  "none=; SameSite=None; Secure; Max-Age=0",
  "adminOnly=; Path=/admin; Max-Age=0", // without Path=/admin, this cookie would NOT be deleted
  "shortLived=; Max-Age=0",
  "__Host-session=; Secure; Path=/; Max-Age=0",
];

// The server only ever receives "name=value" pairs. It never sees the flags.
function parseCookies(header = "") {
  const cookies = {};
  for (const part of header.split(";")) {
    const eq = part.indexOf("=");
    if (eq > 0) cookies[part.slice(0, eq).trim()] = part.slice(eq + 1).trim();
  }
  return cookies;
}

const HOME_PAGE = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Cookie playground</title>
<style>
  body { font: 16px/1.5 system-ui, sans-serif; max-width: 860px; margin: 32px auto; padding: 0 16px; }
  .boxes { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
  pre { background: #f1f5f9; padding: 12px; border-radius: 8px; min-height: 120px; white-space: pre-wrap; }
  a { margin-right: 12px; }
</style></head>
<body>
  <h1>🍪 Cookie playground: your website (localhost:3000)</h1>
  <p>
    <a href="/set">1. Set demo cookies</a>
    <a href="/admin/echo">2. Open /admin/echo (Path)</a>
    <a href="http://127.0.0.1:4000">3. Visit the other website (SameSite)</a>
    <a href="/clear">4. Delete all</a>
  </p>
  <div class="boxes">
    <div><h3>What JavaScript can see<br><small>document.cookie</small></h3><pre id="js"></pre></div>
    <div><h3>What the server receives<br><small>Cookie header on GET /echo</small></h3><pre id="server"></pre></div>
  </div>
  <p>HttpOnly cookies appear on the <b>right</b> but not on the <b>left</b>. Refresh after 20 seconds and <code>shortLived</code> is gone.</p>
  <script>
    document.getElementById("js").textContent = document.cookie.split("; ").filter(Boolean).join("\\n") || "(nothing)";
    fetch("/echo").then((r) => r.json()).then((data) => {
      const lines = Object.entries(data.cookiesReceived).map(([k, v]) => k + "=" + v);
      document.getElementById("server").textContent = lines.join("\\n") || "(nothing)";
    });
  </script>
</body></html>`;

// ---------- Your website: http://localhost:3000 ----------
http.createServer((req, res) => {
  const path = req.url.split("?")[0];

  if (path === "/set") {
    res.writeHead(302, { "Set-Cookie": DEMO_COOKIES, Location: "/" });
    return res.end();
  }

  if (path === "/clear") {
    res.writeHead(302, { "Set-Cookie": CLEAR_COOKIES, Location: "/" });
    return res.end();
  }

  if (path === "/echo" || path === "/admin/echo") {
    // Shows exactly which cookies the browser decided to attach to THIS request
    res.writeHead(200, { "Content-Type": "application/json" });
    return res.end(JSON.stringify({ path, method: req.method, cookiesReceived: parseCookies(req.headers.cookie) }));
  }

  if (path === "/") {
    res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
    return res.end(HOME_PAGE);
  }

  res.writeHead(404);
  res.end("Not found");
}).listen(3000, () => console.log("Your website:      http://localhost:3000   (start at /set)"));

// ---------- The other website: http://127.0.0.1:4000 ----------
// localhost and 127.0.0.1 are different sites, so every request from here to localhost:3000 is CROSS-SITE.
const OTHER_SITE = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>The other website</title>
<style>
  body { font: 16px/1.5 system-ui, sans-serif; max-width: 860px; margin: 32px auto; padding: 0 16px; background: #fff7ed; }
  .row { margin: 16px 0; padding: 12px; background: #fff; border-radius: 8px; border: 1px solid #fed7aa; }
  iframe { width: 100%; height: 90px; border: 1px solid #ccc; }
</style></head>
<body>
  <h1>😈 The other website (127.0.0.1:4000)</h1>
  <p>Each button sends a <b>cross-site</b> request to <code>localhost:3000/echo</code>. The response shows which cookies the browser attached.</p>

  <div class="row"><b>A. Click a link</b> (top-level GET navigation)<br>
    <a href="http://localhost:3000/echo">Go to localhost:3000/echo</a></div>

  <div class="row"><b>B. Submit a form</b> (top-level POST, like a CSRF attack)<br>
    <form action="http://localhost:3000/echo" method="POST"><input type="hidden" name="amount" value="50000"><button>Submit the form</button></form></div>

  <div class="row"><b>C. Load it in an iframe</b> (an embedded, cross-site request)<br>
    <button onclick="document.getElementById('frame').src='http://localhost:3000/echo'">Load the iframe</button>
    <iframe id="frame" title="localhost:3000/echo inside an iframe"></iframe></div>
</body></html>`;

http.createServer((req, res) => {
  res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
  res.end(OTHER_SITE);
}).listen(4000, "127.0.0.1", () => console.log("The other website: http://127.0.0.1:4000"));
