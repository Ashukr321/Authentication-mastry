# 47. CSRF

## Notes

### What is CSRF?

**CSRF (Cross-Site Request Forgery)** is when **another website makes your browser send a request to a site you're logged in to**. The browser attaches your cookies automatically, so the server thinks **you** sent it.

You met it already: topic 09 ("Sessions and CSRF") and topic 10 (`SameSite`). This topic is the full defense: why `SameSite` alone is not enough, and the **Origin check**, **Fetch Metadata** and **CSRF tokens** that close the gaps.

> **One-line answer:** CSRF = a foreign page makes the victim's browser send a cookie-authenticated request; the attacker can **send** but can't **read**. So: never change data on GET, set `SameSite=Lax`, refuse unsafe requests whose `Sec-Fetch-Site`/`Origin` is not your own site, and require a secret **CSRF token** that only your own pages contain.

---

### Why it matters

| What the attacker can make you do | Example |
|---|---|
| Move money | `POST /transfer to=vikram amount=50000` |
| Take over your account | `POST /account/email email=vikram@evil.com`, then "forgot password" (topic 13) |
| Change security settings | Turn off 2FA, add their passkey, add a forwarding rule |
| Log you into **their** account (login CSRF) | You then save your card/address into Vikram's account (topic 42) |
| Delete things | `POST /account/delete` (topic 17) |

Who is at risk? **Anything that logs in with cookies** (sessions, topic 09; JWT in a cookie, topic 25), and also HTTP Basic auth (topic 08) and client certificates, because the browser sends them automatically too.

Who is **not**: an API that only accepts `Authorization: Bearer …` from JavaScript memory (topic 19). Nobody can make your browser add that header to a request. (But that token can be stolen by XSS instead, topics 25 and 48.)

---

### Real-life example: the office peon 📮

Rahul is a manager at a Mumbai company. His peon, Ramu, carries the **company stamp**. Any letter handed to Ramu gets the stamp and goes to the bank.

1. Ramu stamps **every** letter handed to him, no questions → the browser attaches cookies to **every** request to that site
2. Vikram from another office slips Ramu a letter: "Pay ₹50,000 to Vikram" → evil.com's hidden form
3. The bank sees the real stamp and pays → the server sees a valid session cookie
4. Fix 1: the bank checks **which office the envelope came from** → the `Origin` / `Sec-Fetch-Site` check
5. Fix 2: every real letter has a **secret code word** printed on Rahul's own letterhead. Vikram can make Ramu stamp a letter, but he has never **seen** the letterhead → the **CSRF token**
6. Fix 3: Ramu stops stamping letters that come from outside the building → `SameSite=Lax`

---

### The attack, step by step

#### 📊 Diagrams

Open **[diagrams.html](diagrams.html)** in your browser (just double-click the file) to see:

- **Flow diagram**: every check a request passes before money moves
- **Data flow**: the attack and the real transfer side by side, with the real headers
- **Which defense stops what**: same-site vs cross-site attackers, POST vs GET

In short: `logged in to the bank → visit evil page → hidden form POSTs to the bank → browser adds the cookie → bank checks Sec-Fetch-Site / Origin → bank checks the CSRF token → refused`

```html
<!-- on Vikram's page -->
<form action="https://paisapay.in/transfer" method="POST">
  <input type="hidden" name="to" value="vikram@mail.com">
  <input type="hidden" name="amount" value="5000">
</form>
<script>document.forms[0].submit();</script>
```

What the attacker **can** and **can't** do. This table is the whole topic:

| Vikram's page can… | Vikram's page can't… |
|---|---|
| Make your browser **send** a GET (link, `<img>`) or a form POST to the bank | **Read** the bank's response (same-origin policy) |
| Choose the URL and the form fields | Add custom headers like `X-CSRF-Token` to a cross-site request (without CORS, topic 49) |
| Get your cookies attached (depending on `SameSite`) | Read your cookies or the bank's pages, so it never learns your **CSRF token** |
| Send `Content-Type`: form, `multipart` or `text/plain` | Send `application/json` without a CORS preflight |

So every defense is built on the right column.

---

### Defense 0: Never change data on GET

`GET` must only **read**. A link, an `<img src>`, a link preview or a prefetch can all trigger a GET.

| ✅ Do | ❌ Don't |
|---|---|
| `POST /transfer`, `DELETE /posts/7` | `GET /transfer?to=vikram&amount=1000` |
| `POST /logout` with a token | `<a href="/logout">` (anyone can log you out, and it's a GET) |
| `GET /verify?token=…` shows a confirm page, the button POSTs (topic 42) | `GET /verify?token=…` logs you in |

Why so strict? `SameSite=Lax` **still sends cookies on a top-level GET** (clicking a link). Our demo's trap C is exactly this: a "cute cat photos" link moves ₹1000, even from a cross-site page.

---

### Defense 1: `SameSite=Lax` cookies (topic 10)

```
Set-Cookie: sid=…; HttpOnly; Secure; SameSite=Lax
```

`Lax` = the cookie is **not** sent on a cross-site POST, `fetch`, `<img>` or `<iframe>`. That alone stops the hidden form on evil.com. So why isn't it enough?

| Gap | Why |
|---|---|
| **Same-site attackers** | "Site" = the registrable domain. `blog.paisapay.in`, an old `promo.paisapay.in` with an XSS, or `localhost:3001` vs `localhost:3000` are **the same site**, so `Lax` sends the cookie. Our demo's attacker on `localhost:3048` steals ₹5000 this way. |
| GET still works | Top-level navigations carry the cookie (Defense 0) |
| `SameSite=None` cookies | Needed for embeds and some SSO flows. These get **no** CSRF protection from the browser. |
| Older browsers | Some don't support `SameSite`, or treat a missing value as `None` |
| Chrome's "Lax-by-default" 2-minute window | A cookie **without** an explicit `SameSite` is sent on cross-site POSTs for its first 2 minutes. Always write `SameSite=Lax` explicitly. |

👉 `SameSite` is a great **layer**, not the whole defense.

---

### Defense 2: Fetch Metadata (`Sec-Fetch-Site`)

Modern browsers add this header to every request, and **web pages can't change it**:

| `Sec-Fetch-Site` | Means | For POST/PUT/PATCH/DELETE |
|---|---|---|
| `same-origin` | Your own page (same scheme, host **and port**) | ✅ allow |
| `none` | The user typed the URL or used a bookmark | ✅ allow |
| `same-site` | A sibling: `blog.paisapay.in`, another port | ❌ refuse (unless you really need it) |
| `cross-site` | evil.com | ❌ refuse |

```js
const site = req.get("sec-fetch-site");
if (site && site !== "same-origin" && site !== "none") return res.status(403)...;
```

This is the check that also stops **same-site** attackers, which `SameSite` can't.

---

### Defense 3: The `Origin` check

Browsers send `Origin: https://evil.com` on every cross-site POST (and `fetch`). Compare it to **your own configured origin**:

```js
const origin = req.get("origin");
if (origin && origin !== BASE_URL) return res.status(403)...; // "null" is refused too
```

| ✅ Do | ❌ Don't |
|---|---|
| Compare to a fixed `BASE_URL` (or an allowlist) | Compare to the `Host` header (an attacker can control it behind some proxies) |
| Exact match `https://paisapay.in` | `origin.includes("paisapay.in")` (matches `paisapay.in.evil.com`) |
| Refuse `Origin: null` | Treat `null` as "no origin" (sandboxed iframes send `null`) |

Missing `Origin`? curl, old browsers, some privacy tools. OWASP suggests falling back to the `Referer` header, then to the token. In our demo the token check (next) always runs anyway.

---

### Defense 4: The CSRF token (synchronizer token pattern)

The strongest and most classic defense:

1. On login, create `csrfToken = randomBytes(32)` and store it **in the session** (server side)
2. Put it into **your own pages**: a hidden field in every form, or a JSON endpoint for SPAs
3. On every POST/PUT/PATCH/DELETE, compare the sent token with the session's token (constant time)

```html
<form method="post" action="/transfer">
  <input type="hidden" name="_csrf" value="aIXIcTZ_W9uKPaBE…">
  …
</form>
```

```js
// SPA: read it once, send it as a header
const { csrfToken } = await (await fetch("/api/csrf-token")).json();
fetch("/transfer", { method: "POST", headers: { "Content-Type": "application/json", "X-CSRF-Token": csrfToken }, body: … });
```

Why does it work? Vikram's page can make the browser **send** the cookie, but it can't **read** your page or `/api/csrf-token` (trap D in the demo: "Failed to fetch"). Without the token, the forged form is refused.

| ✅ Do | ❌ Don't |
|---|---|
| `crypto.randomBytes(32)` | `Math.random()`, the user id, a timestamp |
| Store it in the **session**, new token on **login** | One token for everyone, or a token that survives logout/login |
| Compare with `timingSafeEqual` | `===` (tiny timing leak) |
| Send it in a **hidden field** or a **header** | Put it in the **URL** (`?csrf=…`): it leaks into logs, history and `Referer` |
| Check it on **every** unsafe method | Check only POST and forget PUT/DELETE |
| Return `403` when it's missing or wrong | Skip the check when the field is missing |

#### Other token patterns you'll hear about

| Pattern | How | When |
|---|---|---|
| **Synchronizer token** (our demo) | Token stored in the server session | You have server sessions |
| **Signed double-submit cookie** | Token = `HMAC(secret, sessionId + random)`, sent in a cookie **and** a header; server checks they match and the HMAC is valid | Stateless servers (JWT in a cookie) |
| Naive double-submit (cookie value == header value, no HMAC) | ❌ A sibling subdomain can **set** the cookie (cookie tossing), so the attacker knows both values. Use the signed version, and a `__Host-` cookie name. | Don't |
| Custom header only (`X-Requested-With: fetch`) | Cross-site forms can't add headers; `fetch` needs CORS preflight | OK for pure JSON APIs **with strict CORS**, weaker than a token |

> ⚠️ The `csurf` npm package that many old tutorials use is **deprecated**. Write the 20 lines yourself (like `server.js`) or use a maintained library like `csrf-csrf` (signed double-submit).

---

### 🤔 Tricky parts

**1. "My API only accepts JSON, so I'm safe."** Partly. A form can't send `Content-Type: application/json`. But a form **can** send `text/plain` with a body that looks like JSON (`{"to":"vikram","amount":5000,"x":"=…"}`). If your server parses JSON **regardless of the Content-Type**, it's exploitable. Check the Content-Type, and still use the Origin check.

**2. Login CSRF.** No session yet, so there's no session token. The attacker logs **you** into **his** account, and you save your card in it. Defenses: the Origin/Fetch-Metadata check on `POST /login` (our demo), or a pre-login token in a short-lived cookie.

**3. XSS beats every CSRF defense.** A script running **on your own page** is same-origin: it can read the token from the page and send the request with all the right headers. CSRF defense assumes you have no XSS (topic 48).

**4. A bad CORS config leaks the token.** If your server answers `Access-Control-Allow-Origin: <whatever Origin was sent>` with `Allow-Credentials: true`, evil.com **can** read `/api/csrf-token`. Then the token is worthless (topic 49).

**5. Rotate on login, not on every request.** Per-request tokens break the back button and multiple tabs. One token per session, renewed on login (with the new session id, topic 50), is what OWASP recommends.

**6. "Same-site" ≠ "same-origin".** `https://paisapay.in` and `https://blog.paisapay.in` are the same **site** but different **origins**. `SameSite` cookies protect against other **sites**; `Sec-Fetch-Site: same-origin` and the Origin check protect against other **origins**. Demo: the attacker on `localhost:3048` is same-site with the bank on `localhost:3047`.

**7. Clickjacking is CSRF's cousin.** Instead of forging a request, the attacker shows your real page in an invisible `<iframe>` and tricks the user into clicking. Tokens don't help (it's your real page). Fix: `Content-Security-Policy: frame-ancestors 'none'` (or `X-Frame-Options: DENY`).

---

### Common beginner mistakes

1. **Changing data with GET.**
   `GET /delete?id=7` or `<a href="/logout">`. `SameSite=Lax` sends cookies on links.

2. **Thinking `SameSite=Lax` is all you need.**
   It ignores same-site attackers (subdomains), GET, and `SameSite=None` cookies.

3. **Thinking JWT means no CSRF.**
   A JWT **in a cookie** is sent automatically, exactly like a session id. Only a `Bearer` header is CSRF-free.

4. **Checking the token only when it's present.**
   `if (req.body._csrf && req.body._csrf !== session.token)` lets requests **without** a token through.

5. **Comparing `Origin` with `includes()` or `startsWith()`.**
   `https://paisapay.in.evil.com` passes. Use an exact match.

6. **Putting the token in the URL.**
   It leaks through logs, history and the `Referer` header.

7. **One global token, or a token that never changes.**
   Tie it to the session and renew it on login.

8. **Protecting POST but not PUT/PATCH/DELETE.**
   Protect every method except GET, HEAD and OPTIONS.

9. **A CORS config that reflects any Origin with credentials.**
   Now other sites can read your token.

10. **Forgetting login and logout.**
    Login CSRF logs you into the attacker's account; logout CSRF is annoying. Protect both.

---

### Interview questions

1. **What is CSRF?**
   An attack where another site makes the victim's browser send a request to a site they're logged in to. The browser attaches the cookies, so the request looks legitimate. The attacker can trigger the request but can't read the response.

2. **How do you prevent it?**
   Layers: no state changes on GET; `SameSite=Lax` (or `Strict`) cookies; refuse unsafe requests whose `Sec-Fetch-Site` isn't `same-origin`/`none` or whose `Origin` isn't yours; and a CSRF token (synchronizer or signed double-submit) on every state-changing request.

3. **Is `SameSite=Lax` enough?**
   No. It doesn't stop same-site attackers (a compromised subdomain), it allows top-level GET, it doesn't apply to `SameSite=None` cookies, and older browsers may not support it.

4. **How does a CSRF token work, and why can't the attacker get it?**
   It's a random secret stored in the session and embedded in the site's own pages. The same-origin policy stops other sites from reading those pages, so a forged request can't include it.

5. **Does a REST API using JWTs need CSRF protection?**
   If the JWT is in an `Authorization: Bearer` header, no: browsers don't add that header automatically. If the JWT is in a cookie, yes.

6. **What's the difference between CSRF and XSS?**
   CSRF tricks the browser into **sending** a request from another site; it can't read anything. XSS **runs the attacker's script** on your site; it can read the page, the token, and send anything. XSS defeats CSRF defenses.

7. **What is login CSRF?**
   Logging the victim into the **attacker's** account, so the victim's later actions (saved cards, search history) go to the attacker. Stopped with an Origin check or a pre-session token on the login form.

8. **What is double-submit cookie and its weakness?**
   The token is in a cookie and a header/field, and the server checks they match. The naive version breaks if an attacker can set cookies for your domain (a subdomain); the signed (HMAC) version fixes it.

9. **Can an attacker send a JSON body with a form?**
   Not with `Content-Type: application/json`, but with `text/plain` they can send JSON-looking text. Enforce the Content-Type and keep a real CSRF defense.

---

### Quick recap

- CSRF = **another site makes your browser send** a cookie-authenticated request. It can **send, not read**.
- **GET never changes data** (Lax still sends cookies on link clicks)
- **`SameSite=Lax`** on session cookies: a layer, not the whole fix (same-site attackers!)
- **`Sec-Fetch-Site`** must be `same-origin` or `none`; **`Origin`** must exactly equal your `BASE_URL`
- **CSRF token**: `randomBytes(32)` in the session, hidden field or `X-CSRF-Token` header, `timingSafeEqual`, renewed on login
- Protect **every** unsafe method, plus **login** and **logout**
- **Bearer headers** don't need CSRF protection; **cookies** (session or JWT) do
- **XSS** (topic 48) and **bad CORS** (topic 49) break all of this

## Code

A small **Express** app with **two servers in one file**: **PaisaPay**, a bank (on `PORT`), and **Vikram's prize page**, the attacker (on `PORT + 1`). The bank has a protected `POST /transfer` (Origin + Fetch Metadata + CSRF token) and, for learning, an unprotected `/vulnerable/transfer` that trusts the cookie alone. Log in, visit the attacker's page in the same browser, and watch which traps work. Everything is in memory, so a restart resets the balances.

📄 **Full code: [server.js](server.js)**. Open it and read the comments, which follow the same defenses as the notes above.

Install Express once (from this folder), then start the server:

```bash
npm install
```

```bash
node server.js
```

> Port 3000 busy? Run it on another port: `PORT=3047 node server.js` (Git Bash). The attacker then runs on 3048. The outputs below were recorded on port 3047.

### Try it in the browser (the real attack)

1. Open **http://localhost:3047** and log in as **rahul@mail.com** / **chai-and-code-42** (balance ₹10000).
2. Send ₹100 with the form: ✅ works (your page has the hidden `_csrf` field).
3. Open **http://localhost:3048** (same-site, only the port differs). These are the results from our test run:

| Trap | Result | Why |
|---|---|---|
| **A**: hidden form → `/vulnerable/transfer` | ✅ "Sent ₹5000 to vikram" 😱 | Same **site**, so `SameSite=Lax` sends the cookie |
| **B**: hidden form → `/transfer` | ❌ `CSRF check failed: request came from another site (Sec-Fetch-Site: same-site)` | Fetch Metadata stops same-site attackers |
| **D**: `fetch` the token | "Blocked by the browser (no CORS): Failed to fetch" | The attacker can't **read** your token |

4. Open **http://127.0.0.1:3048** (cross-site: a different host):

| Trap | Result | Why |
|---|---|---|
| **A**: hidden form → `/vulnerable/transfer` | ❌ `Not signed in` | Cross-site POST: `SameSite=Lax` keeps the cookie at home |
| **C**: "cute cat photos" link (GET) | ✅ "Sent ₹1000 to vikram" 😱 | `Lax` **does** send cookies on link clicks, and this route changes data on GET |

The server terminal logs every transfer with the headers the browser sent:

```
💸 ₹5000 rahul@mail.com → vikram@mail.com (via POST /vulnerable/transfer, Origin: http://localhost:3048, Sec-Fetch-Site: same-site)
💸 ₹1000 rahul@mail.com → vikram@mail.com (via GET /vulnerable/transfer, Origin: none, Sec-Fetch-Site: cross-site)
```

### Try it with curl (Git Bash)

curl is not a browser: it sends cookies wherever you tell it and adds no `Origin` or `Sec-Fetch-Site`. So below, **we** add the headers a browser would send from the attacker's page.

```bash
APP=http://localhost:3047
```

✅ **① Log in.** `-c rahul.jar` saves the session cookie like a browser would.

```bash
curl -i -c rahul.jar -b rahul.jar $APP/login -H "Content-Type: application/json" -d '{"email":"rahul@mail.com","password":"chai-and-code-42"}'
```
→
```
HTTP/1.1 200 OK
Set-Cookie: sid=SkqI01vVNrkNSdGrkUUU3KRr_uuvX9Q7bjl3uzGirZE; Max-Age=604800; Path=/; Expires=...; HttpOnly; SameSite=Lax
{"message":"Logged in as rahul@mail.com"}
```

✅ **② Get your CSRF token** (what a single-page app does once after login):

```bash
curl -s -b rahul.jar $APP/api/csrf-token
```
→ `{"csrfToken":"aIXIcTZ_W9uKPaBEKJZVLZ5dioXvAm9bvDljeWVXBIs"}`

```bash
TOKEN=PASTE_YOUR_TOKEN_HERE
```

✅ **③ A real transfer:** cookie **and** token.

```bash
curl -s -b rahul.jar $APP/transfer -H "Content-Type: application/json" -H "X-CSRF-Token: $TOKEN" -d '{"to":"vikram@mail.com","amount":100}'
```
→ `{"message":"Sent ₹100 to vikram@mail.com","balance":9900}`

😱 **④ The attack on the vulnerable route:** the form from Vikram's page, with the headers the browser adds. Only the cookie is checked, so it works.

```bash
curl -s -b rahul.jar $APP/vulnerable/transfer -H "Origin: http://localhost:3048" -H "Sec-Fetch-Site: same-site" -d "to=vikram@mail.com&amount=5000"
```
→ `{"message":"Sent ₹5000 to vikram@mail.com","balance":4900}`

🛡️ **⑤ The same attack on `/transfer`:** no token (the attacker doesn't know it).

```bash
curl -s -b rahul.jar $APP/transfer -d "to=vikram@mail.com&amount=5000"
```
→ `{"error":"CSRF check failed: missing or wrong CSRF token"}` (403)

🛡️ **⑥ Even with the right token, a foreign `Origin` is refused:**

```bash
curl -s -b rahul.jar $APP/transfer -H "Origin: http://localhost:3048" -d "to=vikram@mail.com&amount=5000&_csrf=$TOKEN"
```
→ `{"error":"CSRF check failed: Origin http://localhost:3048 is not http://localhost:3047"}` (403)

🛡️ **⑦ …and so is `Sec-Fetch-Site: cross-site`:**

```bash
curl -s -b rahul.jar $APP/transfer -H "Sec-Fetch-Site: cross-site" -H "X-CSRF-Token: $TOKEN" -d "to=vikram@mail.com&amount=5000"
```
→ `{"error":"CSRF check failed: request came from another site (Sec-Fetch-Site: cross-site)"}` (403)

🛡️ **⑧ A guessed token:**

```bash
curl -s -b rahul.jar $APP/transfer -H "X-CSRF-Token: guessed-token" -d "to=vikram@mail.com&amount=5000"
```
→ `{"error":"CSRF check failed: missing or wrong CSRF token"}` (403)

😱 **⑨ A GET that changes data** (trap C, the "cat photos" link):

```bash
curl -s -b rahul.jar "$APP/vulnerable/transfer?to=vikram@mail.com&amount=1000"
curl -s -b rahul.jar "$APP/transfer?to=vikram@mail.com&amount=1000"
```
→ `{"message":"Sent ₹1000 to vikram@mail.com","balance":3900}`, then `{"error":"Not found"}` (the safe route has no GET at all)

✅ **⑩ Where did the money go?**

```bash
curl -s -b rahul.jar $APP/me
```
→ `{"email":"rahul@mail.com","balance":3900,"recentTransfers":[{… "amount":100,"via":"/transfer" …},{… "amount":5000,"via":"POST /vulnerable/transfer" …},{… "amount":1000,"via":"GET /vulnerable/transfer" …}]}`

🛡️ **⑪ Login CSRF:** another site can't log you into Vikram's account.

```bash
curl -s $APP/login -H "Origin: http://127.0.0.1:3048" -d "email=vikram@mail.com&password=vikram-pass-99"
```
→ `{"error":"CSRF check failed: Origin http://127.0.0.1:3048 is not http://localhost:3047"}` (403)

👋 **⑫ Log out:** a POST, so it needs the token too.

```bash
curl -s -b rahul.jar -X POST $APP/logout
curl -s -b rahul.jar -c rahul.jar -X POST $APP/logout -H "X-CSRF-Token: $TOKEN"
curl -s -b rahul.jar $APP/me
```
→ `{"error":"CSRF check failed: missing or wrong CSRF token"}`, then `{"message":"Logged out"}`, then `{"error":"Not signed in"}`

> **Windows PowerShell users:** the single quotes in `-d '...'` and `VAR=value node ...` work in Git Bash. In PowerShell, use Git Bash or Postman, or set the port with `$env:PORT=3047; node server.js`. Restart the server to reset the balances.
