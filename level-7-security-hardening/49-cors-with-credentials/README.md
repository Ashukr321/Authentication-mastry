# 49. CORS with Credentials

## Notes

### What is CORS?

Browsers have a rule called the **same-origin policy**: JavaScript on `https://shop.com` may **send** requests to other origins, but it may **not read the responses**. **CORS (Cross-Origin Resource Sharing)** is how a server says "it's OK, let **this** other origin read my responses".

"**With credentials**" means the request carries the user's **cookies** (or HTTP auth). That's the dangerous case: a CORS mistake there lets another site read **the logged-in user's private data**, and often act as them.

> **One-line answer:** CORS is the server telling the browser which **other origins may read** its responses. With cookies, reply with **one exact allow-listed origin** + `Access-Control-Allow-Credentials: true` + `Vary: Origin`. Never reflect any Origin, never use prefix/suffix/regex checks, never allow `null`. CORS controls **reading**, not **sending**, so writes still need CSRF protection (topic 47).

---

### Why it matters

| Situation | What happens |
|---|---|
| Frontend `app.paisapay.in`, API `api.paisapay.in` | Different **origins**: the frontend needs CORS to read API responses |
| Frontend `paisapay-web.vercel.app`, API `api.paisapay.in` | Different **sites**: the cookie must be `SameSite=None; Secure`, so **SameSite gives no CSRF protection** any more |
| Developer sees a "CORS error" and copies the origin from the request into the response | **Every** website can now read your users' data with their cookies 😱 |
| `Access-Control-Allow-Origin: *` | Fine for public data (no cookies). The browser **refuses** it with credentials. |

CORS misconfigurations are a very common bug-bounty finding, because the "fix" for the error message is so often "allow everything".

---

### Real-life example: the bank's phone line ☎️

Rahul's bank in Chennai answers phone calls about his account.

1. Anyone can **call** the bank and ask "what's Rahul's balance?" → any page can **send** a request
2. The bank reads out the answer **only if** the caller ID is on Rahul's list of trusted numbers → `Access-Control-Allow-Origin`
3. Rahul's list: his own number and his wife Priya's → an **exact allow-list** of origins
4. A lazy clerk who answers **every caller whose number is shown on the screen** → **reflecting** any Origin
5. A clerk who trusts every number **starting with +91 98** → a **prefix check**; Vikram's number also starts with +91 98
6. A clerk who also answers **"Unknown number"** → allowing `Origin: null`
7. Even when the clerk refuses to **read out** the balance, a caller can still say "transfer ₹1000" → CORS blocks **reading**, not **sending**: writes need CSRF protection

---

### How it works, step by step

#### 📊 Diagrams

Open **[diagrams.html](diagrams.html)** in your browser (just double-click the file) to see:

- **Flow diagram**: how the server builds the CORS headers, and how the browser decides to show or hide the response
- **Data flow**: the real frontend reading the API, then Vikram's page against the safe and the broken API
- **Allow-list bugs**: which Origin checks let Vikram in

In short: `fetch(API, { credentials: "include" }) → browser sends cookie + Origin → server: is Origin in the allow-list? → yes: ACAO=<that origin> + ACAC=true + Vary: Origin → browser lets the page read it. No CORS headers → browser hides the response.`

#### Origin vs site (from topics 10 and 47)

| A | B | Same origin? | Same site? |
|---|---|---|---|
| `https://paisapay.in` | `https://paisapay.in/api` | ✅ | ✅ |
| `https://paisapay.in` | `https://api.paisapay.in` | ❌ (host differs) | ✅ |
| `http://localhost:3049` | `http://localhost:3050` | ❌ (port differs) | ✅ |
| `http://localhost:3049` | `http://127.0.0.1:3050` | ❌ | ❌ (this demo's frontend) |

CORS is about **origins**. `SameSite` cookies are about **sites**.

---

### Step 1: The browser sends `Origin`, the server answers with headers

```
GET /api/me                                   ← from the page at http://127.0.0.1:3050
Origin: http://127.0.0.1:3050
Cookie: sid=z3sT6K…
```

```
HTTP/1.1 200 OK
Access-Control-Allow-Origin: http://127.0.0.1:3050    ← exactly this origin may read it
Access-Control-Allow-Credentials: true                ← …even though cookies were sent
Vary: Origin                                          ← caches: the answer depends on Origin
{"email":"rahul@mail.com","phone":"+91 98xxxxxx21","balance":10000}
```

The frontend must opt in to sending cookies:

```js
fetch("https://api.paisapay.in/api/me", { credentials: "include" });  // axios: withCredentials: true
```

**Important:** the server **still sends the data** to a non-allowed origin. The browser receives it and then **hides it from the page**. CORS is enforced by the **browser**, not the server. curl, Postman or a server-side script ignore it completely (but they don't have the victim's cookie).

---

### Step 2: The rules for credentials

| Header | With credentials | Why |
|---|---|---|
| `Access-Control-Allow-Origin` | **One exact origin**, never `*` | The browser refuses `*` with credentials: "must not be the wildcard '*' when the request's credentials mode is 'include'" |
| `Access-Control-Allow-Credentials` | `true` | Without it, the page can't read a response to a request that carried cookies |
| `Vary: Origin` | Always, when the answer depends on Origin | Otherwise a CDN may cache "ACAO: app" and serve it to other origins, or the reverse |
| Allow-list | A `Set` of full origins: scheme + host + port | `new Set(["https://app.paisapay.in"])` and `.has(origin)` |

```js
const ALLOWED_ORIGINS = new Set(["https://app.paisapay.in"]);
res.vary("Origin");
if (origin && ALLOWED_ORIGINS.has(origin)) {
  res.set("Access-Control-Allow-Origin", origin);
  res.set("Access-Control-Allow-Credentials", "true");
}
```

Using the `cors` npm package, the same thing is:

```js
app.use(cors({ origin: ["https://app.paisapay.in"], credentials: true }));   // ✅ an array of exact origins
app.use(cors({ origin: true, credentials: true }));                          // ❌ origin: true = reflect anything
```

---

### Step 3: Preflight (`OPTIONS`) for non-simple requests

A **simple** request (GET, or a POST with a form/text content type and no custom headers) is sent straight away. Anything else (a JSON body, `PUT`/`DELETE`, an `Authorization` or `X-CSRF-Token` header) makes the browser **ask first**:

```
OPTIONS /api/transfer
Origin: http://127.0.0.1:3050
Access-Control-Request-Method: POST
Access-Control-Request-Headers: content-type
```
```
HTTP/1.1 204 No Content
Access-Control-Allow-Origin: http://127.0.0.1:3050
Access-Control-Allow-Credentials: true
Access-Control-Allow-Methods: GET, POST
Access-Control-Allow-Headers: Content-Type
Access-Control-Max-Age: 600
```

If the preflight answer has no matching CORS headers, the browser **never sends** the real request. That's what stopped Vikram's `POST /api/transfer` in our test: "Response to preflight request doesn't pass access control check".

---

### Step 4: CORS is not CSRF protection

CORS decides who can **read**. A simple request (a form POST, an `<img>`) is **sent** whether or not CORS allows it, with cookies attached (if `SameSite` allows). So:

| ✅ Do | ❌ Don't |
|---|---|
| Check `Origin` on POST/PUT/PATCH/DELETE against the same allow-list (topic 47) | Think "CORS blocks other origins, so I'm safe from CSRF" |
| Require `Content-Type: application/json` on JSON endpoints (a form can't send it without a preflight) | Parse JSON from any content type (the `text/plain` trick, topic 47) |
| Keep CSRF tokens for cookie-based apps, especially with `SameSite=None` | Drop CSRF protection because "the API is JSON" |

---

### Step 5: The broken allow-lists (all real-world bugs)

| Check | Code | Who gets in |
|---|---|---|
| ❌ **Reflect anything** | `ACAO = req.headers.origin` / `cors({ origin: true })` | **Every** website |
| ❌ **Prefix** | `origin.startsWith("https://paisapay.in")` | `https://paisapay.in.evil.com` (demo: `http://127.0.0.1:3051` passes `startsWith("http://127.0.0.1")`) |
| ❌ **Suffix** | `origin.endsWith("paisapay.in")` | `https://evilpaisapay.in` |
| ❌ **Unescaped regex** | `/^https:\/\/app.paisapay.in$/` | `https://appXpaisapay.in` (`.` matches anything) |
| ❌ **`includes`** | `origin.includes("paisapay.in")` | `https://paisapay.in.evil.com`, `https://evil.com/?paisapay.in`… |
| ❌ **`null`** | `allowed.includes(origin) \|\| origin === "null"` | Any site, via a sandboxed `<iframe>` (its Origin is `null`) |
| ❌ **All subdomains** | `/^https:\/\/[a-z]+\.paisapay\.in$/` | Any subdomain with an XSS (topic 48) or a takeover (a dangling DNS record) |
| ✅ **Exact** | `ALLOWED_ORIGINS.has(origin)` | Only the origins you listed |

---

### 🤔 Tricky parts

**1. `SameSite=None` is the price of a cross-site frontend.** If the frontend and API are on different **sites**, the cookie must be `SameSite=None; Secure` to be sent at all. That switches off the browser's CSRF help (topic 47) and makes CORS bugs exploitable from **any** site. If you can, put the API on the same site (`api.paisapay.in` + `app.paisapay.in`), or call it through your own backend (the BFF pattern, topic 25).

**2. `*` is fine for truly public data.** A public price list, fonts, open data: `Access-Control-Allow-Origin: *` **without** credentials. The browser then sends no cookies and the response contains nothing private.

**3. XSS on an allowed origin = full access.** If `app.paisapay.in` is allowed and has an XSS, the attacker's script runs **on an allowed origin** (topic 48). Keep the allow-list short.

**4. CORS errors are browser errors.** The server log says `200 OK`; the browser console says "blocked by CORS policy". Debug with the **Network** tab: look at the `OPTIONS` request and the response headers.

**5. Third-party cookie blocking.** Safari blocks, and Firefox partitions, `SameSite=None` cookies in cross-site requests (and so do private windows), so a cross-site frontend + cookie setup may simply not work for some users. Another reason to prefer same-site or a BFF.

**6. Local network access.** In our test, the browser refused **every** request from a sandboxed iframe to a localhost address, even to Vikram's own server, so the `null` case is shown with curl. Browsers increasingly protect `localhost` and private IPs from pages on other addresses (Private/Local Network Access). Don't rely on it for your public API.

---

### Common beginner mistakes

1. **Reflecting the request's `Origin`** (or `cors({ origin: true, credentials: true })`) to make the error go away.
2. **`Access-Control-Allow-Origin: *` with credentials**, then "fixing" the browser error with mistake 1.
3. **Prefix, suffix, `includes()` or unescaped regex** origin checks.
4. **Allowing `null`** for "local testing".
5. **Forgetting `Vary: Origin`** on dynamic CORS responses (cache poisoning).
6. **Thinking CORS protects the server.** It protects the **user's data in the browser**. curl ignores it.
7. **Thinking CORS stops CSRF.** Simple requests are still sent.
8. **Allowing every subdomain** when one of them is an old, unpatched site.
9. **Putting `http://localhost:3000` in the production allow-list.** Any page served from that port on the user's machine is now trusted.
10. **Copying CORS settings to every route.** Public endpoints and private ones need different policies.

---

### Interview questions

1. **What is CORS and why does it exist?**
   The same-origin policy stops scripts from reading responses from other origins. CORS lets a server relax that for specific origins with `Access-Control-*` headers. It exists so legitimate cross-origin frontends can work without opening up every site.

2. **Can you use `Access-Control-Allow-Origin: *` with cookies?**
   No. The browser rejects it when credentials are included. You must return the single exact origin and `Access-Control-Allow-Credentials: true`.

3. **Why is reflecting the Origin header dangerous?**
   Any website can then read authenticated responses: the victim's browser sends the cookie, the server allows the attacker's origin, and the attacker's script reads the private data (and with preflight passing, can make writes too).

4. **What is a preflight request?**
   An `OPTIONS` request the browser sends before a non-simple request (JSON body, PUT/DELETE, custom headers) to ask whether the method and headers are allowed for that origin. If not, the real request isn't sent.

5. **Does CORS protect against CSRF?**
   No. CORS controls reading responses. Simple requests like form POSTs are still sent with cookies. You need SameSite cookies, Origin checks and CSRF tokens.

6. **Why `Vary: Origin`?**
   The response headers depend on the Origin. Without `Vary`, a shared cache could serve a response with one origin's `Access-Control-Allow-Origin` to another origin.

7. **How would you configure CORS for an SPA on `app.example.com` and an API on `api.example.com`?**
   Allow-list exactly `https://app.example.com`, `Allow-Credentials: true`, `Vary: Origin`, allow only the needed methods and headers, cookie `HttpOnly; Secure; SameSite=Lax` (same site, so Lax works), plus Origin checks on writes.

8. **What's dangerous about allowing `null`?**
   Sandboxed iframes, `data:` URLs and some redirects send `Origin: null`. Any attacker can create a sandboxed iframe, so allowing `null` allows everyone.

---

### Quick recap

- Same-origin policy: other origins can **send**, not **read**. CORS = the server's **read permission**
- With cookies: **exact origin** in `Access-Control-Allow-Origin`, `Allow-Credentials: true`, **`Vary: Origin`**
- **Never** reflect, prefix/suffix/regex/`includes` match, allow `null`, or use `*` with credentials
- Preflight `OPTIONS` guards JSON/PUT/DELETE: allow only needed **methods and headers**
- CORS ≠ CSRF protection: **Origin check + CSRF token** on writes (topic 47)
- Cross-site frontend ⇒ `SameSite=None; Secure` ⇒ no SameSite help; prefer same-site or a BFF
- Enforced by the **browser**: curl ignores it, an XSS on an allowed origin defeats it (topic 48)

## Code

A small **Express** demo with **three servers in one file**, on three origins:

| Server | Origin | Role |
|---|---|---|
| **PaisaPay API** | `http://localhost:PORT` | Login page, session cookie (`HttpOnly; Secure; SameSite=None`), `/me` and `/transfer` under several CORS policies |
| **PaisaPay Web** | `http://127.0.0.1:PORT+1` | The **real** frontend, on another site. It's in the allow-list. |
| **Vikram's page** | `http://127.0.0.1:PORT+2` | The attacker. Not in the allow-list. |

The API mounts the same two endpoints under each policy, so you can compare them:

| Path prefix | CORS policy |
|---|---|
| `/api` | ✅ exact allow-list (`Set.has`) |
| `/vulnerable/reflect` | ❌ reflects any Origin |
| `/vulnerable/prefix` | ❌ `origin.startsWith("http://127.0.0.1")` |
| `/vulnerable/null` | ❌ allow-list **or** `null` |
| `/wildcard/me` | 🚫 `*` with credentials: the browser refuses it |

The CORS middleware is about 25 lines of plain Express (no `cors` package), so you can see every header.

📄 **Full code: [server.js](server.js)**. Open it and read the comments, which follow the same steps as the notes above.

Install Express once (from this folder), then start the servers:

```bash
npm install
```

```bash
node server.js
```

> Port 3000 busy? Run it on another port: `PORT=3049 node server.js` (Git Bash). The frontend then runs on 3050 and Vikram's page on 3051. The outputs below were recorded on port 3049.

### Try it in the browser

1. Open **http://localhost:3049** and log in as **rahul@mail.com** / **chai-and-code-42**.
2. Open the real frontend, **http://127.0.0.1:3050**. It reads the API with Rahul's cookie:
   ```
   GET /api/me → { "email": "rahul@mail.com", "phone": "+91 98xxxxxx21", "balance": 9900 }
   ```
   - **Send ₹100 to Priya** → `{"message":"Sent ₹100 to priya@mail.com","balance":9800}` (preflight passed, then the POST)
   - **Try /wildcard/me** → `Failed to fetch`, and the console says: *The value of the 'Access-Control-Allow-Origin' header in the response must not be the wildcard '\*' when the request's credentials mode is 'include'.*
3. Open Vikram's page, **http://127.0.0.1:3051**. Results from our test run:

| Attack | Result |
|---|---|
| Read `/api/me` | 🛡️ `Failed to fetch` (console: *No 'Access-Control-Allow-Origin' header is present*) |
| Read `/vulnerable/reflect/me` | 😱 `{"email":"rahul@mail.com","phone":"+91 98xxxxxx21","balance":9800}` |
| Read `/vulnerable/prefix/me` | 😱 same data |
| **Take ₹1000 via /vulnerable/reflect/transfer** | 😱 `{"message":"Sent ₹1000 to vikram@mail.com","balance":8800}` |
| **Take ₹1000 via /api/transfer** | 🛡️ `Failed to fetch` (console: *Response to preflight request doesn't pass access control check*) |

The servers' terminal shows what Vikram collected and every money move:

```
🕵️  Stolen via /vulnerable/reflect/me: {"email":"rahul@mail.com","phone":"+91 98xxxxxx21","balance":9800}
🕵️  Stolen via /vulnerable/prefix/me: {"email":"rahul@mail.com","phone":"+91 98xxxxxx21","balance":9800}
💸 ₹1000 rahul@mail.com → vikram@mail.com (via /vulnerable/reflect/transfer, Origin: http://127.0.0.1:3051)
```

### Try it with curl (Git Bash)

curl **ignores CORS** (only browsers enforce it), so here we look at the **headers** the server sends. We add `Origin` ourselves, like a browser would.

```bash
API=http://localhost:3049
APP=http://127.0.0.1:3050
EVIL=http://127.0.0.1:3051
```

✅ **① Log in.** Note `SameSite=None` and `Secure`: needed because the frontend is on another site.

```bash
curl -s -i -c rahul.jar $API/login -H "Content-Type: application/json" -d '{"email":"rahul@mail.com","password":"chai-and-code-42"}'
```
→
```
HTTP/1.1 200 OK
Set-Cookie: sid=z3sT6KxYzh3XVB7_2cIgeCsp9xefo9TTv4SFZZhBM20; Max-Age=604800; Path=/; Expires=...; HttpOnly; Secure; SameSite=None
{"message":"Logged in as rahul@mail.com"}
```

✅ **② The real frontend's origin gets CORS headers:**

```bash
curl -s -i -b rahul.jar $API/api/me -H "Origin: $APP"
```
→
```
HTTP/1.1 200 OK
Vary: Origin
Access-Control-Allow-Origin: http://127.0.0.1:3050
Access-Control-Allow-Credentials: true
{"email":"rahul@mail.com","phone":"+91 98xxxxxx21","balance":10000}
```

🛡️ **③ Vikram's origin gets none.** The data is still in the response (curl shows it), but a browser would **hide** it from his page.

```bash
curl -s -i -b rahul.jar $API/api/me -H "Origin: $EVIL"
```
→
```
HTTP/1.1 200 OK
Vary: Origin
{"email":"rahul@mail.com","phone":"+91 98xxxxxx21","balance":10000}
```

❌ **④ The broken policies say yes to Vikram:**

```bash
curl -s -i -b rahul.jar $API/vulnerable/reflect/me -H "Origin: http://evil.example" | grep -i "^access-control"
curl -s -i -b rahul.jar $API/vulnerable/prefix/me -H "Origin: $EVIL" | grep -i "^access-control"
curl -s -i -b rahul.jar $API/vulnerable/null/me -H "Origin: null" | grep -i "^access-control"
```
→
```
Access-Control-Allow-Origin: http://evil.example
Access-Control-Allow-Credentials: true
Access-Control-Allow-Origin: http://127.0.0.1:3051
Access-Control-Allow-Credentials: true
Access-Control-Allow-Origin: null
Access-Control-Allow-Credentials: true
```

🚫 **⑤ `*` with credentials:** the server sends it, the browser rejects it (step 2 above).

```bash
curl -s -i -b rahul.jar $API/wildcard/me -H "Origin: $EVIL" | grep -i "^access-control"
```
→
```
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true
```

✅ **⑥ Preflight from the real frontend:**

```bash
curl -s -i -X OPTIONS $API/api/transfer -H "Origin: $APP" -H "Access-Control-Request-Method: POST" -H "Access-Control-Request-Headers: content-type"
```
→
```
HTTP/1.1 204 No Content
Vary: Origin
Access-Control-Allow-Origin: http://127.0.0.1:3050
Access-Control-Allow-Credentials: true
Access-Control-Allow-Methods: GET, POST
Access-Control-Allow-Headers: Content-Type
Access-Control-Max-Age: 600
```

🛡️ **⑦ Preflight from Vikram:** `204` with no CORS headers, so the browser never sends the POST.

```bash
curl -s -i -X OPTIONS $API/api/transfer -H "Origin: $EVIL" -H "Access-Control-Request-Method: POST" -H "Access-Control-Request-Headers: content-type"
```
→
```
HTTP/1.1 204 No Content
Vary: Origin
```

🛡️ **⑧ Writes check Origin too** (CORS doesn't stop requests from being **sent**):

```bash
curl -s -b rahul.jar $API/api/transfer -H "Origin: $APP" -H "Content-Type: application/json" -d '{"to":"priya@mail.com","amount":100}'
curl -s -b rahul.jar $API/api/transfer -H "Origin: $EVIL" -H "Content-Type: application/json" -d '{"to":"vikram@mail.com","amount":1000}'
```
→ `{"message":"Sent ₹100 to priya@mail.com","balance":9900}`, then `{"error":"Origin http://127.0.0.1:3051 is not allowed"}` (403)

🛡️ **⑨ A plain form POST can't send JSON**, so the transfer endpoints refuse it, even the broken ones:

```bash
curl -s -b rahul.jar $API/vulnerable/reflect/transfer -d "to=vikram@mail.com&amount=1000"
```
→ `{"error":"Send JSON"}` (415)

> **Windows PowerShell users:** the single quotes in `-d '...'` and `VAR=value node ...` work in Git Bash. In PowerShell, use Git Bash or Postman, or set the port with `$env:PORT=3049; node server.js`. Restart the server to reset the balances.
