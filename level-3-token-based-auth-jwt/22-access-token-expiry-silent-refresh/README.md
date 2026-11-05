# 22. Access Token Expiry & Silent Refresh

## Notes

### What is silent refresh?

In topic 21 the access token expires every 15 minutes, and the client trades its refresh token for a new one. **Silent refresh** is doing that **automatically, in the background**, so the user never notices. No login screen, no failed button click, no "please try again".

> **One-line answer:** the frontend keeps the access token in memory, refreshes it **a little before it expires** (a timer), and if a request still comes back `401 token_expired`, it refreshes **once** and **retries** the request. All requests waiting at the same moment share **one** refresh call.

---

### Why does it matter?

Without silent refresh, a short-lived access token is a pain:

| Without silent refresh… | What the user sees |
|---|---|
| The token expires while the page is open | The next click fails with an error |
| The token expires while filling a long form | "Submit" fails and the form data may be lost 😡 |
| The page is reloaded | Logged out, because the token was only in memory |
| 5 requests fire at once with an expired token | 5 refresh calls. With rotation (topic 23) that looks like **token theft** and logs the user out |
| The refresh token itself is dead | An endless loop of refresh → 401 → refresh |

---

### Real-life example: a metro card 🚇

Priya uses the Delhi Metro every day.

1. Her **metro card** has a balance that runs out → the **access token expires**
2. She sets up **auto top-up**: when the balance gets low, the bank adds ₹500 **before** it hits zero → **proactive refresh** (a timer before expiry)
3. One day auto top-up was late and the gate says "low balance". She tops up at the machine **once** and taps again → **reactive refresh**: `401 token_expired` → refresh → retry
4. Her whole family taps through behind her on the same account. The machine tops up **once**, not five times → **single-flight**: many requests, one refresh
5. If her **bank account** is closed, top-up fails and she must go to the counter → **refresh fails → show the login page** (don't keep retrying)

---

### The flow, step by step

#### 📊 Diagrams

Open **[diagrams.html](diagrams.html)** in your browser (just double-click the file) to see:

- **Flow diagram**: what the client's `api()` wrapper does on every request
- **Data flow**: proactive timer, then 5 requests with an expired token sharing one refresh
- **Page reload**: how the login comes back after the in-memory token is gone

In short: `login → keep accessToken in memory + set a timer for (expiresIn - a bit) → timer fires → POST /auth/refresh → new token → new timer`. Safety net: `request → 401 token_expired → refresh (shared) → retry once`. Refresh fails → login page.

---

### Step 1: The server says when the token expires

```js
res.json({ accessToken, tokenType: "Bearer", expiresIn: 900 }); // seconds
```

The JWT also has an `exp` claim, so the client could decode it. Sending `expiresIn` is simpler and is what OAuth 2.0 does. The client **doesn't** need to trust it for security: the server checks `exp` itself on every request.

---

### Step 2: The server says **why** a request failed

```js
if (err.name === "TokenExpiredError") {
  res.set("WWW-Authenticate", 'Bearer error="invalid_token", error_description="The access token expired"');
  return res.status(401).json({ error: "Access token expired", code: "token_expired" });
}
res.status(401).json({ error: "Invalid access token", code: "invalid_token" });
```

| Answer | What the client should do |
|---|---|
| `401` + `code: "token_expired"` | Refresh, then retry |
| `401` + `code: "invalid_token"` (tampered, wrong signature) | **Don't** refresh. Something is wrong; log out |
| `403` | You're logged in but **not allowed** (Level 4). Refreshing won't help |

`WWW-Authenticate` is the standard header for this (RFC 6750). The JSON `code` is just easier to read in JavaScript.

---

### Step 3: Proactive refresh (a timer)

```js
function setToken({ accessToken: token, expiresIn }) {
  accessToken = token;                               // memory only, never localStorage (topic 25)
  clearTimeout(refreshTimer);
  const earlyMs = Math.min(60_000, expiresIn * 200); // 60 s early, or 20% early for tiny tokens
  refreshTimer = setTimeout(refresh, expiresIn * 1000 - earlyMs);
}
```

Refreshing **before** expiry means requests almost never hit a `401`. Refresh a bit **early** because of:

- **Clock skew**: the server's clock and the user's laptop clock are rarely identical (another reason to use `expiresIn`, which is relative, instead of comparing to `Date.now()`)
- **Network time**: a token that's valid when the request leaves may be expired when it arrives

⚠️ Timers aren't reliable on their own: a laptop that sleeps or a background tab that the browser throttles can fire the timer late. That's why you **also** need step 4.

---

### Step 4: Reactive refresh (401 → refresh → retry once)

```js
async function api(path) {
  const call = () => fetch(path, { headers: { Authorization: "Bearer " + accessToken } });
  let res = await call();
  if (res.status === 401 && (await res.clone().json()).code === "token_expired") {
    await refresh();
    res = await call(); // retry ONCE
  }
  return res;
}
```

Every API call goes through this one wrapper (with axios this is an **interceptor**). Rules:

| ✅ Do | ❌ Don't |
|---|---|
| Retry **once** | Loop until it works (endless refresh → 401 → refresh) |
| Refresh only on `token_expired` | Refresh on every `401` or on `403` |
| Not retry `/auth/refresh` itself through the wrapper | Let the refresh call trigger another refresh |
| On refresh failure, clear the token and show the login page | Keep the user on a broken page |

---

### Step 5: Single-flight: many requests, one refresh

```js
let refreshPromise = null;
function refresh() {
  if (!refreshPromise) {
    refreshPromise = fetch("/auth/refresh", { method: "POST" })
      .then(/* save the new token, or go to the login page */)
      .finally(() => { refreshPromise = null; });
  }
  return refreshPromise; // everyone waiting gets the SAME promise
}
```

A dashboard loads and fires 5 requests. The token has expired, so all 5 get `401`. Without this, you send **5** refresh calls. That's wasteful, and once refresh tokens **rotate** (topic 23), calls 2–5 use an already-used refresh token, which looks exactly like **theft** and logs the user out everywhere.

With single-flight, the first `401` starts the refresh. The other four `await` the **same promise**, then all five retry with the new token. The demo shows this: 5 × `401` → **1** refresh → 5 × `200`.

---

### Step 6: Page load restores the login

The access token lives only in a JavaScript variable, so a reload (or a new tab) loses it. That's on purpose (XSS can't steal it from `localStorage`, topic 25). On page load:

```js
try { await refresh(); showLoggedIn(); }     // the HttpOnly refresh cookie is still there
catch { showLoggedOut("Please log in"); }
```

The browser sends the refresh cookie by itself, the server returns a new access token, and the user is back in. If there's no valid cookie (logged out, expired), show the login page.

---

### 🤔 Tricky parts

**1. Several tabs.**
Each tab has its own memory and its own timer, so 3 open tabs = 3 refreshes. Fine without rotation. With rotation (topic 23), tabs can race. Fixes: a short grace period on the server, or one tab refreshes and shares the token with the others (`BroadcastChannel` or the Web Locks API).

**2. The user is idle for a week.**
Silent refresh only works while the **refresh token** is valid. After it expires, the next request fails to refresh → login page. That's the intended "you've been away too long" logout.

**3. Should an idle open tab keep refreshing forever?**
The timer keeps the user logged in as long as the tab is open. Banking apps instead log you out after N minutes of **no activity**: stop the timer when the user is idle and let the token expire.

**4. Retrying POSTs.**
Retrying a `GET` is always safe. A `POST` that got `401` was **rejected before it ran**, so retrying it is also safe. But never retry on network errors or `5xx` blindly: the order may have gone through (use idempotency keys, Level 7).

**5. Server-side clock tolerance.**
Libraries let the server accept a token a few seconds after `exp` (`jwt.verify(..., { clockTolerance: 5 })`). Keep it small: it's a fix for skew between servers, not a way to make tokens live longer.

**6. Mobile apps.**
Same logic, but the refresh token comes from the Keychain / Keystore and is sent in the request body. Refresh when the app comes back to the foreground, too.

---

### Common beginner mistakes

1. **Retrying in a loop.**
   Retry once. If the refresh fails, log out.

2. **Refreshing on every 401 (or 403).**
   Only `token_expired`. A tampered token or a missing permission won't be fixed by refreshing.

3. **No single-flight.**
   5 requests → 5 refreshes, and with rotation the user gets logged out for "theft".

4. **Only a timer, no 401 handling.**
   A sleeping laptop or throttled tab misses the timer. The next request fails.

5. **Only 401 handling, no timer.**
   Works, but every 15 minutes one request is slow (fail, refresh, retry). Fine for small apps, worse UX.

6. **Saving the access token in `localStorage` "so reloads work".**
   Use the refresh cookie on page load instead (step 6).

7. **Refreshing exactly at `exp`.**
   Clock skew and network time make the request arrive late. Refresh early.

8. **Routing `/auth/refresh` through the same retry wrapper.**
   A failed refresh triggers another refresh, forever.

9. **Not forgetting the token on refresh failure.**
   Clear it, stop the timer and show the login page.

---

### Interview questions

1. **What is silent refresh?**
   Getting a new access token in the background with the refresh token, before or right after the old one expires, so the user stays logged in without seeing anything.

2. **Proactive vs reactive refresh?**
   Proactive: a timer refreshes a bit before `exp`. Reactive: a request gets `401 token_expired`, the client refreshes and retries once. Use both: the timer for smooth UX, the 401 path as the safety net.

3. **How do you stop 10 parallel requests from causing 10 refreshes?**
   Keep the in-flight refresh promise in a variable. Every request that needs a new token awaits the same promise. Clear it when it settles.

4. **Why is that important with refresh token rotation?**
   With rotation each refresh token works once. Parallel refreshes reuse the same token, which the server sees as reuse = theft, and revokes everything.

5. **How does the client tell "expired" from "invalid"?**
   The server returns a specific code (`token_expired`) or the `WWW-Authenticate: Bearer error="invalid_token", error_description=...` header. Only expired tokens should trigger a refresh.

6. **The access token is in memory. How does a page reload keep the user logged in?**
   On load, the app calls `/auth/refresh`. The browser sends the `HttpOnly` refresh cookie automatically and gets a new access token.

7. **Why refresh before expiry and not exactly at it?**
   Clock skew between client and server, and network latency. A token that's valid when sent may be expired on arrival.

8. **What do you do when refresh fails?**
   Clear the in-memory token and timer, don't retry, and send the user to the login page.

---

### Quick recap

- Access token in **memory**; the server sends `expiresIn`
- **Proactive**: timer refreshes **early** (60 s or 20% before expiry)
- **Reactive**: `401 token_expired` → refresh → **retry once**
- **Single-flight**: all waiting requests share **one** refresh promise
- Expired (`token_expired`) ≠ invalid (`invalid_token`) ≠ forbidden (`403`). Only refresh on expired
- **Page load** → call `/auth/refresh` to restore the login from the `HttpOnly` cookie
- Refresh fails → clear everything → login page. No loops
- Next: rotation + reuse detection (topic 23), where single-flight becomes essential

## Code

The same **Express** + **`jsonwebtoken`** API as topic 21, plus a tiny **demo page** served at `/`. Silent refresh happens in the **frontend**, so the interesting code is the `<script>` inside `DEMO_PAGE` in server.js: the timer, the `api()` wrapper, single-flight `refresh()` and the page-load restore. Users and refresh tokens are kept in memory, so they disappear when you restart.

📄 **Full code: [server.js](server.js)**. Open it and read the comments, which follow the same steps as the notes above.

Install the dependencies once (from this folder), then start the server. `ACCESS_TTL_SECONDS=10` makes access tokens last only 10 seconds:

```bash
npm install
```

```bash
ACCESS_TTL_SECONDS=10 node server.js
```

> Port 3000 busy? Run it on another port: `ACCESS_TTL_SECONDS=10 PORT=3022 node server.js` (Git Bash), then use that port below. Open the page at `http://localhost:…`, not `127.0.0.1`, or the `Origin` check blocks its requests.

### Try it in the browser

Open **http://localhost:3000** (the email and password are filled in). The log at the bottom shows the newest line first.

✅ **Sign up, then Log in.** Wait about 8 seconds without clicking anything. The **timer** refreshes before the 10-second token expires:

```
⏰ timer: token expires soon, refreshing in the background
🔄 POST /auth/refresh (the browser sends the HttpOnly cookie by itself)
✅ new access token received
```

✅ **Reactive refresh + single-flight:** untick **Proactive refresh**, wait 11 seconds so the token expires, then click **Call /me 5 times at once**:

```
⌛ /me → 401 token_expired, refreshing and retrying      (×5)
🔄 POST /auth/refresh (the browser sends the HttpOnly cookie by itself)   ← only ONE
✅ new access token received
#1 /me → 200 {"email":"rahul@mail.com","accessTokenExpiresAt":"2026-11-05T02:04:28.000Z"}
...
#5 /me → 200 {...}
```

The terminal confirms it: one `🔄 refresh #2 for rahul@mail.com` line for all five requests.

✅ **Reload the page:** the token in memory is gone, but the refresh cookie brings the login back:

```
🔄 POST /auth/refresh (the browser sends the HttpOnly cookie by itself)
✅ new access token received
page load: login restored from the refresh cookie
```

✅ **Log out, then reload:** `page load: no valid refresh cookie, please log in`, and the login form is back.

### Try it with curl

`curl` doesn't refresh by itself, but you can see the two different `401` answers that the frontend relies on:

```bash
curl -X POST http://localhost:3000/auth/signup -H "Content-Type: application/json" -d '{"email":"rahul@mail.com","password":"correct horse battery"}'
```

```bash
curl -c jar.txt -X POST http://localhost:3000/auth/login -H "Content-Type: application/json" -d '{"email":"rahul@mail.com","password":"correct horse battery"}'
```
→ `{"accessToken":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...","tokenType":"Bearer","expiresIn":10}`. Copy it: `TOKEN=eyJ...`

⏰ **Wait 11 seconds**, then:

```bash
curl -i http://localhost:3000/me -H "Authorization: Bearer $TOKEN"
```
→
```
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer error="invalid_token", error_description="The access token expired"
{"error":"Access token expired","code":"token_expired"}
```
The frontend sees `token_expired` → refreshes and retries.

```bash
curl -i http://localhost:3000/me -H "Authorization: Bearer ${TOKEN}x"
```
→ `401 Unauthorized` with `{"error":"Invalid access token","code":"invalid_token"}`. The frontend **doesn't** refresh for this one.

```bash
curl -b jar.txt -X POST http://localhost:3000/auth/refresh
```
→ a new `{"accessToken":"eyJ...","tokenType":"Bearer","expiresIn":10}`, exactly what `refresh()` gets in the browser.

> **Windows PowerShell users:** the single quotes in the `-d '...'` part, `TOKEN=...` / `$TOKEN` and `VAR=value node ...` work in Git Bash. In PowerShell, use Git Bash, Postman, or `$env:ACCESS_TTL_SECONDS=10; node server.js`. The browser demo works the same everywhere.
