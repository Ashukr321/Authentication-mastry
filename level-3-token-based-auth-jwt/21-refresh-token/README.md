# 21. Refresh Token

## Notes

### What is a refresh token?

In topic 20 we gave the user an **access token**: a JWT that proves "I am Rahul" on every request. It must be **short-lived** (5–15 minutes), because a stolen JWT can't be cancelled before it expires.

But nobody wants to type their password every 15 minutes. So at login the server hands out a **second** token: a long-lived **refresh token**. Its only job is to get a **new access token** when the old one expires, without asking for the password again.

> **One-line answer:** a refresh token is a long-lived, random, server-stored credential that is only ever sent to one endpoint (`POST /auth/refresh`) to get a new short-lived access token. Short access token = small damage if stolen. Long refresh token = the user stays logged in, and the server keeps a place to say "no".

---

### Why does it matter?

With only one token, you have to pick a bad trade-off:

| Only an access token that is… | What happens |
|---|---|
| **Short** (15 minutes) | The user is logged out every 15 minutes. Terrible UX |
| **Long** (30 days) | A stolen token works for 30 days and you **can't revoke it** (it's stateless, topic 19) |
| Long + checked against a DB on every request | Works, but now it's just a session (topic 09) with extra steps, and you've lost the "no DB lookup" benefit |

A **pair** of tokens gets the best of both:

| | Access token (topic 20) | Refresh token (this topic) |
|---|---|---|
| Lives | **Minutes** (15 min) | **Days** (7–30 days) |
| Sent to | **Every** API request | **Only** `POST /auth/refresh` |
| Format | JWT (signed claims) | Random string (opaque) |
| Checked by | Signature only, **no DB** | **Database lookup** |
| Where (browser) | Memory (a JS variable) | `HttpOnly` cookie, `Path=/auth` |
| Can be revoked? | ❌ Not really, it just expires | ✅ Yes, delete the row |
| If stolen | Works for at most 15 minutes | Works until revoked/expired (topic 23 adds theft detection) |

---

### Real-life example: a hotel stay 🏨

Rahul checks into a hotel in Goa for 5 days.

1. At the **front desk** he shows his Aadhaar card once → **login with the password**
2. He gets a **room key card** that opens his room, the gym and the pool. The key card **stops working at midnight** → **access token**: used everywhere, short-lived, checked by the door lock alone (no call to the front desk = no DB lookup)
3. He also gets a **booking slip** for 5 days. It doesn't open any door. He only shows it **at the front desk** to get a fresh key card each morning → **refresh token**: used in one place only
4. The front desk **checks the booking system** every time: "Is the booking still active? Did he check out? Did he not pay ₹4,500?" → **refresh = the one place the server can say no**
5. Rahul checks out → the booking is **cancelled in the system**. Tonight's key card still opens the door until midnight, but tomorrow the front desk won't give him a new one → **logout deletes the refresh token; the access token dies on its own**

---

### The flow, step by step

#### 📊 Diagrams

Open **[diagrams.html](diagrams.html)** in your browser (just double-click the file) to see:

- **Flow diagram**: what `POST /auth/refresh` checks before giving a new access token
- **Data flow**: login → use the access token → it expires → refresh → logout
- **Access vs refresh**: what each token is for

In short: `login (password) → access token (15 min, in the body) + refresh token (7 days, HttpOnly cookie) → call APIs with the access token → 401 token_expired → POST /auth/refresh → new access token → … → logout deletes the refresh token`.

---

### Step 1: Login gives you a pair

```js
issueRefreshToken(res, user);    // long-lived, random, in an HttpOnly cookie
res.json({ accessToken: issueAccessToken(user), tokenType: "Bearer", expiresIn: 900 });
```

- The password is checked **once**, here. After this, the client never sends it again.
- The **access token** goes in the response **body**. The frontend keeps it in memory and sends `Authorization: Bearer …` (topic 19).
- The **refresh token** goes in a **cookie** the frontend's JavaScript can't read.

---

### Step 2: What a refresh token looks like and how it's stored

```js
const refreshToken = crypto.randomBytes(32).toString("hex");            // 64 random hex chars
refreshTokens.set(sha256(refreshToken), { userId, expiresAt: now + 7 days });
res.cookie("refreshToken", refreshToken, { httpOnly: true, sameSite: "strict", path: "/auth", maxAge: 7 days });
```

**Why a random string and not another JWT?** The refresh token is only ever checked by **our** server, against **our** database. It doesn't need claims or a signature; it needs to be **unguessable** and **revocable**. Many apps do use a JWT as a refresh token, and that's fine too, but you still need a database row to revoke it, so the JWT part adds little.

**Why store only the hash?** Same reason as passwords and reset tokens (topic 13): if the database leaks, the attacker gets hashes they can't send. SHA-256 is enough here because the token is already 256 random bits (no need for slow scrypt).

**Why those cookie flags?**

| Flag | Why |
|---|---|
| `HttpOnly` | JavaScript (and an XSS attack) can't read it |
| `Secure` (production) | Only over HTTPS |
| `SameSite=Strict` | Not sent with requests started by other sites (CSRF, topic 10) |
| `Path=/auth` | Sent **only** to `/auth/*`, not to every API call. Less exposure, smaller logs |
| `Max-Age=604800` | 7 days. The server **also** checks `expiresAt`, never trust the browser |

| ✅ Do | ❌ Don't |
|---|---|
| `crypto.randomBytes(32)` | `Math.random()`, user ID, timestamp |
| Store `sha256(token)` + `userId` + `expiresAt` | Store the token in plain text |
| `HttpOnly` cookie, narrow `Path` | Put the refresh token in `localStorage` (topic 25) |
| Give it an **absolute** expiry | Refresh tokens that never expire |

📱 **Mobile apps** have no cookies to lean on, so they get the refresh token in the response body and keep it in the **Keychain / Keystore**, then send it in the body of `/auth/refresh`.

---

### Step 3: The refresh endpoint

```http
POST /auth/refresh
Cookie: refreshToken=e5bf…e6d9
```

The server:

1. Reads the cookie. Missing or the wrong shape → `401`, please log in
2. Looks up `sha256(token)` in the database
3. Not found, **expired**, or the **user no longer exists / is banned / deleted** (topic 17) → delete the row, clear the cookie, `401`
4. Otherwise → sign a **new access token** and return it

Step 3 is the important one: **this is the one place a JWT system goes back to the database.** Every 15 minutes, each client has to come here, and the server gets a chance to say "no" (banned user, password changed, logged out). That's how JWT apps get **revocation** without a DB lookup on every request.

How does the client know when to refresh? When an API answers:

```json
401 { "error": "Access token expired", "code": "token_expired" }
```

The client calls `/auth/refresh` and retries the request. Doing this automatically (and before expiry) is **silent refresh**, topic 22.

---

### Step 4: Logout

```js
refreshTokens.delete(sha256(refreshToken)); // on the server
res.clearCookie("refreshToken", { path: "/auth", ... });
```

- Logout deletes the refresh token **on the server**. Clearing the cookie alone isn't enough: a copied token would still work.
- The **access token can't be deleted**. It keeps working until it expires (the demo shows this). That's the whole reason it must be **short**. Ways to kill it sooner are topic 24.
- The frontend should also throw away its in-memory access token.

---

### 🤔 Tricky parts

**1. The refresh token is now the "real" login.**
Anyone who has it can make access tokens for 7 days. So protect it **more** than the access token: `HttpOnly` cookie, hashed in the DB, narrow path. This demo reuses the same refresh token until it expires. Real apps **rotate** it on every use and detect a reused old one (that's topic 23, and the same idea as "remember me" in topic 15).

**2. Absolute vs sliding expiry.**
If every refresh gave a brand-new 7-day refresh token, an active user would stay logged in forever. Decide on purpose: many apps use a **sliding** window (7 days of inactivity) **plus** an absolute cap (e.g. 90 days, then type the password again).

**3. Does refreshing need the old access token?**
No. The refresh token alone is enough. Don't require a valid access token (it's expired, that's the point), and don't put user data in the refresh request.

**4. "Stateless" JWT, but a refresh table?**
Yes. The access token is stateless; the refresh token is **stateful on purpose**. You get a DB lookup every 15 minutes per user instead of on every request.

**5. Changing the password or banning a user.**
Delete **all** refresh tokens of that user. Within 15 minutes (one access token lifetime) they're out everywhere.

**6. CSRF on `/auth/refresh`?**
The cookie is sent automatically, so a malicious site could trigger a refresh. But it can't **read** the response (CORS blocks it), so it can't get the new access token. `SameSite=Strict` and the `Origin` check close the door anyway.

---

### Common beginner mistakes

1. **Making the access token long-lived "because refreshing is annoying".**
   Then you don't need a refresh token, and you can't revoke anything. Keep it 5–15 minutes.

2. **Sending the refresh token on every request.**
   It should go to **one** endpoint only. Use `Path=/auth` (or send it only from the refresh call on mobile).

3. **Storing the refresh token in `localStorage`.**
   Any XSS can read it and stay logged in for days. Use an `HttpOnly` cookie (topic 25).

4. **Storing it in plain text in the database.**
   Store `sha256(token)`.

5. **Not checking the user on refresh.**
   A deleted or banned user keeps getting access tokens. Check the user every time.

6. **Logout that only clears the cookie.**
   Delete the row on the server.

7. **Refresh tokens that never expire.**
   Give them an absolute limit.

8. **Using the same secret / same format for both tokens.**
   If a refresh token is a JWT signed with the access secret, a refresh token might be accepted as an access token. Use different secrets or a `typ` claim (topic 27). An opaque random refresh token avoids this completely.

9. **Not deleting refresh tokens on password change/reset (topics 13, 14).**
   The attacker's device keeps refreshing.

---

### Interview questions

1. **Why do we need refresh tokens?**
   Access tokens are stateless and can't be revoked, so they must be short-lived. A refresh token lets the client get new access tokens without the password, and gives the server a regular checkpoint where it can refuse (logout, ban, password change).

2. **Access token vs refresh token?**
   Access: short-lived (minutes), sent on every request, verified by signature only. Refresh: long-lived (days), sent only to the refresh endpoint, checked against the database, revocable.

3. **Where should you store the refresh token in a browser?**
   In an `HttpOnly`, `Secure`, `SameSite=Strict` cookie with a narrow `Path` like `/auth`. Not in `localStorage`. The access token stays in memory.

4. **Should a refresh token be a JWT?**
   It can be, but it doesn't need to be. It must be revocable, so you need a DB row anyway. An opaque random string, stored as a hash, is simpler and can't be confused with an access token.

5. **What happens on logout?**
   The server deletes the refresh token and clears the cookie. The access token keeps working until it expires, which is why it's short (or use a deny-list, topic 24).

6. **How do you revoke a user's access immediately?**
   Delete all their refresh tokens. They lose access within one access token lifetime. For "right now", also deny-list the access token's `jti` or bump a token version (topic 24).

7. **What if a refresh token is stolen?**
   The attacker can mint access tokens until it expires or is revoked. Mitigations: `HttpOnly` cookie, rotation on every use with reuse detection (topic 23), binding to a device, short absolute lifetimes.

8. **How does the client know it's time to refresh?**
   The API answers `401` with a code like `token_expired`, or the client reads `expiresIn` / `exp` and refreshes a little before expiry (topic 22).

---

### Quick recap

- Login gives a **pair**: short **access token** (JWT, body) + long **refresh token** (random, `HttpOnly` cookie)
- The access token goes to **every** API. The refresh token goes **only** to `POST /auth/refresh`
- Store `sha256(refreshToken)` + `userId` + `expiresAt`. Never the token itself
- Refresh = **DB lookup**: token valid, not expired, user still allowed → new access token
- Logout deletes the refresh token **on the server**. The access token dies on its own (keep it short!)
- Password change / ban → delete **all** refresh tokens of the user
- Next: silent refresh (22), rotation + reuse detection (23), revocation (24), storage (25)

## Code

A small **Express** API with **`jsonwebtoken`** (plus Node's built-in `crypto`): log in to get an access token and a refresh token cookie, call a protected route, let the access token expire, refresh it, and log out. Users and refresh tokens are kept in memory, so they disappear when you restart.

📄 **Full code: [server.js](server.js)**. Open it and read the comments, which follow the same steps as the notes above.

Install the dependencies once (from this folder), then start the server. `ACCESS_TTL_SECONDS=5` makes access tokens last only 5 seconds, so you can watch them expire:

```bash
npm install
```

```bash
ACCESS_TTL_SECONDS=5 node server.js
```

> Port 3000 busy? Run it on another port: `ACCESS_TTL_SECONDS=5 PORT=3021 node server.js` (Git Bash), then use that port in the commands below.

### Try it

`-c jar.txt` saves the cookies a "browser" gets, `-b jar.txt` sends them back.

✅ **Sign up:**

```bash
curl -X POST http://localhost:3000/auth/signup -H "Content-Type: application/json" -d '{"email":"rahul@mail.com","password":"correct horse battery"}'
```
→ `{"id":"85338be2-7467-437e-a75c-f92553533e46","email":"rahul@mail.com"}`

✅ **Log in:** the access token comes in the body, the refresh token in a cookie.

```bash
curl -i -c jar.txt -X POST http://localhost:3000/auth/login -H "Content-Type: application/json" -d '{"email":"rahul@mail.com","password":"correct horse battery"}'
```
→
```
Set-Cookie: refreshToken=e5bff11b5815f937...0e6d9; Max-Age=604800; Path=/auth; Expires=...; HttpOnly; SameSite=Strict
{"accessToken":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOi...","tokenType":"Bearer","expiresIn":5}
```

Copy the `accessToken` value into a variable (Git Bash):

```bash
TOKEN=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

✅ **Call a protected route with the access token:**

```bash
curl http://localhost:3000/me -H "Authorization: Bearer $TOKEN"
```
→ `{"id":"85338be2-...","email":"rahul@mail.com","accessTokenExpiresAt":"2026-11-05T01:58:17.000Z"}`

⏰ **Wait 6 seconds**, then try again:

```bash
curl -i http://localhost:3000/me -H "Authorization: Bearer $TOKEN"
```
→ `401 Unauthorized` with `{"error":"Access token expired","code":"token_expired"}`

✅ **Refresh:** no password, just the cookie.

```bash
curl -i -b jar.txt -X POST http://localhost:3000/auth/refresh
```
→ `200 OK` with `{"accessToken":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOi...","tokenType":"Bearer","expiresIn":5}`. Put the new value in `TOKEN` and `/me` works again.

❌ **Refresh without the cookie:**

```bash
curl -i -X POST http://localhost:3000/auth/refresh
```
→ `401 Unauthorized` with `{"error":"Missing refresh token, please log in"}`

❌ **Refresh triggered by another site:**

```bash
curl -i -b jar.txt -X POST http://localhost:3000/auth/refresh -H "Origin: https://evil.example"
```
→ `403 Forbidden` with `{"error":"Request from another site was blocked"}`

✅ **Log out:** the refresh token is deleted on the server and the cookie is cleared.

```bash
cp jar.txt stolen.txt
```

```bash
curl -i -b jar.txt -c jar.txt -X POST http://localhost:3000/auth/logout
```
→
```
Set-Cookie: refreshToken=; Path=/auth; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; SameSite=Strict
{"message":"Logged out. This device can't get new access tokens anymore."}
```

⚠️ **The access token still works until it expires** (call `/me` right after logout, within 5 seconds):

```bash
curl http://localhost:3000/me -H "Authorization: Bearer $TOKEN"
```
→ `{"id":"85338be2-...","email":"rahul@mail.com",...}`. This is why access tokens must be short (topic 24).

❌ **A saved copy of the refresh token is dead too:**

```bash
curl -i -b stolen.txt -X POST http://localhost:3000/auth/refresh
```
→ `401 Unauthorized` with `{"error":"Refresh token is invalid or expired, please log in"}`

❌ **A tampered access token:** add one character to the end of `$TOKEN`.

```bash
curl -i http://localhost:3000/me -H "Authorization: Bearer ${TOKEN}x"
```
→ `401 Unauthorized` with `{"error":"Invalid access token"}`

> **Windows PowerShell users:** the single quotes in the `-d '...'` part, `TOKEN=...` / `$TOKEN` and `VAR=value node ...` work in Git Bash. In PowerShell, use Git Bash, Postman, or `$env:ACCESS_TTL_SECONDS=5; node server.js` and `$TOKEN="eyJ..."`.
