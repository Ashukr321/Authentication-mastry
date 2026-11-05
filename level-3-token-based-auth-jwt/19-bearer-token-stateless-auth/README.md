# 19. Stateless Auth with Bearer Token

## Notes

### What is stateless auth with a bearer token?

In topic 09 (sessions), the server **remembers** every logged-in user in a session store, and the browser only holds a random ID.

**Stateless auth** flips that around: after login, the server gives the client a **signed token** (a JWT, topic 18) that already says *"this is Rahul, valid until 10:45"*. The client sends it back on every request in a header:

```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1XzEi...
```

The server **stores nothing**. It just checks the **signature** with its secret key. If the signature is right and the token hasn't expired, it believes what the token says.

**Bearer** means *"whoever holds (bears) this token gets in"*, like cash. No ID check, no password: the token **is** the proof.

> **One-line answer:** the server signs a token at login and keeps no session; the client sends `Authorization: Bearer <token>` on every request, and any server with the key can verify the signature and expiry without a database lookup, which scales easily but means a token can't be taken back before it expires.

---

### Why does it matter?

Sessions work great for one website on one server. They hurt when the app grows:

| Problem with server-side sessions | How a bearer token helps |
|---|---|
| Every request needs a session-store lookup (Redis/DB) | Verifying a signature is just maths in memory, no network call |
| 10 servers must share one session store | Any server with the key can check the token on its own |
| Mobile apps and other APIs don't handle cookies well | A header works the same from a browser, an Android app, `curl`, or another backend |
| Microservices: each service would have to call the auth service | Each service verifies the token itself |
| Cookies are sent automatically → CSRF risk (Level 7) | A header is only sent when your code adds it → no CSRF |

And the price you pay:

| Downside | Why |
|---|---|
| **Can't log a token out** | The server keeps no list, so a stolen token works until it expires |
| **Stale data** | If Rahul becomes an admin or gets banned, his old token still says the old thing |
| **Bigger than a session ID** | 300+ bytes sent on every request instead of 64 characters |
| **Anyone can read it** | The payload is only base64, not encrypted |

That's why real apps use a **short-lived** access token plus a **refresh token** (topics 20–24).

---

### Real-life example: a boarding pass ✈️

Priya flies from Delhi to Mumbai.

1. At the check-in counter she shows her **ID once** (→ login with the password).
2. She gets a **boarding pass** with her name, flight, seat and a **barcode signed by the airline** (→ the server signs a JWT with her user id and an expiry).
3. At security, at the gate, at the lounge, staff just **scan the pass**. Nobody calls the check-in counter to ask "is this person really checked in?" (→ any server verifies the token **itself**, no session lookup).
4. If she changes the seat number with a pen, the **barcode doesn't match** any more → rejected (→ edit the payload and the **signature fails**).
5. The pass is only good for **today's flight** (→ `exp`, the token expires).
6. If she **drops it** and Rahul picks it up, the scanner can't tell: whoever **bears** the pass boards 😱 (→ a stolen bearer token = a stolen login, so keep it short-lived and send it only over HTTPS).
7. The counter **can't take back** a pass that's already printed. It can only refuse to print a new one (→ no logout for a JWT, only for the refresh token, topic 24).

---

### The flow, step by step

#### 📊 Diagrams

Open **[diagrams.html](diagrams.html)** in your browser (just double-click the file) to see:

- **Flow diagram**: every check the server does on a request with `Authorization: Bearer …`
- **Data flow**: login, a normal request, a forged token, logout, and a restart, with the real headers
- **Session vs token**: where the "who is logged in" information lives in each approach, and why two servers don't need to share anything

In short: `login (password once) → server signs a JWT {sub, exp} → client keeps it → every request: Authorization: Bearer <jwt> → server checks signature + exp + iss/aud → trusts the claims → no session store anywhere`

#### Sessions vs bearer tokens at a glance 🔍

| | Session (topic 09) | Bearer token (this topic) |
|---|---|---|
| What the client holds | A random ID (meaningless) | A signed token **with the user's data inside** |
| Where "logged in" lives | Server (session store) | Client (the token) |
| How the server checks | Look up the ID in Redis/DB | Verify the signature with a key |
| Sent how | `Cookie` header, automatically | `Authorization: Bearer …`, added by your code |
| Logout | Delete the session → works at once | Client forgets the token; copies still work until `exp` |
| Many servers | Need a shared store | Just share the key (or the public key with RS256) |
| CSRF | A risk (cookies go automatically) | Not a risk (header isn't automatic) |
| XSS | `HttpOnly` cookie can't be read by JS | Token in JS memory/`localStorage` **can** be stolen (topic 25) |

---

### Step 1: Log in once, get a signed token

The password check is the same as topic 07. The difference is what you send back:

```js
const token = jwt.sign({ email: user.email }, JWT_SECRET, {
  algorithm: "HS256",
  subject: user.id,     // "sub": who
  issuer: ISSUER,       // "iss": made by us
  audience: "notes-api",// "aud": meant for this API
  expiresIn: 15 * 60,   // "exp": 15 minutes
});
res.json({ access_token: token, token_type: "Bearer", expires_in: 900 });
```

The response shape `{ access_token, token_type, expires_in }` comes from OAuth 2.0 (RFC 6749). Using it means any client library already knows how to read it.

| ✅ Do | ❌ Don't |
|---|---|
| Put only an **id** and a few non-secret facts in the payload | Put the password, card numbers or anything private in it (anyone can decode it) |
| Always set `exp` (minutes, not days) | Make tokens that never expire |
| Use a **long random secret** (32+ random bytes) from an env variable | Use `"secret"` or commit the key to Git |
| Set `iss` and `aud` | Let a token from another app/API work on yours |

---

### Step 2: The client sends it on every request

```http
GET /me HTTP/1.1
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6...
```

In the browser:

```js
fetch("/me", { headers: { Authorization: `Bearer ${accessToken}` } });
```

| ✅ Do | ❌ Don't |
|---|---|
| Send it in the `Authorization` header | Put it in the URL (`/me?token=...`): it lands in server logs, browser history and the `Referer` header |
| Only over **HTTPS** | Send it over plain HTTP: anyone on the café Wi-Fi can copy it |
| Keep it in memory (where to keep it: topic 25) | Log it, or print it in error messages |

---

### Step 3: The server checks the token (the "bouncer" middleware)

```js
const BEARER = /^Bearer ([A-Za-z0-9\-._~+/]+=*)$/i;

function requireAuth(req, res, next) {
  const token = BEARER.exec(req.get("Authorization") ?? "")?.[1];
  if (!token) return res.status(401).set("WWW-Authenticate", 'Bearer realm="notes-api"').json(...);
  try {
    const claims = jwt.verify(token, JWT_SECRET, { algorithms: ["HS256"], issuer: ISSUER, audience: "notes-api" });
    req.user = { id: claims.sub, email: claims.email };
    next();
  } catch {
    res.status(401).set("WWW-Authenticate", 'Bearer error="invalid_token"').json({ error: "Invalid token" });
  }
}
```

`jwt.verify` does all of this for you:

1. Splits the token into `header.payload.signature`
2. Recomputes the signature with your secret and compares it → **someone edited it?** rejected
3. Checks `exp` (expired?) and `nbf` (not valid yet?)
4. Checks `iss` and `aud` if you pass them

**The most important line:** `algorithms: ["HS256"]`. Without it, an old or badly written library may trust the token's own header, and an attacker sends `"alg": "none"` (no signature at all). Always tell the library which algorithm **you** use (topic 18).

The status codes come from RFC 6750 (the Bearer token standard):

| Situation | Status | `WWW-Authenticate` header |
|---|---|---|
| No `Authorization` header | `401` | `Bearer realm="notes-api"` |
| Header is not `Bearer <token>` | `400` | `Bearer error="invalid_request"` |
| Bad signature, expired, wrong `iss`/`aud` | `401` | `Bearer error="invalid_token"` |
| Valid token but not allowed (e.g. not admin) | `403` | `Bearer error="insufficient_scope"` (Level 4) |

---

### Step 4: Use the claims, no database lookup

```js
app.get("/me", requireAuth, (req, res) => res.json(req.user));
```

`req.user` came from the token itself. That's the whole point of "stateless": the request carries everything the server needs.

💡 You **can** still load the user from the database when you need fresh data (their latest name, their balance). But for "who is this?" the token is enough.

---

### Step 5: Logout (and why it's the weak spot)

There's nothing on the server to delete, so "logout" = **the client throws the token away**.

```js
accessToken = null; // that's it
```

But if someone **copied** the token before (XSS, a leaked log), it still works until `exp`. The server has no way to say "not this one any more" without keeping some state again.

| Fix | Topic |
|---|---|
| Keep access tokens **short** (5–15 min) | 20 |
| Use a **refresh token** that the server **does** store and can delete | 21, 24 |
| A **deny-list** of revoked `jti`s (only until they expire) | 24 |
| A `tokenVersion` on the user: bump it to kill all old tokens | 24 |

---

### Step 6: Scaling: why "stateless" is the selling point

With sessions, two servers must share one Redis. With tokens, they only share the **key**:

- **HS256** (one shared secret): every server that verifies can also **create** tokens. OK inside one app.
- **RS256 / ES256** (private + public key): only the auth server has the private key and signs; every other service gets the **public key** and can only verify. The standard for microservices (topic 18).

Restart the server or add 10 more: old tokens keep working, as long as the key is the same.

---

### 🤔 Tricky parts

**1. "Stateless" is never 100% stateless.**
The moment you want instant logout, banning or "log out all devices", you need some server state again (a refresh-token table, a deny-list). Real systems are "mostly stateless": the fast path (checking an access token) needs no lookup, the rare path (refresh, logout) does.

**2. The token outlives the user.**
Delete Rahul's account (topic 17) or ban him, and his token still says "Rahul, valid until 10:45". You'll see this in the demo: after a restart the users list is empty, but the old token still works on `/me`. Short expiry limits the damage; check the database on sensitive actions.

**3. Base64 is not encryption.**
Paste any JWT into jwt.io or decode it with one line of code: the payload is plain JSON. Signing proves **who wrote it**, not that **nobody can read it**. (If you really need hidden contents, that's JWE, rarely used.)

**4. "Bearer" scheme is case-insensitive.**
HTTP auth schemes are case-insensitive (RFC 9110), so `bearer abc` must work too. The token itself is case-sensitive.

**5. Cookies vs header is a separate choice.**
You can also put a JWT inside an `HttpOnly` cookie. Then it's no longer a "bearer header" and CSRF matters again. Which storage to pick is topic 25.

---

### Common beginner mistakes

1. **No `algorithms` option in `jwt.verify`.**
   Opens the door to `alg: none` and algorithm-confusion attacks. Always pin it.

2. **Using `jwt.decode()` to check a token.**
   `decode` only reads it, it does **not** check the signature. Anyone can make a token that decodes fine.

3. **Tokens that never expire (or last 30 days).**
   A stolen token becomes a permanent key. Access tokens: minutes.

4. **Secrets in the payload.**
   Password hashes, phone numbers, internal flags: everyone can read them.

5. **A weak or committed secret.**
   `jwt.sign(data, "secret")` can be brute-forced offline from one token. Use 32+ random bytes from an env variable.

6. **Token in the URL.**
   `?token=...` ends up in logs, history and `Referer`. Use the header.

7. **Thinking logout works.**
   Deleting the token in the browser doesn't stop a copy. Plan for revocation (topic 24).

8. **Returning 200 with `{ error }` or a 500 for a bad token.**
   Bad/expired token = `401` with `WWW-Authenticate`, so clients know to refresh or log in again.

9. **Trusting old claims for important decisions.**
   A role in a 1-hour-old token may be wrong now. Re-check the database for money, admin actions, deleting things.

10. **Sending it over plain HTTP.**
    A bearer token is like cash: whoever sees it can spend it. HTTPS only.

---

### Interview questions

1. **What does "stateless authentication" mean?**
   The server keeps no session for logged-in users. Each request carries a signed token with everything needed to identify the user, and the server verifies it with a key.

2. **What is a bearer token?**
   A token where possession is enough: whoever presents it is treated as the owner. It's sent as `Authorization: Bearer <token>` (RFC 6750).

3. **Session vs JWT: which one would you pick?**
   Sessions for a classic single website (simple, instant logout, `HttpOnly` cookies). JWTs for APIs used by mobile apps, many services or many servers. Many apps mix them: short JWT access token + server-stored refresh token.

4. **How does the server know a JWT wasn't changed?**
   It recomputes the signature over `header.payload` with its key and compares it with the token's signature. Any change to the payload makes them differ.

5. **How do you log out a user with JWTs?**
   You can't delete an issued JWT. Keep it short-lived, delete the refresh token on logout, and if you need instant revocation, keep a deny-list of `jti`s or a token version per user.

6. **Why use the `Authorization` header and not a cookie or the URL?**
   The header isn't sent automatically (no CSRF) and isn't logged like URLs are. It works the same for browsers, mobile apps and servers.

7. **What should go in a JWT payload?**
   A user id (`sub`), expiry (`exp`), issuer and audience, maybe a role. Nothing secret, and nothing that changes often.

8. **What's the `alg: none` attack?**
   An attacker sets the header's algorithm to `none` and removes the signature. A library that trusts the header accepts it. Fix: always pass the allowed `algorithms` list when verifying.

9. **What status code for an expired token?**
   `401` with `WWW-Authenticate: Bearer error="invalid_token"`. The client then refreshes the token (topic 22) or sends the user to login.

10. **HS256 or RS256 for many services?**
    RS256/ES256: only the auth server holds the private key and can sign; the other services only get the public key and can only verify.

---

### Quick recap

- Login once → server **signs** a JWT (`sub`, `exp`, `iss`, `aud`) and **stores nothing**
- Client sends `Authorization: Bearer <token>` on **every** request, over **HTTPS**
- Server checks with `jwt.verify(token, key, { algorithms: [...], issuer, audience })`, never `jwt.decode`
- `401` + `WWW-Authenticate: Bearer error="invalid_token"` for bad/expired tokens
- **Pros:** no session store, scales across servers, works for mobile/APIs, no CSRF
- **Cons:** can't revoke, stale claims, readable payload, XSS can steal it
- So: **short-lived** access tokens + **refresh tokens** (topics 20–24), storage choice in topic 25

## Code

A small **Express** API using **`jsonwebtoken`** (plus Node's built-in `crypto` for passwords): sign up, log in to get a bearer token, call a protected `/me` route with it, then try a missing header, a wrong scheme, a forged token, "logout", a server restart and an expired token. There's **no session store** in the code at all; users are kept in memory, so they disappear when you restart.

📄 **Full code: [server.js](server.js)**. Open it and read the comments, which follow the same steps as the notes above.

Install the packages once (from this folder), then start the server. `JWT_SECRET` is the signing key (32+ characters; without it the server makes a random one on every start):

```bash
npm install
```

```bash
JWT_SECRET=dev-only-secret-at-least-32-characters-long node server.js
```

> Port 3000 busy? Run it on another port: `PORT=3019 JWT_SECRET=dev-only-secret-at-least-32-characters-long node server.js` (Git Bash), then use that port in the commands below.

### Try it

✅ **Sign up and log in:**

```bash
curl -i -X POST http://localhost:3000/signup -H "Content-Type: application/json" -d '{"email":"rahul@mail.com","password":"rahul password 123"}'
```
→ `201 Created` with `{"id":"6d3124b2-...","email":"rahul@mail.com"}`

```bash
curl -X POST http://localhost:3000/login -H "Content-Type: application/json" -d '{"email":"rahul@mail.com","password":"rahul password 123"}'
```
→ `{"access_token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6...","token_type":"Bearer","expires_in":900}`

Save the token in a shell variable so you don't have to copy it:

```bash
TOKEN=$(curl -s -X POST http://localhost:3000/login -H "Content-Type: application/json" -d '{"email":"rahul@mail.com","password":"rahul password 123"}' | sed -E 's/.*"access_token":"([^"]+)".*/\1/')
```

🔍 **Anyone can read the payload** (it's base64url, not encrypted):

```bash
node -e "console.log(Buffer.from(process.argv[1].split('.')[1], 'base64url').toString())" "$TOKEN"
```
→ `{"email":"rahul@mail.com","iat":1793843884,"exp":1793844784,"aud":"notes-api","iss":"http://localhost:3000","sub":"6d3124b2-...","jti":"021d4fca-..."}`

✅ **Call a protected route with the token:**

```bash
curl -i http://localhost:3000/me -H "Authorization: Bearer $TOKEN"
```
→ `200 OK` with `{"id":"6d3124b2-...","email":"rahul@mail.com","expiresAt":"2026-11-05T02:13:04.000Z"}`

(`bearer` in lower case works too: the scheme is case-insensitive.)

❌ **No token:**

```bash
curl -i http://localhost:3000/me
```
→ `401 Unauthorized`, `WWW-Authenticate: Bearer realm="notes-api"`, `{"error":"Missing bearer token"}`

❌ **Wrong scheme:**

```bash
curl -i http://localhost:3000/me -H "Authorization: Token $TOKEN"
```
→ `400 Bad Request` with `{"error":"Authorization header must be: Bearer <token>"}`

❌ **Forge it:** change the email in the payload to Priya's and keep the old signature.

```bash
FAKE=$(node -e "const [h,p,s]=process.argv[1].split('.'); const c=JSON.parse(Buffer.from(p,'base64url')); c.email='priya@mail.com'; console.log([h, Buffer.from(JSON.stringify(c)).toString('base64url'), s].join('.'))" "$TOKEN")
```

```bash
curl -i http://localhost:3000/me -H "Authorization: Bearer $FAKE"
```
→ `401 Unauthorized`, `WWW-Authenticate: Bearer realm="notes-api", error="invalid_token", error_description="Invalid token"`, `{"error":"Invalid token"}`

🚪 **"Log out", then use the token again:**

```bash
curl -X POST http://localhost:3000/logout -H "Authorization: Bearer $TOKEN"
```
→ `{"message":"Delete the token on your side. The server keeps no session, so it can't log the token out."}`

```bash
curl http://localhost:3000/me -H "Authorization: Bearer $TOKEN"
```
→ still `{"id":"6d3124b2-...","email":"rahul@mail.com",...}` 😬 A copy of the token works until it expires.

🔁 **Restart the server** (Ctrl+C, then the same `JWT_SECRET=... node server.js` command) and call `/me` again with the same `$TOKEN`:

→ still `200 OK` with Rahul's data: no session was lost, because there never was one. But try logging in:

```bash
curl -i -X POST http://localhost:3000/login -H "Content-Type: application/json" -d '{"email":"rahul@mail.com","password":"rahul password 123"}'
```
→ `401 Unauthorized` with `{"error":"Invalid email or password"}`. The users list was in memory and is **gone**, yet the token still works: the token outlives the user (Tricky part 2).

🔑 **Restart without `JWT_SECRET`** (a new random key): the old token → `401` with `{"error":"Invalid token"}`. Changing the key logs everyone out.

⏰ **Expiry:** start with short tokens, then sign up, log in and save `$TOKEN` again:

```bash
TOKEN_TTL_SECONDS=5 node server.js
```

Call `/me` right away (→ `200`), wait 6 seconds and call it again:

→ `401 Unauthorized`, `WWW-Authenticate: Bearer realm="notes-api", error="invalid_token", error_description="Token expired"`, `{"error":"Token expired"}`

> **Windows PowerShell users:** the single quotes in `-d '...'`, `TOKEN=$(...)` and `VAR=value node ...` work in Git Bash. In PowerShell, use Git Bash or Postman (Authorization tab → Bearer Token), or set variables with `$env:JWT_SECRET="dev-only-secret-at-least-32-characters-long"; node server.js`.
