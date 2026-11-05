# 20. Access Token

## Notes

### What is an access token?

In Level 1, after login the server gave Rahul a **session id** (topic 09). The id meant nothing by itself: on every request the server had to **look it up** in the sessions table.

An **access token** is different. It's a small **signed pass** that **carries the answer inside it**: "this is user `7acb…`, role `user`, valid until 10:15". The server only checks the **signature** and the **expiry**. No lookup.

> **One-line answer:** an access token is a short-lived, signed pass (usually a JWT) that the client sends in the `Authorization: Bearer <token>` header on every API request, so the server can tell who you are and what you may do just by verifying it.

```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoidXNlciIs....I6ZMH_UhCgt0rny-Rg5eF...
                      └──────── header ────────┘ └─── payload (claims) ───┘ └── signature ──┘
```

(How the three parts are built is topic 18. Why "bearer" and "stateless" matter is topic 19. This topic is about **using** one well.)

---

### Why does it matter?

Access tokens are how almost every modern API (mobile apps, SPAs, microservices, OAuth, "Login with Google") knows who's calling.

| If you get it wrong… | What happens |
|---|---|
| Token lives for days or forever | A stolen token works for days, and you **can't log it out** |
| Secret or private data in the payload | Anyone with the token **reads it**: the payload is only Base64, not encrypted |
| Server doesn't pin the algorithm | `"alg": "none"` or algorithm-confusion tokens are accepted → anyone is admin |
| Weak or committed signing secret | Attackers **make their own tokens** for any user |
| Role check missing | Any logged-in user can call admin routes |
| Token sent in the URL | It lands in server logs, browser history and `Referer` headers |
| 401 vs 403 mixed up | The app logs the user out when it should say "not allowed", or loops forever |

---

### Real-life example: a festival wristband 🎟️

Priya goes to a 3-day music festival (₹4,500 ticket).

1. At the **gate** she shows her ID and ticket once (→ **login** with the password).
2. She gets a **wristband**: today's date, colour "General", and a **hologram** that only the festival can print (→ **access token** with claims and a **signature**).
3. At every stage, the guard just **looks at the wristband**. He doesn't phone the ticket office (→ the API **verifies the signature**, no database lookup).
4. The **VIP lounge** guard sees "General" and says **"not for you"**. She is a valid guest, just not allowed in there (→ **403 Forbidden**).
5. Tomorrow, today's wristband is **expired** and she goes back to the gate for a new one (→ **401**, get a new token, topics 21–22).
6. If she **loses** the wristband, the festival can't switch it off from far away. Anyone wearing it gets in **until it expires**. That's why wristbands only last **one day** (→ access tokens live **5–15 minutes**).

Someone draws "VIP" on a General wristband with a marker? The hologram doesn't match (→ the **signature check fails**).

---

### The flow, step by step

#### 📊 Diagrams

Open **[diagrams.html](diagrams.html)** in your browser (just double-click the file) to see:

- **Flow diagram**: every check the API does on a request that carries a token
- **Data flow**: login → use the token → 403 on an admin route → token expires → 401
- **Session vs access token**: where each one looks for the answer

In short: `login with password → server signs { sub, role, iss, aud, iat, exp } → client sends Authorization: Bearer <token> → server verifies signature + alg + exp + iss + aud → checks role → 200 / 401 / 403`

#### Session id vs access token 🔍

| | Session id (topic 09) | Access token (JWT) |
|---|---|---|
| What's inside | A random string, means nothing | Claims: who, role, expiry |
| How the server checks it | **Looks it up** in the sessions table | **Verifies the signature** (no lookup) |
| Sent as | A cookie, automatically | `Authorization: Bearer …` header, by your code |
| Logout | Delete the row → dead at once | Can't delete it → wait for it to expire |
| Lifetime | Hours or days | **Minutes** (5–15) |
| Good for | One web app + one server | Mobile apps, SPAs, many servers, microservices |

#### Access token vs refresh token (preview of topic 21)

| | Access token | Refresh token |
|---|---|---|
| Used for | Calling the API | Getting a **new** access token |
| Sent to | Every API request | Only `/refresh` |
| Lifetime | Minutes | Days or weeks |
| Checked by | Signature (stateless) | Database lookup (can be revoked) |

---

### Step 1: Issue (sign) the token at login

`POST /login { email, password }` → check the password (topic 07), then:

```js
const accessToken = jwt.sign(
  { role: user.role },                 // custom claim
  JWT_SECRET,
  {
    algorithm: "HS256",
    subject: user.id,                  // sub
    issuer: "auth.example.com",        // iss
    audience: "api.example.com",       // aud
    expiresIn: 15 * 60,                // exp (iat is added for you)
  },
);
res.json({ access_token: accessToken, token_type: "Bearer", expires_in: 900 });
```

The reply uses the **OAuth 2.0 shape** (`access_token`, `token_type`, `expires_in`), so any client library understands it.

**What goes inside (claims):**

| Claim | Meaning | Example |
|---|---|---|
| `sub` | Subject: **who** this is | `"7acb141c-…"` (the user id) |
| `role` / `scope` | What they may do | `"user"`, `"notes:read notes:write"` |
| `iss` | Issuer: who made it | `"auth.example.com"` |
| `aud` | Audience: which API it's for | `"api.example.com"` |
| `iat` | Issued at (seconds since 1970) | `1793843874` |
| `exp` | Expires at | `1793844774` (iat + 900) |
| `jti` | Token id (optional) | used for revocation lists, topic 24 |

| ✅ Do | ❌ Don't |
|---|---|
| Put a stable, random **user id** in `sub` | Use the email as `sub` (it can change, and it's personal data) |
| Put only what the API needs to decide (role, scopes) | Put the password hash, phone, address, Aadhaar, card numbers |
| Keep it small (it's sent on **every** request) | Put the user's whole profile in it |
| Use a **long random secret** (32+ bytes) from env / a secret manager | Use `"secret"`, `"mysecret123"` or commit it to git |

---

### Step 2: The client sends it on every request

```
GET /me
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9....
```

```js
fetch("/me", { headers: { Authorization: `Bearer ${accessToken}` } });
```

| ✅ Do | ❌ Don't |
|---|---|
| Send it in the `Authorization` header | Put it in the URL: `/me?token=eyJ…` (logs, history, `Referer`) |
| Only over **HTTPS** | Send it over plain HTTP (anyone on the Wi-Fi copies it) |
| Keep it in memory in the browser (topic 25 compares the options) | Log it, or send it to analytics / error trackers |

---

### Step 3: Verify it on every request

A small middleware runs before every protected route:

```js
const token = /^Bearer (\S+)$/i.exec(req.headers.authorization ?? "")?.[1];
if (!token) return res.status(401).json({ error: "Missing access token" });

req.token = jwt.verify(token, JWT_SECRET, {
  algorithms: ["HS256"],          // PIN the algorithm
  issuer: "auth.example.com",
  audience: "api.example.com",
  clockTolerance: 5,              // seconds of clock difference allowed
});   // throws if the signature, alg, exp, iss or aud is wrong
```

`jwt.verify` checks, in order:

1. **Signature**: made with our secret, and **not one byte changed**. Change `"role":"user"` to `"admin"` and the signature no longer matches.
2. **Algorithm**: only `HS256`. Never trust the `alg` written in the token: a token that says `"alg": "none"` (no signature at all) must be rejected.
3. **`exp`**: not expired.
4. **`iss` / `aud`**: made by our auth server, for this API (topic 27 goes deeper).

If anything fails → **401** with a `WWW-Authenticate` header (RFC 6750) that says why:

```
WWW-Authenticate: Bearer realm="api", error="invalid_token", error_description="The access token expired"
```

💡 `jwt.decode()` **does not verify anything**. It just reads the payload. Never use it to decide who the user is.

---

### Step 4: Authorize: is this user allowed?

A valid token means "logged in". It does **not** mean "allowed to do everything".

```js
const requireRole = (role) => (req, res, next) => {
  if (req.token.role !== role) return res.status(403).json({ error: `Requires role: ${role}` });
  next();
};
app.get("/admin/stats", requireAccessToken, requireRole("admin"), handler);
```

| Status | Meaning | What the client does |
|---|---|---|
| **401 Unauthorized** | No token, bad token, expired token: "I don't know who you are" | Refresh the token or log in again |
| **403 Forbidden** | Valid token, but not allowed: "I know who you are, and no" | Show "not allowed". Logging in again won't help |

(Roles and permissions get a full level of their own: Level 7.)

---

### Step 5: Pick a short lifetime

There's **no logout** for an access token: once issued, it works until `exp`. So the lifetime **is** your worst case.

| Lifetime | Good | Bad |
|---|---|---|
| 1–5 min | Stolen token is useless fast | Many refreshes, more load |
| **5–15 min** ✅ | The usual balance | — |
| Hours / days ❌ | No refreshes | Stolen token works for hours, role changes take hours to apply |

When it expires, the client doesn't ask for the password again. It uses a **refresh token** (topic 21) to get a new one silently (topic 22).

---

### 🤔 Tricky parts

**1. The payload is readable by anyone.**
A JWT is **signed, not encrypted**. Paste one into jwt.io, or run `atob()` on the middle part, and you see everything. The signature only stops **changes**, not **reading**. (Encrypted tokens exist, JWE, but are rarely needed: just don't put secrets in.)

**2. Claims can go stale.**
Rahul is made admin at 10:00, but his token (issued 9:58) still says `"role":"user"` until it expires. The same in reverse: a removed admin stays admin until `exp`. Short lifetimes keep this window small. For really sensitive actions, load the user from the database (the demo's `/me` does this, so a deleted user gets 401 at once).

**3. You can't revoke one access token (easily).**
Logout, password change, "log out all devices": the access token keeps working until `exp`. Options: keep it short (most common), keep a deny-list of `jti`s, or a per-user "tokens before this time are invalid" timestamp. Topic 24 covers this.

**4. Clock skew.**
If the server that **verifies** is 10 seconds behind the one that **signed**, a fresh token can look "not yet valid" or an old one still valid. A few seconds of `clockTolerance` fixes it. Keep servers synced with NTP.

**5. HS256 vs RS256.**
HS256 uses **one shared secret** to sign **and** verify, so every API that verifies can also **create** tokens. With many services, use RS256/ES256: the auth server signs with a **private key**, APIs verify with the **public key** (topic 18).

**6. Opaque access tokens.**
An access token doesn't have to be a JWT. Some systems use a random string and the API asks the auth server "is this valid?" (**token introspection**, RFC 7662). Revocable at once, but a network call per request. JWT = fast and stateless; opaque = revocable.

---

### Common beginner mistakes

1. **Long-lived access tokens ("expiresIn: 30d").**
   A stolen token works for a month and you can't kill it.

2. **Secrets or personal data in the payload.**
   The payload is just Base64. Anyone with the token reads it.

3. **Using `jwt.decode()` instead of `jwt.verify()`.**
   Anyone can then forge a token with any `sub` and `role`.

4. **Not passing `algorithms: [...]` to verify.**
   Opens the door to `alg: none` and algorithm-confusion attacks.

5. **Weak or hard-coded secret.**
   `"secret"` is cracked offline in seconds, then attackers sign their own admin tokens.

6. **Sending the token in the URL.**
   It leaks into logs, history and the `Referer` header.

7. **Returning 401 for "not allowed".**
   The client thinks the token is bad, refreshes, retries, gets 401 again → loop. Use 403.

8. **Only checking "is there a token?" and not its role/scope.**
   Every logged-in user becomes an admin.

9. **Trusting a role sent in the request body or a header** instead of the one inside the signed token.

10. **No HTTPS.** Bearer tokens are like cash: whoever holds them can spend them.

---

### Interview questions

1. **What is an access token?**
   A short-lived credential the client sends with each API request (usually `Authorization: Bearer <token>`) to prove who it is and what it may do. Often a signed JWT with claims like `sub`, `exp` and scopes.

2. **How is it different from a session id?**
   A session id is a random key the server looks up in a store. A JWT access token carries the data itself and is checked by verifying its signature, so no lookup is needed. The price: it can't be deleted before it expires.

3. **Why are access tokens short-lived?**
   Because a stateless token can't easily be revoked. A short lifetime limits how long a stolen token works and how long stale claims (role, deleted user) stay valid. Refresh tokens handle staying logged in.

4. **Is the JWT payload encrypted?**
   No. It's Base64URL-encoded and readable by anyone. The signature protects integrity, not confidentiality. Never put secrets in it.

5. **What does the server check when it receives a JWT?**
   The signature with a pinned algorithm, `exp` (and `nbf`), `iss`, `aud`, then the claims needed for authorization (role/scope). Optionally that the user still exists or the `jti` isn't revoked.

6. **What is the `alg: none` attack?**
   An attacker changes the header to `"alg": "none"`, edits the payload and removes the signature. A library that trusts the header accepts it. Fix: always pass the allowed algorithms to `verify`.

7. **401 or 403?**
   401: no valid token (missing, expired, tampered) → authenticate again. 403: valid token but not permitted → re-authenticating won't help.

8. **Where should the client store the access token?**
   In memory is safest against XSS for SPAs. `localStorage` is readable by any injected script. An `HttpOnly` cookie hides it from JS but brings CSRF back. Topic 25 compares them.

9. **How would you log a user out "everywhere" with JWTs?**
   Revoke their refresh tokens, keep access tokens short, and if it must be instant, check a deny-list (`jti`) or a "tokens issued before X are invalid" timestamp per user.

---

### Quick recap

- Access token = **short-lived signed pass**, sent as `Authorization: Bearer <token>`
- Server **verifies** it (signature, **pinned alg**, `exp`, `iss`, `aud`), **no session lookup**
- Claims: `sub` (user id), `role`/`scope`, `iss`, `aud`, `iat`, `exp`. **Nothing secret**: anyone can read the payload
- `jwt.verify`, never `jwt.decode`, to decide who the user is
- **401** = who are you? **403** = I know you, and no
- Lifetime **5–15 min**, because it **can't be revoked** before `exp`
- Long random secret from the environment, HTTPS only, never in the URL
- Expired → use a **refresh token** (topics 21–22), not the password again

## Code

A small **Express** API with **[jsonwebtoken](https://www.npmjs.com/package/jsonwebtoken)** (plus Node's built-in `crypto` for passwords): sign up, log in to get an access token, call `/me` with it, get **403** on an admin route, try a forged and an edited token, then watch the token **expire**. Users are kept in memory, so they disappear when you restart.

📄 **Full code: [server.js](server.js)**. Open it and read the comments, which follow the same steps as the notes above.

Install the packages once (from this folder), then start the server. `ACCESS_TOKEN_SECONDS=20` shortens the 15-minute lifetime to 20 seconds so you can watch a token expire:

```bash
npm install
```

```bash
ACCESS_TOKEN_SECONDS=20 node server.js
```

> No `JWT_SECRET` set? The server makes a random one and warns you, so every token dies when you restart it. A real app sets `JWT_SECRET` (32+ random characters) from a secret manager.

> Port 3000 busy? Run it on another port: `PORT=3020 ACCESS_TOKEN_SECONDS=20 node server.js` (Git Bash), then use that port in the commands below.

### Try it

✅ **Sign up:**

```bash
curl -i -X POST http://localhost:3000/signup -H "Content-Type: application/json" -d '{"email":"rahul@mail.com","password":"rahul password 123"}'
```
→ `201 Created` with `{"id":"7acb141c-f56c-4e2b-b9fb-d8e93e69fa1c","email":"rahul@mail.com"}`

✅ **Log in and get an access token:**

```bash
curl -X POST http://localhost:3000/login -H "Content-Type: application/json" -d '{"email":"rahul@mail.com","password":"rahul password 123"}'
```
→
```json
{"access_token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoidXNlciIsImlhdCI6MTc5Mzg0Mzg3NCwiZXhwIjoxNzkzODQzODk0LCJhdWQiOiJhcGkuZXhhbXBsZS5jb20iLCJpc3MiOiJhdXRoLmV4YW1wbGUuY29tIiwic3ViIjoiN2FjYjE0MWMtZjU2Yy00ZTJiLWI5ZmItZDhlOTNlNjlmYTFjIn0.I6ZMH_UhCgt0rny-Rg5eFjMThzlOLtL8aAycehjDQ0Y","token_type":"Bearer","expires_in":20}
```

Save it in a variable so the next commands can use it (log in again: it expires in 20 seconds!):

```bash
TOKEN=$(curl -s -X POST http://localhost:3000/login -H "Content-Type: application/json" -d '{"email":"rahul@mail.com","password":"rahul password 123"}' | sed -E 's/.*"access_token":"([^"]+)".*/\1/')
```

👀 **Anyone can read the payload** (no secret needed):

```bash
node -e "const [h,p]=process.argv[1].split('.');console.log(Buffer.from(h,'base64url').toString());console.log(Buffer.from(p,'base64url').toString())" "$TOKEN"
```
→
```
{"alg":"HS256","typ":"JWT"}
{"role":"user","iat":1793843874,"exp":1793843894,"aud":"api.example.com","iss":"auth.example.com","sub":"7acb141c-f56c-4e2b-b9fb-d8e93e69fa1c"}
```
`exp - iat = 20` seconds. No email, no password: just what the API needs.

✅ **Call the API with the token:**

```bash
curl -i http://localhost:3000/me -H "Authorization: Bearer $TOKEN"
```
→ `200 OK` with `{"id":"7acb141c-f56c-4e2b-b9fb-d8e93e69fa1c","email":"rahul@mail.com","role":"user","tokenExpiresAt":"2026-11-05T01:58:14.000Z"}`

❌ **No token:**

```bash
curl -i http://localhost:3000/me
```
→ `401 Unauthorized` with the header `WWW-Authenticate: Bearer realm="api"` and `{"error":"Missing access token"}`

🚫 **Valid token, wrong role:** Rahul is logged in, but he isn't an admin.

```bash
curl -i http://localhost:3000/admin/stats -H "Authorization: Bearer $TOKEN"
```
→ `403 Forbidden` with `{"error":"Requires role: admin"}` (403, not 401: a new token won't help)

🦹 **Edit the payload to `"role":"admin"`** (keep the old signature):

```bash
EDITED=$(node -e "const [h,p,s]=process.argv[1].split('.');const o=JSON.parse(Buffer.from(p,'base64url'));o.role='admin';console.log(h+'.'+Buffer.from(JSON.stringify(o)).toString('base64url')+'.'+s)" "$TOKEN")
```

```bash
curl -i http://localhost:3000/admin/stats -H "Authorization: Bearer $EDITED"
```
→ `401 Unauthorized`, `WWW-Authenticate: Bearer realm="api", error="invalid_token", error_description="The access token is invalid"` and `{"error":"The access token is invalid"}`. The signature no longer matches.

🦹 **Sign your own admin token with a guessed secret** (run it from this folder, it uses the installed `jsonwebtoken`):

```bash
FORGED=$(node -e "console.log(require('jsonwebtoken').sign({role:'admin'},'my guessed secret',{subject:'x',issuer:'auth.example.com',audience:'api.example.com',expiresIn:900}))")
```

```bash
curl -i http://localhost:3000/admin/stats -H "Authorization: Bearer $FORGED"
```
→ `401 Unauthorized` with `{"error":"The access token is invalid"}`. (An `"alg":"none"` token with no signature gets the same reply, because the server pins `HS256`.)

⏰ **Wait 25 seconds, then use the same token again:**

```bash
curl -i http://localhost:3000/me -H "Authorization: Bearer $TOKEN"
```
→ `401 Unauthorized` with
```
WWW-Authenticate: Bearer realm="api", error="invalid_token", error_description="The access token expired"
{"error":"The access token expired"}
```
The client would now use a refresh token to get a new one (topics 21–22).

> **Windows PowerShell users:** the single quotes in `-d '...'`, `VAR=value node ...` and `TOKEN=$(...)` work in Git Bash. In PowerShell, use Git Bash, Postman (paste the token in **Authorization → Bearer Token**), or set variables with `$env:ACCESS_TOKEN_SECONDS=20; node server.js`.
