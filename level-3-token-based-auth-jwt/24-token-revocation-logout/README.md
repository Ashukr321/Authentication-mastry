# 24. Token Revocation & Logout with JWT

## Notes

### What is token revocation?

**Revocation** = making a token stop working **before** it expires. With sessions (topic 09) that's easy: delete the session row. With JWTs it's the hardest part, because the server checks a JWT by its **signature alone**. A JWT that's correctly signed and not expired is accepted, even if the user clicked "Log out" a second ago.

> **One-line answer:** refresh tokens are revoked by **deleting their row**. Access tokens (JWTs) can't be deleted, so you either **wait** for them to expire (keep them short), put their `jti` on a **deny-list** until they expire (one device), or bump a per-user **`tokenVersion`** that every token carries (all devices at once). The last two need a small state lookup on every request.

---

### Why does it matter?

| Situation | What goes wrong without revocation |
|---|---|
| Rahul clicks **Log out** | His access token keeps working for up to 15 minutes |
| A laptop is **stolen** | Rahul clicks "log out everywhere", but the thief keeps using it |
| Rahul **changes his password** after a hack | The attacker's tokens still work |
| An admin **bans** a user | The user keeps working until the token expires |
| A token **leaks** in a log file | Anyone can use it until `exp` |

---

### Real-life example: a cinema ticket 🎬

Rahul buys a ticket for a 3-hour movie at a PVR in Mumbai.

1. The ticket is **printed and stamped** → a **JWT**: anyone checking it can see it's real without calling the box office
2. The usher at the door checks the stamp and the **show time** → verify the **signature** and `exp`
3. Rahul gets a refund, but he still holds the printed ticket. The stamp is still real! → **logout doesn't destroy a JWT**
4. So the box office gives the usher a short list: **"ticket numbers #4521, #4522 were refunded"** → the **deny-list** (by `jti`). The list only needs tonight's tickets: tomorrow they're expired anyway
5. A whole booking was fraud? The box office says **"only tickets printed after 7 pm are valid for Rahul's account"** → **tokenVersion**: one number kills every older ticket at once
6. The ticket is only valid for **3 hours** → **short access tokens** limit the damage even when nothing is revoked

---

### The flow, step by step

#### 📊 Diagrams

Open **[diagrams.html](diagrams.html)** in your browser (just double-click the file) to see:

- **Flow diagram**: the checks on every request: signature → `exp` → deny-list → `tokenVersion`
- **Data flow**: logout on the laptop, the phone keeps working, then "log out everywhere"
- **Which tool for which job**: short TTL vs deny-list vs tokenVersion vs deleting refresh tokens

In short: `logout → delete the refresh token + deny-list this access token's jti`. `logout everywhere / password change / ban → tokenVersion++ + delete all refresh tokens`. Every request: `verify signature → jti not denied → ver === user.tokenVersion`.

---

### Step 1: Revoking the refresh token is easy

Refresh tokens are already stored in the database (topic 21), so revoking one is just:

```js
refreshTokens.delete(sha256(refreshToken));                 // this device
for (...) if (t.userId === userId) refreshTokens.delete(key); // every device
```

That alone is often **enough**: the device can't get a new access token, and the current one dies within 15 minutes. Many apps stop here and accept that window. If that's not good enough, you need steps 2 and 3.

---

### Step 2: Deny-list one access token (`jti`)

Give every access token a unique ID:

```js
jwt.sign({ sub, email, ver }, SECRET, { expiresIn: 900, jwtid: crypto.randomUUID() }); // → "jti" claim
```

On logout, put it on the deny-list **until it would expire anyway**:

```js
const { jti, exp } = jwt.verify(token, SECRET, { algorithms: ["HS256"], ignoreExpiration: true });
if (exp * 1000 > Date.now()) revokedAccessTokens.set(jti, exp);
```

And check it on every request:

```js
if (revokedAccessTokens.has(claims.jti)) return res.status(401).json({ code: "token_revoked" });
```

Why this stays cheap:

- The list holds only tokens that were **logged out** and are **not expired yet**. With 15-minute tokens, that's a tiny list.
- In production it lives in **Redis** with a TTL equal to the token's remaining life: `SET deny:<jti> 1 EX <seconds left>`. Redis deletes it for you.

| ✅ Do | ❌ Don't |
|---|---|
| Deny-list by `jti`, with an expiry | Store the whole JWT forever |
| Verify the signature before deny-listing | Let anyone add garbage to your list |
| Make logout succeed even with an expired / missing token | Return an error from logout (the user is stuck "logged in") |
| Use an **allow-list** of sessions if you need full control | Pretend a JWT is stateless **and** revocable |

---

### Step 3: Revoke **all** of a user's tokens (`tokenVersion`)

Store a number on the user and put it in every token:

```js
user.tokenVersion = 1;                                      // in the users table
jwt.sign({ sub: user.id, ver: user.tokenVersion, ... });   // "ver" claim
// every request
if (claims.ver !== user.tokenVersion) return res.status(401).json({ code: "token_revoked" });
```

To log out everywhere, **bump the number**:

```js
user.tokenVersion++;          // every older token now has the wrong "ver"
deleteAllRefreshTokens(user.id);
```

One write kills every access token on every device, no list needed. Use it for:

- **Log out everywhere**
- **Password change / reset** (topics 13, 14)
- **Admin bans** or disables the user
- **Role change** (Level 4), so old tokens with old permissions stop working

The cost: you look up the user (or just their `tokenVersion`) on every request. Cache it in Redis or in memory with a short TTL.

---

### Step 4: Put it together

| Event | Refresh tokens | Access tokens |
|---|---|---|
| **Logout** (this device) | Delete this one | Deny-list this `jti` |
| **Log out everywhere** | Delete all | `tokenVersion++` |
| **Password change / reset** | Delete all (then issue new ones for **this** device) | `tokenVersion++` |
| **Ban / disable user** | Delete all | `tokenVersion++` (or check `user.disabled`) |
| **Theft detected** (topic 23) | Delete the family | Deny-list, or `tokenVersion++` to be safe |
| **Do nothing** | — | Short TTL: it dies in ≤ 15 min |

And the **client** (topic 22) must throw away its in-memory access token and stop the refresh timer on logout.

---

### 🤔 Tricky parts

**1. "Isn't this just sessions again?"**
Partly, yes. Every check against the deny-list or `tokenVersion` is state. The difference: it's a tiny, fast lookup (a set of recent `jti`s, one number per user), not a full session row. If you check a database on **every** request anyway, ask whether plain sessions (topic 09) would be simpler. Often they would be!

**2. Microservices.**
Every service that accepts the JWT must check the same deny-list and versions. Usually a shared Redis, or the API gateway does it once. Services that only check the signature will still accept revoked tokens.

**3. Short TTL is the cheapest revocation.**
5-minute access tokens + revoked refresh tokens means "logged out within 5 minutes", with **no** per-request lookup. Banks pick short TTLs plus lookups; a blog can live with 15 minutes and no lookups.

**4. Revocation lists for refresh tokens?**
Not needed. Refresh tokens are already in a table: delete the row. The deny-list is only for the stateless access tokens.

**5. OAuth has standards for this.**
`POST /revoke` (RFC 7009) lets a client revoke a token, and token introspection (RFC 7662) lets an API ask "is this token still active?" (Level 5).

**6. Logout must never fail.**
If the access token is expired, missing or garbage, still delete the refresh token, clear the cookie and say "Logged out".

---

### Common beginner mistakes

1. **Logout that only deletes the token in the browser.**
   The token still works if it was copied. Revoke it on the server.

2. **Forgetting the refresh token.**
   The client deletes its access token, but the refresh cookie gets a new one on the next page load (topic 22).

3. **Long-lived access tokens "because we have a deny-list".**
   The list grows huge and every request depends on it. Keep tokens short.

4. **A deny-list that never shrinks.**
   Remove entries once the token's `exp` passes (Redis `EX`).

5. **No `jti` in the token.**
   Then you can't deny-list one token without storing the whole JWT.

6. **Password change that doesn't revoke other devices.**
   The attacker keeps their tokens. Bump `tokenVersion`, delete all refresh tokens.

7. **Only checking revocation in some services.**
   Every service that trusts the JWT must check it, or none of it matters.

8. **Logout that returns an error for an expired token.**
   Logout should always succeed.

---

### Interview questions

1. **How do you log out a user with JWTs?**
   Delete the refresh token on the server and clear its cookie. Then either let the short access token expire, or deny-list its `jti` until its `exp`. The client also discards its in-memory access token.

2. **Can you revoke a JWT?**
   Not by itself: a valid signature and `exp` make it acceptable. You add state: a deny-list of `jti`s, a per-user `tokenVersion`, or an allow-list of sessions. Or keep it short-lived and revoke the refresh token.

3. **Deny-list vs tokenVersion?**
   Deny-list revokes **one** token (one device's logout). `tokenVersion` revokes **all** of a user's tokens with one write (log out everywhere, password change, ban).

4. **Doesn't a deny-list make JWTs stateful?**
   Yes, a little. It's a small, short-lived set (only revoked, unexpired tokens), usually in Redis. If you need a full lookup per request, consider plain sessions.

5. **How long do you keep a `jti` on the deny-list?**
   Until the token's `exp`. After that, the signature check rejects it anyway.

6. **What happens to tokens on password change?**
   Bump `tokenVersion` (all access tokens die), delete all refresh tokens, then issue new tokens for the current device so the user isn't logged out where they just changed it.

7. **How do microservices know a token was revoked?**
   A shared revocation store (Redis), checking at the gateway, or OAuth token introspection. Or short TTLs and accept the window.

8. **Why should access tokens be short even with revocation?**
   Short TTLs keep the deny-list small, limit the damage when a check is missing somewhere, and make "do nothing" an acceptable answer for most events.

---

### Quick recap

- A JWT stays valid until `exp`. **Revocation = adding state**
- Refresh tokens: **delete the row**. That's often enough with short access tokens
- One device: deny-list the access token's **`jti`** until its `exp` (Redis with a TTL)
- All devices: bump **`tokenVersion`**, every token carries `ver`, mismatch = revoked
- Log out everywhere, password change/reset, ban, role change → `tokenVersion++` + delete all refresh tokens
- Logout must **always succeed**, and the client drops its in-memory token
- Every service that trusts the JWT must check revocation
- Next: where to store tokens in the browser (topic 25)

## Code

A small **Express** + **`jsonwebtoken`** API: the refresh tokens from topic 21, plus a **`jti` deny-list** for logout on one device and a per-user **`tokenVersion`** for "log out everywhere" and password changes. Users, tokens and the deny-list are kept in memory, so they disappear when you restart.

📄 **Full code: [server.js](server.js)**. Open it and read the comments, which follow the same steps as the notes above.

Install the dependencies once (from this folder), then start the server:

```bash
npm install
```

```bash
node server.js
```

> Port 3000 busy? Run it on another port: `PORT=3024 node server.js` (Git Bash), then use that port in the commands below.

### Try it

Each "device" keeps its refresh cookie in its own file (`-c` / `-b`) and its access token in a variable. Copy the `accessToken` from each login into `LAPTOP` / `PHONE` (Git Bash).

✅ **Sign up, then log in on the laptop and the phone:**

```bash
curl -X POST http://localhost:3000/auth/signup -H "Content-Type: application/json" -d '{"email":"rahul@mail.com","password":"correct horse battery"}'
```

```bash
curl -c laptop.txt -X POST http://localhost:3000/auth/login -H "Content-Type: application/json" -d '{"email":"rahul@mail.com","password":"correct horse battery"}'
```

```bash
curl -c phone.txt -X POST http://localhost:3000/auth/login -H "Content-Type: application/json" -d '{"email":"rahul@mail.com","password":"correct horse battery"}'
```

```bash
curl http://localhost:3000/me -H "Authorization: Bearer $LAPTOP"
```
→ `{"email":"rahul@mail.com","jti":"3d542a13-b1ce-48bf-b133-a80d52674dde","tokenVersion":1}`

✅ **Log out on the laptop:** send the refresh cookie **and** the access token.

```bash
curl -i -b laptop.txt -c laptop.txt -X POST http://localhost:3000/auth/logout -H "Authorization: Bearer $LAPTOP"
```
→
```
Set-Cookie: refreshToken=; Path=/auth; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; SameSite=Strict
{"message":"Logged out on this device"}
```

❌ **The laptop's access token is dead right away**, not in 15 minutes:

```bash
curl -i http://localhost:3000/me -H "Authorization: Bearer $LAPTOP"
```
→ `401 Unauthorized` with `{"error":"Access token was revoked (logged out)","code":"token_revoked"}`

✅ **The phone is not affected:**

```bash
curl http://localhost:3000/me -H "Authorization: Bearer $PHONE"
```
→ `{"email":"rahul@mail.com","jti":"3fb66190-c236-4321-9d6b-d38fc18c70d8","tokenVersion":1}`

✅ **Logout never fails**, even with a garbage token:

```bash
curl -i -X POST http://localhost:3000/auth/logout -H "Authorization: Bearer abc"
```
→ `200 OK` with `{"message":"Logged out on this device"}`

✅ **Log out everywhere** (log in on the laptop again first and save the new token in `LAPTOP`):

```bash
curl -b phone.txt -c phone.txt -X POST http://localhost:3000/auth/logout-all -H "Authorization: Bearer $PHONE"
```
→ `{"message":"Logged out on every device"}`. Now **every** old token fails:

```bash
curl -i http://localhost:3000/me -H "Authorization: Bearer $LAPTOP"
```
→ `401 Unauthorized` with `{"error":"Access token was revoked, please log in again","code":"token_revoked"}` (the token has `ver: 1`, the user is now on version 2). The phone's token gives the same answer, and `curl -i -b laptop.txt -X POST http://localhost:3000/auth/refresh` → `401` with `{"error":"Refresh token is invalid or expired, please log in"}`.

✅ **Change the password:** log in on both devices again (new `LAPTOP` / `PHONE`), then on the laptop:

```bash
curl -b laptop.txt -c laptop.txt -X POST http://localhost:3000/auth/change-password -H "Content-Type: application/json" -H "Authorization: Bearer $LAPTOP" -d '{"currentPassword":"correct horse battery","newPassword":"new secret phrase"}'
```
→ `{"message":"Password changed. Other devices were logged out.","accessToken":"eyJ...","tokenType":"Bearer","expiresIn":900}` and the terminal prints the 📧 email.

- The phone's access token → `{"error":"Access token was revoked, please log in again","code":"token_revoked"}`
- The phone's refresh (`curl -b phone.txt -X POST http://localhost:3000/auth/refresh`) → `{"error":"Refresh token is invalid or expired, please log in"}`
- The laptop's **old** access token → `token_revoked` too
- The laptop's **new** access token (from the response) → `{"email":"rahul@mail.com","jti":"f0297499-...","tokenVersion":3}`. The laptop stays logged in
- A wrong `currentPassword` → `{"error":"Current password is wrong"}`

> **Windows PowerShell users:** the single quotes in the `-d '...'` part, `LAPTOP=...` / `$LAPTOP` and `VAR=value node ...` work in Git Bash. In PowerShell, use Git Bash, Postman, or `$env:PORT=3024; node server.js` and `$LAPTOP="eyJ..."`.
