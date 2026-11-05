# 23. Refresh Token Rotation & Reuse Detection

## Notes

### What is refresh token rotation?

In topic 21, the same refresh token works again and again for 7 days. If someone copies it, they can quietly make access tokens for a week, and nobody notices.

**Rotation** means: every time a refresh token is used, the server **replaces it with a new one**, and the old one becomes **used**. Each refresh token works **exactly once**.

**Reuse detection** is the payoff: if a **used** token ever comes back, two parties had it: the real user and a thief. The server can't tell which one is knocking, so it **revokes the whole login** (the "family") and both must log in again.

> **One-line answer:** each refresh returns a **new** refresh token and marks the old one used. A used token showing up again = theft → revoke every token of that login (family) and alert the user. New tokens keep the family's **original** expiry, so rotation can't extend a login forever.

---

### Why does it matter?

| Without rotation (topic 21) | With rotation + reuse detection |
|---|---|
| A stolen refresh token works for **7 days** | It works **at most once** before the alarm goes off |
| Nobody ever notices the theft | The **next** refresh by the user or the thief triggers the alarm |
| One token, used 700 times | 700 tokens, each used once |
| Logout must hit the exact token | Logout revokes the whole family |

This is what the OAuth 2.0 Security Best Current Practice (RFC 9700) recommends for refresh tokens given to browsers and mobile apps, and what Auth0, Okta and others do by default.

---

### Real-life example: a cheque book 📒

Priya's company in Bengaluru pays her travel costs with numbered cheques.

1. The company gives her **cheque #1**. She uses it, and the bank gives her **cheque #2** → **rotation**: every use gives you the next token
2. The bank records "cheque #1 has been **cashed**" → **used tokens are kept**, marked `usedAt`
3. A thief photocopied cheque #1 and tries to cash it → the bank sees **"already cashed!"** → **reuse detected**
4. The bank can't tell if Priya or the thief is holding cheque #2 right now, so it **cancels the whole cheque book** and calls her → **revoke the family + alert the user**
5. Her **other cheque book** (for a different account) keeps working → **other devices are separate families**
6. Each cheque book still expires at the **end of the year**, no matter how many cheques are used → **the family keeps its original expiry**

---

### The flow, step by step

#### 📊 Diagrams

Open **[diagrams.html](diagrams.html)** in your browser (just double-click the file) to see:

- **Flow diagram**: what `POST /auth/refresh` does: unknown, expired, **used (theft!)** or valid (rotate)
- **Data flow**: Rahul's laptop rotates its token, Priya replays a copied old one, the laptop's family is revoked, his phone keeps working
- **Token family**: how one login turns into a chain of one-use tokens

In short: `login → family F, token RT1 → refresh with RT1 → RT1 marked used, RT2 issued (same F, same end date) → … → a used token comes back → revoke all of F → 401 token_reused + email the user`.

---

### Step 1: Families: one login = one family

```js
// login
issueRefreshToken(res, user.id, crypto.randomUUID(), Date.now() + REFRESH_TTL_MS); // new familyId
// stored as
refreshTokens.set(sha256(token), { userId, familyId, expiresAt, usedAt: null });
```

- **Family** = all the refresh tokens that came from **one login** on **one device**.
- Logging in on the laptop and on the phone gives **two families**. Theft on the laptop doesn't log the phone out.
- `expiresAt` is set **once**, at login. Every rotated token copies it, so after 7 days the user must type the password again, however active they are (absolute expiry, topic 21).

---

### Step 2: Rotate on every refresh

```js
stored.usedAt = Date.now();                                          // mark, DON'T delete
issueRefreshToken(res, user.id, stored.familyId, stored.expiresAt);  // new token, same family, same end
res.json(tokenResponse(user));                                       // + a new access token
```

The response sets a **new** cookie, so the browser automatically uses the new token next time. Mobile apps must **save the new refresh token** from every refresh response (and stop using the old one).

| ✅ Do | ❌ Don't |
|---|---|
| Mark the old token `usedAt` | Delete it (then a replay looks like "unknown", not "stolen") |
| Keep the family's original `expiresAt` | Give every rotated token a fresh 7 days (= logged in forever) |
| Do "mark used" **atomically** in the DB | Read, check, then write in two steps (two parallel requests both pass) |
| Keep used tokens until the family expires | Clean them up immediately |

The atomic update looks like this in SQL:

```sql
UPDATE refresh_tokens SET used_at = now() WHERE token_hash = $1 AND used_at IS NULL;
-- 1 row updated → rotate. 0 rows → it was already used → reuse!
```

---

### Step 3: Reuse detection: a used token came back

```js
if (stored.usedAt) {
  revokeFamily(stored.familyId);                  // every token of this login, used or not
  res.clearCookie("refreshToken", { path: "/auth", ... });
  // email the user
  return res.status(401).json({ error: "Refresh token reuse detected...", code: "token_reused" });
}
```

Why revoke the **whole family** and not just the replayed token?

- **Thief replays first**: the thief gets RT2, the user's RT1 is now "used". When the user refreshes with RT1 → reuse → family revoked → **the thief's RT2 dies too**.
- **User refreshes first**: the user gets RT2, the thief's copy RT1 is "used". The thief replays it → reuse → family revoked → the user must log in again (annoying, but safe).

Either way, the thief's access ends at the **next refresh**, and the user gets an email. That's the whole point.

⚠️ The **access token** the thief already got still works until it expires (15 minutes). Short access tokens matter; topic 24 shows how to kill them sooner.

---

### Step 4: Logout and "log out everywhere"

| Event | What to revoke |
|---|---|
| Logout on this device | This token's **family** |
| Log out everywhere / password change / reset | **All** families of the user |
| Reuse detected | That **family** (some apps revoke **all** families, to be extra safe) |

---

### 🤔 Tricky parts

**1. The race that looks like theft.**
Two tabs (or 5 parallel requests) refresh at the same moment with the same token. The first wins and gets RT2; the second arrives with RT1, which is now "used" → **reuse detected** → the user is logged out for nothing. The demo shows exactly this: `200` then `401`. Fixes:
- **Single-flight in the client** (topic 22): one refresh at a time per tab.
- **Share across tabs**: `BroadcastChannel` or the Web Locks API, so only one tab refreshes.
- **Grace period on the server**: if a used token comes back within a few seconds, return the token that replaced it instead of raising the alarm. This weakens detection a little; Auth0 calls it a "reuse interval".

**2. Network failures.**
The server rotated, but the response never reached the client (Wi-Fi dropped). The client still has RT1, which is now used → next refresh = reuse → logged out. A small grace period helps here too.

**3. Can the attacker just win the race forever?**
Only until the user's next refresh. As soon as the real user's app refreshes with its token (now used), the family dies. A thief who steals the token **and** blocks the user's device is a much bigger problem than tokens.

**4. Why not just make the refresh token short-lived?**
Then the user is logged out often. Rotation gives you long logins **and** fast detection.

**5. The token store grows.**
Every refresh adds a row. Delete families when they expire, or keep only the latest token per family and store old hashes in a compact list.

---

### Common beginner mistakes

1. **Rotating but not detecting reuse.**
   You add complexity and get no theft alarm. The detection is the reason to rotate.

2. **Deleting the old token instead of marking it used.**
   A replay then looks like an unknown token, and the thief's new token keeps working.

3. **Revoking only the replayed token.**
   Revoke the whole family, or the thief keeps the newer token.

4. **Giving every rotated token a fresh expiry.**
   The user (or a thief) stays logged in forever. Keep the family's original `expiresAt`.

5. **Non-atomic "check then mark used".**
   Two parallel requests can both rotate the same token. Use a single conditional `UPDATE`.

6. **No single-flight in the client.**
   Users get logged out for "theft" whenever two requests refresh at once.

7. **Mobile apps that don't save the new refresh token.**
   The next refresh sends the old one → reuse → logged out.

8. **Not telling the user.**
   Send an email / notification: "We logged out a device because your login may have been stolen."

9. **Revoking everything for every family on any reuse without thinking.**
   Safer, but a race on one tab logs the user out of all devices. Decide on purpose.

---

### Interview questions

1. **What is refresh token rotation?**
   Each refresh request returns a new refresh token and invalidates the old one, so every refresh token can be used only once.

2. **What is reuse detection?**
   The server keeps used tokens. If a used token is presented again, two parties held it, so the server revokes the whole token family and alerts the user.

3. **Why revoke the whole family?**
   The server can't tell whether the user or the thief presented the replayed token. Revoking the family kills the thief's newer token too, whoever went first.

4. **What is a token family?**
   All refresh tokens that descend from one login on one device. It shares an ID and an absolute expiry.

5. **How do you avoid false positives from concurrent refreshes?**
   Single-flight refresh in the client, sharing one refresh across tabs, and optionally a short server-side grace period that returns the successor token.

6. **Does rotation stop a stolen access token?**
   No. The access token works until it expires. That's why access tokens are short, and why revocation lists exist (topic 24).

7. **Why keep the original expiry on rotated tokens?**
   Otherwise an active session (or an attacker who keeps refreshing) never has to re-authenticate. The absolute expiry forces a password login eventually.

8. **How would you implement "mark as used" safely in a real database?**
   An atomic conditional update: `UPDATE ... SET used_at = now() WHERE token_hash = ? AND used_at IS NULL`, then check the affected row count. Or a transaction with a row lock.

---

### Quick recap

- **Rotation**: every refresh → new refresh token, old one marked **used**
- **Reuse detection**: a used token comes back → **theft** → revoke the **family** + email the user + `401 token_reused`
- **Family** = one login on one device. Other devices aren't affected
- Rotated tokens keep the family's **original expiry**
- Mark-used must be **atomic**. Keep used tokens until the family expires
- Concurrent refreshes look like theft → **single-flight** (topic 22), cross-tab sharing, or a small grace period
- Same idea as remember-me rotation (topic 15). Next: revoking access tokens (topic 24)

## Code

A small **Express** + **`jsonwebtoken`** API, building on topic 21: login starts a token **family**, every refresh **rotates** the token, and a **used** token coming back revokes the family. Users and tokens are kept in memory, so they disappear when you restart.

📄 **Full code: [server.js](server.js)**. Open it and read the comments, which follow the same steps as the notes above.

Install the dependencies once (from this folder), then start the server:

```bash
npm install
```

```bash
node server.js
```

> Port 3000 busy? Run it on another port: `PORT=3023 node server.js` (Git Bash), then use that port in the commands below.

### Try it

`-c file.txt` saves the cookies a "device" gets, `-b file.txt` sends them back. Using both on `/auth/refresh` saves the **rotated** token, just like a browser.

✅ **Sign up, then log in on the laptop and on the phone** (two families):

```bash
curl -X POST http://localhost:3000/auth/signup -H "Content-Type: application/json" -d '{"email":"rahul@mail.com","password":"correct horse battery"}'
```

```bash
curl -i -c laptop.txt -X POST http://localhost:3000/auth/login -H "Content-Type: application/json" -d '{"email":"rahul@mail.com","password":"correct horse battery"}'
```
→ `Set-Cookie: refreshToken=f53069d89e71...58f5; Max-Age=604799; Path=/auth; Expires=Thu, 12 Nov 2026 02:08:02 GMT; HttpOnly; SameSite=Strict`

```bash
curl -c phone.txt -X POST http://localhost:3000/auth/login -H "Content-Type: application/json" -d '{"email":"rahul@mail.com","password":"correct horse battery"}'
```

🕵️ **Priya copies the laptop's refresh token:**

```bash
cp laptop.txt stolen.txt
```

✅ **The laptop refreshes twice:** a **new** token each time, and the expiry date stays the same.

```bash
curl -i -b laptop.txt -c laptop.txt -X POST http://localhost:3000/auth/refresh
```
→ `200 OK`, `Set-Cookie: refreshToken=05b7c10c0772...27c9; Max-Age=604799; ... Expires=Thu, 12 Nov 2026 02:08:02 GMT` and a new `accessToken`

```bash
curl -i -b laptop.txt -c laptop.txt -X POST http://localhost:3000/auth/refresh
```
→ `200 OK`, `Set-Cookie: refreshToken=fc2d74068cdc...6d8e; ...`

🚨 **Priya replays the copied (now used) token:**

```bash
curl -i -b stolen.txt -X POST http://localhost:3000/auth/refresh
```
→
```
HTTP/1.1 401 Unauthorized
Set-Cookie: refreshToken=; Path=/auth; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; SameSite=Strict
{"error":"Refresh token reuse detected. This login was revoked, please log in again.","code":"token_reused"}
```
The terminal prints the alert and the email:
```
🚨 Refresh token reuse for rahul@mail.com (family c6b9ac99-f8eb-435f-850f-f004cc247ef9). Family revoked.
📧 To: rahul@mail.com: "Someone may have stolen your login on one device. We logged that device out. Please log in again."
```

❌ **The laptop's newest token is dead too** (same family):

```bash
curl -i -b laptop.txt -X POST http://localhost:3000/auth/refresh
```
→ `401 Unauthorized` with `{"error":"Refresh token is invalid or expired, please log in"}`

✅ **The phone is a different family, so it still works:**

```bash
curl -i -b phone.txt -c phone.txt -X POST http://localhost:3000/auth/refresh
```
→ `200 OK` with a new token

⚠️ **The race that looks like theft:** log in, then send two refreshes **at the same moment** with the same token:

```bash
curl -s -c tab.txt -X POST http://localhost:3000/auth/login -H "Content-Type: application/json" -d '{"email":"rahul@mail.com","password":"correct horse battery"}'
```

```bash
curl -s -o /dev/null -w "%{http_code}\n" -b tab.txt -X POST http://localhost:3000/auth/refresh & curl -s -o /dev/null -w "%{http_code}\n" -b tab.txt -X POST http://localhost:3000/auth/refresh; wait
```
→ `200` and `401`, plus a 🚨 line in the terminal. Nobody stole anything; two tabs just raced. This is why the client needs **single-flight** refresh (topic 22).

✅ **Logout revokes the family, so a saved copy is dead:**

```bash
cp phone.txt phone-copy.txt
```

```bash
curl -b phone.txt -c phone.txt -X POST http://localhost:3000/auth/logout
```
→ `{"message":"Logged out"}`

```bash
curl -i -b phone-copy.txt -X POST http://localhost:3000/auth/refresh
```
→ `401 Unauthorized` with `{"error":"Refresh token is invalid or expired, please log in"}`

> **Windows PowerShell users:** the single quotes in the `-d '...'` part, `&` / `wait` and `VAR=value node ...` work in Git Bash. In PowerShell, use Git Bash or Postman, or `$env:PORT=3023; node server.js`.
