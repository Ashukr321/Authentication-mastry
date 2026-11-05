# 15. Remember Me

## Notes

### What is "Remember me"?

It's the little checkbox under the login form. **Unticked**: you're logged out when the session times out or you close the browser. **Ticked**: you come back a week later and you're **still logged in**.

The simple (but weak) way is to make the session cookie live for 30 days. The safer way, used in this topic, is a **second, separate cookie**: a long-lived **remember-me token** whose only job is to **start a new short session** when the old one has ended.

> **One-line answer:** keep sessions short; on "remember me", also set a 30-day `selector.validator` cookie (the validator stored only as a hash). When there's no session, use it to start a new one, **replace the validator every time**, treat a reused old validator as **theft**, and ask for the password again before sensitive actions.

---

### Why does it matter?

"Remember me" is a **long-lived key to the account** sitting in a browser. Done carelessly:

| If you get it wrong… | What happens |
|---|---|
| The session itself lives 30 days | A stolen session cookie works for a month |
| The cookie contains the user ID or email | Anyone can make one (`remember=rahul@mail.com`) |
| The token is stored in plain text | A database leak = logged in as everyone |
| The token never changes | A copied cookie works quietly for 30 days, and nobody notices |
| Logout doesn't delete it | The user clicks "Log out" and is logged straight back in |
| "Remembered" users can do everything | A thief with the cookie can change the password or see card details |

---

### Real-life example: a gym membership card 🏋️

Priya goes to a gym in Pune.

1. **Day pass** (the session): she shows ID at the desk and gets a wristband. It works for **today only**, then it's useless → a **short session**
2. **Membership card** (the remember-me cookie): it lasts **a month**. Each visit, the desk **swaps** the wristband: she taps the card and gets a **new wristband** for the day → the remember-me token **starts a new short session**
3. Each tap also **updates a secret number** on the card. If someone shows up with a card that has the **old** number, the desk knows it was **copied** and **cancels every card** on her account → **rotation + theft detection**
4. The card gets her into the **gym**, but to change her **bank details for the monthly fee**, she must show her **ID again** → **sensitive actions need a fresh password login**
5. She cancels her membership → the card is **deactivated in the system**, not just thrown away → **logout deletes the token on the server**

---

### The flow, step by step

#### 📊 Diagrams

Open **[diagrams.html](diagrams.html)** in your browser (just double-click the file) to see:

- **Flow diagram**: what the server does on every request: session → remember-me cookie → rotate → new session (or theft!)
- **Data flow**: log in with "Remember me", come back after the session ended, get logged back in, then catch a copied cookie
- **Session vs remember-me**: what each cookie is for

In short: `login + rememberMe → short session + 30-day "selector.validator" cookie → session ends → cookie arrives → find selector → hash(validator) matches? → new validator + new short session (marked "remembered")`. A mismatch means theft, so log out everywhere.

#### Two cookies, two jobs 🍪

| | `sid` (session, topic 09) | `remember` (this topic) |
|---|---|---|
| Lives | Minutes to hours. **No `Max-Age`**, so it's deleted when the browser closes | **30 days** (`Max-Age=2592000`) |
| Sent | On every request | Only matters when there's **no** valid session |
| Contains | Random session ID | `selector.validator` |
| Server stores | `sha256(sessionId)` → `{ userId }` | `selector` → `{ userId, sha256(validator), expiresAt }` |
| Changes | On login (topic 09) | **Every time it's used** |
| Can do | Everything | Only start a **less-trusted** session |

---

### Step 1: Login with the checkbox

```js
startSession(res, user, false);                 // the normal short session
if (rememberMe === true) createRememberToken(res, user);
```

- `rememberMe` must be exactly `true`. Unticked is the **default** (shared computers, café PCs).
- The session cookie has **no `Max-Age`**, so it's a "browser-session cookie" that the browser drops when it closes. The server also expires it (30 minutes in our demo).
- Only the **remember-me** cookie gets `Max-Age=2592000` (30 days), with the same `HttpOnly`, `Secure`, `SameSite=Lax` flags as the session (topic 10).

---

### Step 2: The token: `selector.validator`

```js
const selector  = crypto.randomBytes(12).toString("hex"); // public: used to FIND the row
const validator = crypto.randomBytes(32).toString("hex"); // secret: used to PROVE it's yours
rememberTokens.set(selector, { userId, validatorHash: sha256(validator), expiresAt });
res.cookie("remember", `${selector}.${validator}`, { ...COOKIE_OPTIONS, maxAge: 30 days });
```

Why two parts?

| Part | Like… | Stored as | Why |
|---|---|---|---|
| **selector** | A username | Plain (it's the lookup key) | So the database can find the row quickly |
| **validator** | A password | **SHA-256 hash** | A leaked database can't be turned into working cookies |

If you stored one random token as a hash, you'd have to look it up **by its hash**. That works too (we do it for sessions). The selector/validator split is the classic pattern because it gives us **theft detection** (step 4): the selector stays the same, so we can **recognize** a cookie even when its secret is wrong.

| ✅ Do | ❌ Don't |
|---|---|
| Random `selector` + random `validator` | `remember=rahul@mail.com` or `remember=u_1` |
| Store `sha256(validator)` | Store the validator, or the user's password (!) |
| Compare with `crypto.timingSafeEqual` | Compare with `===` (timing attack, topic 07) |
| Expire after 30 days, checked on the **server** | Trust the cookie's `Max-Age` alone |

---

### Step 3: Coming back: no session, but a remember-me cookie

On every request, the server checks in this order:

1. A valid **session**? → use it. Done.
2. Otherwise, a `remember` cookie shaped like `selector.validator`?
3. Find the row by **selector**. Missing or expired → delete the cookie, not logged in.
4. `sha256(validator)` equals the stored hash? (See step 4 if not.)
5. **Rotate**: make a **new validator**, save its hash, send the new cookie. Keep the **original** 30-day expiry, so "remember me" can't last forever.
6. **Start a new short session**, marked `viaRememberMe: true`.

The user never sees any of this: they open the site and they're just logged in.

---

### Step 4: Rotation and theft detection 🚨

Because the validator **changes on every use**, there is only **one** valid cookie at a time.

Imagine Priya (the attacker) copies Rahul's cookie `b074….d744…`:

- Rahul comes back first → the server rotates → Rahul now has `b074….fce0…`
- Priya uses her copy `b074….d744…` → **the selector exists, but the validator is old**

A known selector with a wrong validator means **two people** have used this cookie. The server can't tell which one is the owner, so it does the safe thing:

```js
forgetEverything(token.userId); // delete ALL sessions and ALL remember-me tokens of this user
```

Everyone (Rahul too) must log in with the password again, and the user gets an email: "We logged you out everywhere because your login may have been stolen." Annoying, but much better than a thief staying inside for a month.

(Without rotation, a stolen cookie works silently for 30 days. With rotation, the thief gets **one** use at most before an alarm goes off.)

---

### Step 5: "Remembered" is less trusted than "just typed the password"

```js
const requireFreshLogin = (req, res, next) =>
  req.session.viaRememberMe ? res.status(403).json({ error: "Please log in with your password again", reauth: true }) : next();
```

A remember-me login proves "this browser was logged in **some time in the last 30 days**". That's fine for reading your feed, but **not** for:

- changing the password or email (topic 14)
- seeing or adding payment methods
- deleting the account (topic 17)
- turning off MFA (Level 6)

Amazon is the famous example: it remembers you for browsing, but asks for your password again at checkout or in account settings. This is **step-up authentication**.

---

### Step 6: Logout, password change, "log out everywhere"

| Event | What to delete |
|---|---|
| **Logout** (topic 11) | This session **and this remember-me token** + clear both cookies. Otherwise the user is logged back in on the next request! |
| **Log out everywhere** | All sessions **and all remember-me tokens** of the user |
| **Password change / reset** (topics 13, 14) | All remember-me tokens (they were created for the old password) |
| **Theft detected** | Everything, and email the user |

💡 A security page can list remembered devices ("Chrome on Windows, last used 2 days ago") with a "Forget this device" button, like the "my devices" list in topic 11.

---

### 🤔 Tricky parts

**1. Two tabs at the same time.**
The session ended, and two tabs send requests at the same moment with the same remember-me cookie. The first one rotates it, and the second one looks like theft! Real apps allow a **short grace period** (for example, accept the previous validator for ~10 seconds), or rotate inside a database transaction.

**2. Just make the session last 30 days?**
Simpler, and many apps do it. But then **one** long-lived secret does everything, never changes, and gets no theft detection, and you can't tell "remembered" from "fresh" logins. The two-cookie design keeps the powerful cookie (the session) short-lived.

**3. JWTs and remember me.**
With JWTs (Level 3), the same idea is called a **refresh token**: a long-lived token that gets new short-lived access tokens, rotated on every use, with **reuse detection**. If you understand this topic, you already understand refresh token rotation.

**4. Mobile apps.**
Apps usually keep the user logged in by default, with the long-lived token stored in the phone's secure storage (Keychain / Keystore), not in cookies.

---

### Common beginner mistakes

1. **Making the session cookie 30 days long.**
   Keep sessions short. Use a separate remember-me token.

2. **Putting the user ID, email or password in the cookie.**
   Use random values only.

3. **Storing the token in plain text.**
   Store `sha256(validator)`.

4. **Never rotating the token.**
   A stolen copy works silently for 30 days. Rotate on every use.

5. **Ignoring a wrong validator for a known selector.**
   That's the theft signal. Log out everywhere and alert the user.

6. **Logout that forgets the remember-me token.**
   The user is logged straight back in.

7. **Letting "remembered" sessions do sensitive things.**
   Ask for the password again (step-up).

8. **Ticking "Remember me" by default.**
   On shared computers that's dangerous. Make it opt-in.

9. **Missing cookie flags.**
   `HttpOnly`, `Secure`, `SameSite=Lax` (topic 10). This cookie is a 30-day key.

10. **Not deleting remember-me tokens after a password change or reset.**
    The attacker's remembered browser keeps working.

---

### Interview questions

1. **How would you implement "Remember me"?**
   Short sessions, plus a separate long-lived cookie `selector.validator`. Store the selector and a hash of the validator with the user ID and an expiry. When there's no session, look up the selector, compare hashes in constant time, rotate the validator, and start a new session marked as remembered.

2. **Why not just make the session cookie last 30 days?**
   A stolen session would work for 30 days with no way to notice. Separating them keeps the powerful session short, lets you rotate the long-lived token, detect theft, and treat remembered logins as less trusted.

3. **Why split the token into a selector and a validator?**
   The selector finds the row, and the validator is the secret, stored only as a hash. Because the selector stays the same when the validator rotates, a request with a known selector but an old validator reveals that the cookie was copied.

4. **How do you detect a stolen remember-me cookie?**
   Rotate the validator on every use. If a request arrives with a valid selector but an old validator, two parties used the cookie, so revoke all the user's tokens and sessions and notify them.

5. **What should a remembered user not be able to do without re-entering the password?**
   Change the password or email, see or change payment methods, delete the account, change MFA settings: anything sensitive (step-up authentication).

6. **What happens to remember-me tokens on logout or password change?**
   Logout deletes this device's token. Log out everywhere, a password change, or a password reset deletes all of them.

7. **How is this related to JWT refresh tokens?**
   It's the same pattern: a long-lived token that issues short-lived credentials, rotated on every use, with reuse detection.

8. **What cookie flags should the remember-me cookie have?**
   `HttpOnly`, `Secure`, `SameSite=Lax` (or `Strict`), `Path=/`, `Max-Age` of e.g. 30 days, ideally with the `__Host-` prefix.

---

### Quick recap

- Sessions stay **short**. "Remember me" adds a **separate 30-day cookie**
- Cookie = `selector.validator`. DB stores `selector` + **`sha256(validator)`** + `userId` + `expiresAt`
- No session? Use the cookie: **find → compare hash (constant time) → rotate validator → new short session**
- **Known selector + wrong validator = theft** → log out everywhere + email
- Remembered sessions are **less trusted**: ask for the password before sensitive actions
- **Logout** deletes the remember-me token too. Password change/reset deletes **all** of them
- Opt-in checkbox, `HttpOnly` + `Secure` + `SameSite`, server-side expiry
- Same idea as **JWT refresh token rotation** (Level 3)

## Code

A small **Express** API (plus Node's built-in `crypto`): log in with and without "Remember me", let the session expire, get logged back in by the remember-me cookie, hit a page that needs a fresh password, and catch a copied cookie. Users, sessions and tokens are kept in memory, so they disappear when you restart.

📄 **Full code: [server.js](server.js)**. Open it and read the comments, which follow the same steps as the notes above.

Install Express once (from this folder), then start the server. `SESSION_TTL_SECONDS=5` makes sessions last only 5 seconds, so you can watch remember-me take over:

```bash
npm install
```

```bash
SESSION_TTL_SECONDS=5 node server.js
```

> Port 3000 busy? Run it on another port: `SESSION_TTL_SECONDS=5 PORT=3015 node server.js` (Git Bash), then use that port in the commands below.

### Try it

`-c file.txt` saves the cookies a "browser" gets, `-b file.txt` sends them back.

✅ **Sign up:**

```bash
curl -X POST http://localhost:3000/signup -H "Content-Type: application/json" -d '{"email":"rahul@mail.com","password":"correct horse battery"}'
```

✅ **Log in on a café PC, without "Remember me":** only a session cookie, with no `Max-Age`.

```bash
curl -i -c cafe.txt -X POST http://localhost:3000/login -H "Content-Type: application/json" -d '{"email":"rahul@mail.com","password":"correct horse battery"}'
```
→ `Set-Cookie: sid=170a17a7...26a0; Path=/; HttpOnly; SameSite=Lax` and `{"message":"Logged in","email":"rahul@mail.com","rememberMe":false}`

✅ **Log in on your laptop, with "Remember me":** two cookies.

```bash
curl -i -c laptop.txt -X POST http://localhost:3000/login -H "Content-Type: application/json" -d '{"email":"rahul@mail.com","password":"correct horse battery","rememberMe":true}'
```
→
```
Set-Cookie: sid=db235d22...f8ce; Path=/; HttpOnly; SameSite=Lax
Set-Cookie: remember=b074b1c353b2e837bda2c1d1.d744926e...34fd; Max-Age=2592000; Path=/; Expires=...; HttpOnly; SameSite=Lax
{"message":"Logged in","email":"rahul@mail.com","rememberMe":true}
```

```bash
curl -b laptop.txt http://localhost:3000/me
```
→ `{"email":"rahul@mail.com","loggedInVia":"password"}`

```bash
curl -b laptop.txt http://localhost:3000/payment-methods
```
→ `{"cards":["Visa ending 4242"]}`. A fresh password login can see it.

🕵️ **Pretend an attacker copied the laptop's cookies:**

```bash
cp laptop.txt stolen.txt
```

⏰ **Wait 6 seconds** so both sessions expire. Then:

```bash
curl -i -b cafe.txt http://localhost:3000/me
```
→ `401 Unauthorized` with `{"error":"Not logged in"}`. No remember-me, so the café PC is logged out.

```bash
curl -i -b laptop.txt -c laptop.txt http://localhost:3000/me
```
→ `200 OK`. The remember-me cookie logged you back in, with a **new validator** (same selector) and a new session:
```
Set-Cookie: remember=b074b1c353b2e837bda2c1d1.fce093ae...1b89; Max-Age=2591993; ...
Set-Cookie: sid=b88f5318...6217; Path=/; HttpOnly; SameSite=Lax
{"email":"rahul@mail.com","loggedInVia":"remember-me"}
```
`Max-Age` went **down** (2591993): the 30-day limit counts from the original login.

❌ **A remembered login can't see payment methods:**

```bash
curl -i -b laptop.txt http://localhost:3000/payment-methods
```
→ `403 Forbidden` with `{"error":"Please log in with your password again to see this","reauth":true}`

🚨 **The attacker uses the copied cookie** (its validator is the old one):

```bash
curl -i -b stolen.txt http://localhost:3000/me
```
→ `401 Unauthorized`, both cookies cleared, and
```
{"error":"Your login may have been stolen. You've been logged out everywhere. Please log in again."}
```
The terminal prints the 🚨 alert and the email to the user. The laptop is logged out too: `curl -i -b laptop.txt http://localhost:3000/me` → `401`.

✅ **Logout deletes the remember-me token too:** log in again with `"rememberMe":true` (as above), then:

```bash
curl -i -b laptop.txt -c laptop.txt -X POST http://localhost:3000/logout
```
→ `200 OK`, both cookies cleared (`sid=; ... Expires=Thu, 01 Jan 1970` and `remember=; ... Expires=Thu, 01 Jan 1970`), and `{"message":"Logged out"}`. Now `curl -i -b laptop.txt http://localhost:3000/me` → `401`. The token was deleted on the server, so even a saved copy of the cookie can't log you back in.

✅ **Log out everywhere:**

```bash
curl -b laptop.txt -X POST http://localhost:3000/logout-all
```
→ `{"message":"Logged out everywhere, and no device is remembered anymore"}` (log in first, of course).

> **Windows PowerShell users:** the single quotes in the `-d '...'` part and `VAR=value node ...` work in Git Bash. In PowerShell, use Git Bash, Postman, or set the variables with `$env:SESSION_TTL_SECONDS=5; node server.js`.
