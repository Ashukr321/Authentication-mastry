# 13. Forgot / Reset Password

## Notes

### What is "forgot password"?

Rahul forgot his password. He can't log in, so we need **another way to prove he owns the account**. The usual way: send a **secret, single-use, short-lived link** to his **email**. Whoever can open that inbox is treated as the owner and can choose a new password.

It works almost exactly like email verification (topic 12): a random token, stored as a hash, sent by email, used once. The difference is **what the link unlocks**: here it unlocks the whole account, so every rule is **stricter**.

> **One-line answer:** the user asks for a reset, you email a random single-use link that expires in minutes, and when they set a new password you log out every device and send a "your password was changed" notice.

---

### Why is this such a big deal?

The reset flow is a **second front door** to every account. If it's weak, your strong password hashing (topic 05) doesn't matter: the attacker just resets the password instead of guessing it.

| If you get it wrong… | What happens |
|---|---|
| Token can be guessed | Attacker resets **anyone's** password |
| Page says "no account with that email" | Attacker learns who has an account (account enumeration, topic 06) |
| Link works for days | An old email in a hacked inbox still opens the account |
| Old sessions stay logged in | The attacker who stole the password **stays inside** after the owner resets it |
| No limit on requests | Your app is used to flood someone's inbox with emails |

---

### Real-life example: a lost locker key at the gym 🔑

Priya loses the key to her locker at the gym.

1. She tells the front desk: "I lost my key" → `POST /forgot-password`
2. The desk **doesn't** say "that locker is empty" or "that locker is taken" to strangers → the same reply for every email
3. They send a **one-time code to the phone number on file** (not to whoever is standing at the desk) → the link goes to the **email on the account**
4. The code works for **15 minutes** and **once** → the token **expires** and is **single-use**
5. They change the lock, so the **old key stops working** → the old password **and every logged-in session** stop working
6. They text her "your lock was changed" → the **password changed notice**, so she notices if it wasn't her

---

### The flow, step by step

#### 📊 Diagrams

Open **[diagrams.html](diagrams.html)** in your browser (just double-click the file) to see:

- **Flow diagram**: every check the server does when the new password is submitted
- **Data flow**: the whole journey, from "Forgot password?" → email → new password → old sessions logged out
- **Forgot request**: why the reply is always the same

In short: `forgot (same reply always) → random token → email the link → open the form → POST token + new password → check hash + expiry → delete token → new hash → log out all devices → notice email`

#### Where does the token live? 🔍

| Place | What's there | Safe? |
|---|---|---|
| Server memory | `8b6d…e1a7` (plain), for a moment only | ✅ Never log it |
| Email / user's inbox | The full link with the plain token | ✅ That's the point: only the owner can read it |
| Database | `sha256("8b6d…e1a7")` + `userId` + `expiresAt` | ✅ A leaked DB can't be used to reset anything |
| Browser address bar | The link, while the form is open | ⚠️ Send `Referrer-Policy: no-referrer` so it doesn't leak to other sites |
| After it's used | **Deleted** (plus every other reset link of that user) | ✅ Can't be used again |

---

### Step 1: "Forgot password?": always the same reply

`POST /forgot-password { email }`

```js
if (user && cooldownPassed) sendResetEmail(user);
res.status(202).json({ message: "If an account exists for that email, we've sent a reset link." });
```

| Rule | Why |
|---|---|
| **Same reply** (`202`) whether the email exists or not | Otherwise it's a free "does this person have an account?" checker |
| **Same speed** for both | If real accounts take 300 ms (sending email) and fake ones take 5 ms, the timing gives it away. Real apps put the email on a **job queue** |
| **Cooldown** per user (1 per minute) + rate limit per IP (topic 16) | Stops attackers from flooding someone's inbox |
| **Don't log the user in** or show anything about them | The person asking may not be the owner |

---

### Step 2: Create a token that can't be guessed

```js
const token = crypto.randomBytes(32).toString("hex"); // 256 random bits
resetTokens.set(sha256(token), { userId: user.id, expiresAt: Date.now() + 15 * 60 * 1000 });
```

Same rules as topic 12, but **shorter**:

| | Email verification (12) | Password reset (13) |
|---|---|---|
| What the link unlocks | One flag: `emailVerified` | **The whole account** |
| Expiry | Up to 24 hours | **15–60 minutes** |
| After use | Delete the token | Delete **all** reset tokens + **log out every device** |
| Notice email afterwards | Not needed | **Yes**: "Your password was changed" |

Store only the **hash** (SHA-256 is enough because the token is random, not guessable like a password). And a new request **kills the older links**, so only the newest email works.

---

### Step 3: Send the email

```
Subject: Reset your password
Click: https://myapp.com/reset-password?token=8b6decba...e1a7
This link works for 15 minutes. Didn't ask for it? Ignore this email.
```

- Build the link from **your own `BASE_URL`**, never from the request's `Host` header. Otherwise an attacker sends a reset request with `Host: evil.com`, and the real email sent to the victim contains a link to **evil.com**. When the victim clicks, the token goes to the attacker. (**Host header injection**, a classic reset bug.)
- Say **how long** the link works, and "**ignore this email if you didn't ask**". Rahul shouldn't panic if someone else typed his email.
- Send it with an email service (SES, Resend, SendGrid, Postmark). Our demo prints it in the terminal.

---

### Step 4: Open the link: show the form, DON'T use the token yet

`GET /reset-password?token=...` only **checks** the token and shows the "choose a new password" form.

Why not change anything on `GET`? **Email scanners** (Outlook, Gmail, antivirus) and **chat link previews** open links automatically. If opening the link used up the token, it would be dead before Rahul even clicks.

👉 The rule: **GET shows, POST changes.** The token is used only when the form is **submitted**.

---

### Step 5: Submit the new password: check everything

`POST /reset-password { token, newPassword }`

1. **Does the token look right?** (64 hex characters) → if not, `400` "invalid or expired"
2. **Is the new password valid?** (8–128 characters, topic 06) → if not, `400`, and the token is **not** used up, so Rahul can just try again
3. **Hash the token and look it up.** Not found → `400` "invalid or expired"
4. **Delete it right away**, so it works only **once** (even if he double-clicks "Save")
5. **Expired?** → `400` "invalid or expired"
6. **Hash and save** the new password (scrypt / argon2, topic 05)
7. **Delete every other reset token** of this user
8. **Log out every device**: delete all of the user's sessions (topic 09)
9. **Send a "your password was changed" email**
10. Reply `200` "Password changed. Please log in with your new password."

💡 Use **the same error message** for "never existed", "already used", and "expired".

---

### Step 6: Log out every device 🚪

This is the step beginners forget.

Why do people reset their password? Often **because someone else got in**. Imagine Priya (the attacker) stole Rahul's password and is logged in on her laptop. Rahul resets his password, but if her **session** still works, she **stays inside** his account.

| Login type | How to log out everywhere |
|---|---|
| **Sessions** (topic 09) | Delete every session row with this `userId` |
| **JWT** (Level 3) | Tokens can't be deleted. Store `passwordChangedAt` and reject any token issued **before** it, or rotate refresh tokens |

Some apps keep the **current** device logged in. That's fine for "change password" (topic 14, where you're already logged in), but after a **reset**, log out everyone and make them log in again.

---

### Step 7: Should we log the user in after the reset?

Two choices:

| Log in automatically | Send them to the login page |
|---|---|
| Smoother: one less step | Simpler and safer: one login path for everyone |
| Skips MFA (Level 6) unless you add it here too | MFA, lockout (topic 16), and "new device" checks all run as usual |

Our demo **doesn't** log in automatically. If you do, still ask for the second factor when MFA is on. **A reset link must never skip MFA.**

---

### 🤔 Tricky parts

**1. The token in the URL leaks through `Referer`.**
The reset page loads an image or script from another site → the browser sends the full URL (with the token) in the `Referer` header. Fix: `Referrer-Policy: no-referrer` on the reset page, and no third-party scripts on it.

**2. "Security questions" are not a reset method.**
"What's your mother's maiden name?" can be found on Facebook. Use email (or SMS / an authenticator app as a second factor, Level 6), never questions.

**3. Does a reset prove the email?**
Yes. The user clicked a link sent to that inbox, so many apps set `emailVerified = true` (topic 12) after a successful reset.

**4. Don't send the new password by email.**
"We've reset your password to `Xk93!a`" means a plain password sits in an inbox forever. Always let the user **choose** it through a link.

---

### Common beginner mistakes

1. **"No account found with that email."**
   Leaks who has an account. Always reply the same way.

2. **Using `Math.random()`, the user ID, or a timestamp as the token.**
   Can be guessed. Use `crypto.randomBytes(32)`.

3. **Storing the plain token in the database.**
   A DB leak = a working reset link for everyone. Store `sha256(token)`.

4. **Links that work for days, or more than once.**
   Expire in 15–60 minutes, and delete the token when it's used.

5. **Building the link from the `Host` header.**
   Host header injection sends the token to the attacker. Use a fixed `BASE_URL`.

6. **Using up the token on `GET`.**
   Email scanners open links and kill them. Show the form on GET, change things on POST.

7. **Not logging out other devices.**
   The attacker who caused the reset stays logged in.

8. **No "password changed" email.**
   If an attacker resets the password, the owner never finds out.

9. **Sending a new password by email.**
   Let the user choose it.

10. **No rate limit on "forgot password".**
    Your app becomes an email spam cannon. Add a cooldown and per-IP limits (topic 16).

---

### Interview questions

1. **Walk me through a secure password reset flow.**
   The user enters their email → same reply always → if the account exists, create a random 256-bit token, store its SHA-256 hash with a 15–60 min expiry, email a link built from a fixed base URL → the link opens a form → on submit, look up the hash, delete it, check expiry, hash and save the new password, delete all sessions and reset tokens, and send a "password changed" notice.

2. **How do you avoid account enumeration in "forgot password"?**
   The same message, status code, and response time whether the email exists or not. Send the email from a background job so timing doesn't leak.

3. **Why hash the reset token in the database?**
   So a database leak doesn't give the attacker working reset links. A fast hash like SHA-256 is fine because the token is long and random.

4. **How long should a reset link be valid?**
   Short: 15 to 60 minutes. It unlocks the whole account, so it should be shorter than an email verification link.

5. **What is host header injection in a reset flow?**
   The server builds the link from the request's `Host` header. An attacker requests a reset for the victim with `Host: evil.com`, so the victim gets a real email with a link to evil.com, and clicking it sends the token to the attacker. Fix: build links from a configured base URL.

6. **What should happen to existing sessions after a reset?**
   Revoke all of them. With JWTs, reject tokens issued before `passwordChangedAt` or rotate refresh tokens.

7. **Why shouldn't opening the link use up the token?**
   Email security scanners and link previews open links automatically. Only the form submission (POST) should use the token.

8. **Should the user be logged in right after the reset?**
   Safer not to, so MFA and other login checks still run. If you do, you must still require MFA.

9. **How is this different from "change password" (topic 14)?**
   Reset is for a user who is **not** logged in and proves ownership through email. Change password is for a logged-in user and asks for the **current** password.

---

### Quick recap

- "Forgot password" **always gives the same reply**, with a **cooldown** and rate limits
- Token = `crypto.randomBytes(32)`, **hashed** in the DB, **expires** in 15–60 min, **single-use**, a new one kills the old ones
- Link uses your own **`BASE_URL`**, never the `Host` header
- **GET shows the form, POST changes the password** (email scanners open links)
- `Referrer-Policy: no-referrer` on the reset page
- On submit: **look up hash → delete → check expiry → new password hash**
- Then **log out every device**, delete other reset links, and send a **"password changed" email**
- One error message for every bad link: **"invalid or expired"**
- Don't skip **MFA**, and never email a password

## Code

A small **Express** API (plus Node's built-in `crypto` for tokens and hashing): sign up, log in on a "laptop" (a session cookie, as in topic 09), ask for a reset link, which is printed in the terminal (pretend it's your inbox), open the form, set a new password, and watch the laptop get logged out. Users, tokens and sessions are kept in memory, so they disappear when you restart.

📄 **Full code: [server.js](server.js)**. Open it and read the comments, which follow the same steps as the notes above.

Install Express once (from this folder), then start the server:

```bash
npm install
```

```bash
node server.js
```

> Port 3000 busy? Run it on another port: `PORT=3013 node server.js` (Git Bash), then use that port in the commands below.

### Try it

✅ **Sign up:**

```bash
curl -i -X POST http://localhost:3000/signup -H "Content-Type: application/json" -d '{"email":"rahul@mail.com","password":"old password 123"}'
```
→ `201 Created` with `{"id":"...","email":"rahul@mail.com"}`

✅ **Log in on the "laptop":** `-c laptop.txt` saves the session cookie in a file, like a browser would.

```bash
curl -c laptop.txt -X POST http://localhost:3000/login -H "Content-Type: application/json" -d '{"email":"rahul@mail.com","password":"old password 123"}'
```
→ `{"message":"Logged in","email":"rahul@mail.com"}`

```bash
curl -b laptop.txt http://localhost:3000/me
```
→ `{"id":"...","email":"rahul@mail.com"}`. The laptop is logged in.

✅ **Forgot password:**

```bash
curl -i -X POST http://localhost:3000/forgot-password -H "Content-Type: application/json" -d '{"email":"rahul@mail.com"}'
```
→ `202 Accepted` with `{"message":"If an account exists for that email, we've sent a reset link."}`

🛡️ **Same request for an email that doesn't exist:**

```bash
curl -i -X POST http://localhost:3000/forgot-password -H "Content-Type: application/json" -d '{"email":"nobody@mail.com"}'
```
→ the **exact same** `202` reply, and no email is printed. Attackers learn nothing.

📧 **Check your "inbox":** look at the terminal where the server is running.

```
📧 To: rahul@mail.com
   Subject: Reset your password
   Click: http://localhost:3000/reset-password?token=8b6decba...e1a7
   (This link works for 900 seconds. Didn't ask for it? Ignore this email.)
```

✅ **Open the link in your browser:** you get a "Choose a new password" form. Opening it doesn't use up the token. Type a new password and press **Save**. Or do the same with curl (put your own token in):

```bash
curl -i -X POST http://localhost:3000/reset-password -H "Content-Type: application/json" -d '{"token":"PASTE_YOUR_TOKEN_HERE","newPassword":"new password 456"}'
```
→ `200 OK` with `{"message":"Password changed. Please log in with your new password."}`, and the terminal prints a "Your password was changed" email.

❌ **Use the same link again:** it's single-use.

```bash
curl -i -X POST http://localhost:3000/reset-password -H "Content-Type: application/json" -d '{"token":"PASTE_YOUR_TOKEN_HERE","newPassword":"new password 456"}'
```
→ `400 Bad Request` with `{"error":"This link is invalid or has expired"}`

🚪 **The laptop was logged out:**

```bash
curl -i -b laptop.txt http://localhost:3000/me
```
→ `401 Unauthorized` with `{"error":"Not logged in"}`

❌ **The old password stops working, the new one works:**

```bash
curl -X POST http://localhost:3000/login -H "Content-Type: application/json" -d '{"email":"rahul@mail.com","password":"old password 123"}'
```
→ `{"error":"Invalid email or password"}`

```bash
curl -X POST http://localhost:3000/login -H "Content-Type: application/json" -d '{"email":"rahul@mail.com","password":"new password 456"}'
```
→ `{"message":"Logged in","email":"rahul@mail.com"}`

⏰ **Watch a link expire:** restart the server with a 10-second expiry.

```bash
RESET_TTL_SECONDS=10 node server.js
```

Sign up, ask for a reset, wait 10 seconds, then open the link → "This link is invalid or has expired".

> **Windows PowerShell users:** the single quotes in the `-d '...'` part and `VAR=value node ...` work in Git Bash. In PowerShell, use Git Bash, Postman, or set the variable with `$env:RESET_TTL_SECONDS=10; node server.js`.
