# 12. Email Verification

## Notes

### What is email verification?

**Email verification** proves that the person who signed up **really owns the email address** they typed. You send a **secret link** to that address. Only someone who can open that inbox can click it.

In topic 06 (signup), we saved every new user with `emailVerified: false`. This topic is how that flag becomes `true`.

> **One-line answer:** send a random, single-use, short-lived link to the email; when it's clicked, mark the email as verified.

---

### Why do we need it?

Anyone can type **any** email into a signup form. Without verification:

| Problem | Example |
|---|---|
| **Typos** | Rahul types `rahul@gmial.com`. Password reset emails go nowhere, and he's locked out forever. |
| **Fake / bot accounts** | A bot signs up 10,000 accounts with made-up emails. |
| **Using someone else's email** | Priya signs up with `rahul@mail.com`. Now Rahul gets her emails, and when he tries to sign up, it says "already registered". |
| **Password reset is unsafe** | Password reset (topic 13) sends a link to the email. That's only safe if we **know** the email belongs to the user. |
| **Spam / bounces** | Sending to bad addresses hurts your email reputation, and your real emails start landing in spam. |

👉 Verification is the base for everything that trusts the email later: **password reset**, **magic links** (Level 6), and **account linking** with Google login (Level 5).

---

### Real-life example: a courier with a delivery code 📦

You order a phone online. The courier won't just hand it to anyone standing at the door:

1. The shop sends a **secret code** to **your phone** → the server emails a **secret link**
2. Only someone holding your phone can read it → only the inbox owner can open the email
3. You tell the courier the code → you **click the link**
4. The courier checks it and hands over the parcel → the server marks `emailVerified: true`
5. The code works **once** and only **today** → the token is **single-use** and **expires**

---

### The flow, step by step

#### 📊 Diagrams

Open **[diagrams.html](diagrams.html)** in your browser (just double-click the file) to see:

- **Flow diagram**: every check the server does when the link is clicked, and what it returns
- **Data flow**: the whole journey, from signup → email → click → login
- **Resend**: why an old link stops working when a new one is sent

In short: `signup (unverified) → random token → email the link → click → check hash + expiry → delete token → emailVerified = true`

#### Where does the token live? 🔍

| Place | What's there | Safe? |
|---|---|---|
| Server memory | `9f3a…c21d` (plain), for a moment only | ✅ Never log it |
| Email / user's inbox | The full link with the plain token | ✅ That's the point: only the owner can read it |
| Database | `sha256("9f3a…c21d")` + `userId` + `expiresAt` | ✅ A leaked DB can't be used to verify anything |
| After it's clicked | **Deleted** | ✅ Can't be used again |

---

### Step 1: Sign up the user as "not verified"

Signup works exactly like topic 06, but the user starts with:

```js
{ id: "u_1", email: "rahul@mail.com", passwordHash: "...", emailVerified: false }
```

Then the server creates a token and sends the email.

---

### Step 2: Create a token that can't be guessed

```js
const token = crypto.randomBytes(32).toString("hex"); // 256 random bits
```

| ✅ Do | ❌ Don't |
|---|---|
| `crypto.randomBytes(32)` (a secure random generator) | `Math.random()` (predictable) |
| 32 bytes = 256 bits of randomness | A 4-digit code in a **link** (only 10,000 options) |
| A random value with no meaning | `base64(email)` or the user ID (anyone can make one) |
| Expires in **24 hours** (or less) | A link that works forever |

> **What about 6-digit codes?** Some apps send a code like `482913` instead of a link. That's fine **only** with strict rate limiting (for example 5 wrong tries, then the code is dead) and a short expiry (10–15 min). There are only 1,000,000 possible codes, so without limits a bot can try them all.

---

### Step 3: Store only the HASH of the token

Just like passwords, we don't store the token itself:

```js
verificationTokens.set(sha256(token), { userId: user.id, expiresAt: Date.now() + 24 * 60 * 60 * 1000 });
```

Why? If your database leaks, the attacker gets only hashes. They can't turn a hash back into a working link.

**Why plain SHA-256 here, but argon2 for passwords?** Passwords are short and guessable (`rahul123`), so we need a **slow** hash. A token is 256 random bits, so there's nothing to guess. A **fast** hash like SHA-256 is enough.

---

### Step 4: Send the email

The email contains a link like:

```
https://myapp.com/verify-email?token=9f3a7b...c21d
```

Rules for the email:

- Build the link from **your own config** (`BASE_URL`), **never** from the request's `Host` header. Attackers can fake that header and make your email contain a link to **their** site (called **host header injection**).
- Send it with an email service (**Amazon SES, Resend, SendGrid, Postmark**). In our demo, we just print it in the terminal.
- Send it **in the background** (a job queue) in real apps, so signup doesn't wait for the email server.
- Say how long the link works ("This link expires in 24 hours").

---

### Step 5: The user clicks the link: check everything

When `GET /verify-email?token=...` arrives:

1. **Is there a token, and does it look right?** (64 hex characters) → if not, `400`
2. **Hash it and look it up.** Not found? → `400` "invalid or expired"
3. **Delete it right away**, so it can be used only **once**
4. **Is it expired?** → `400` "invalid or expired"
5. **Mark the user** `emailVerified: true`, `verifiedAt: now`
6. **Respond** `200` "Email verified! You can now log in."

💡 Use **the same error message** for "never existed", "already used", and "expired". Different messages tell an attacker which tokens were once real.

---

### Step 6: Block (or limit) unverified users

What can an unverified user do? There are two styles:

| | Hard gate | Soft gate |
|---|---|---|
| **Login** | ❌ Blocked: "Please verify your email first" | ✅ Allowed |
| **What's limited** | Everything | Sensitive things: payments, posting, inviting others |
| **User sees** | Must click the link before using the app | A banner: "Please verify your email" |
| **Used by** | Banking, B2B apps | Most social apps, e-commerce |

Our demo uses a **hard gate**: login returns `403` until the email is verified.

⚠️ **Order matters:** check the **password first**, then the verified flag. If you check "verified?" first, anyone can type an email and learn if an unverified account exists (account enumeration, from topic 06).

---

### Step 7: Resend the email

Emails get lost in spam, or the user clicks the link too late. Give them a **"Resend link"** button:

| Rule | Why |
|---|---|
| **The same `202` reply** for every email | So nobody can use it to check which emails have accounts |
| **Cooldown** (for example, 1 email per minute) | So attackers can't use your server to **spam** someone's inbox |
| **Old links stop working** when a new one is sent | Only the newest email is valid, less confusion |
| Don't send if the user is **already verified** | Nothing to do |

---

### Bonus: when the user changes their email

Rahul changes his email from `rahul@mail.com` to `rahul@work.com`. **Don't switch it right away!**

1. Keep the **old** email active
2. Send a verification link to the **new** email
3. Only after it's clicked, switch to the new email
4. Send a "your email was changed" notice to the **old** email (so the real owner notices if it was an attacker)

If you switch first, a typo in the new email locks Rahul out, and an attacker who steals a session can move the account to their own email.

---

### 🤔 Tricky part: pre-account takeover

Priya (an attacker) signs up with **Rahul's email** and **her own password**. She can't verify it, so the account just sits there.

Later, Rahul clicks **"Sign in with Google"** (Level 5). If your app **automatically merges** the Google login into the existing `rahul@mail.com` account, Priya's password still works, and she's now inside Rahul's account! 😱

**Fixes:**
- **Never merge** into an account whose email isn't verified
- When the real owner verifies (or logs in with Google), **remove the old unverified password** and sessions
- **Delete unverified accounts** after a few days

---

### Common beginner mistakes

1. **Using `Math.random()` or the user ID as the token.**
   Predictable tokens can be guessed. Use `crypto.randomBytes(32)`.

2. **Storing the plain token in the database.**
   A DB leak = working links. Store `sha256(token)`.

3. **Tokens that never expire.**
   An old email in an old inbox still works years later. Expire in 24 hours or less.

4. **Tokens that can be used many times.**
   Delete the token as soon as it's used.

5. **Building the link from the `Host` header.**
   Attackers can change it and send your users to their site. Use a fixed `BASE_URL` from config.

6. **"Resend" with no cooldown.**
   Attackers use your app to flood someone's inbox. Add a cooldown and rate limiting (topic 16).

7. **"Resend" says "this email doesn't exist".**
   That leaks who has an account. Always reply the same way.

8. **Checking "verified?" before the password at login.**
   That leaks which emails have unverified accounts. Check the password first.

9. **Switching to a new email before it's verified.**
   Verify the new one first, and notify the old one.

10. **Logging the full link.**
    The token ends up in your logs, where anyone with log access can use it.

---

### Interview questions

1. **Why do we verify emails?**
   To prove the user owns the address. It stops typos, fake accounts, and people using someone else's email, and it makes password reset safe.

2. **How do you generate a verification token?**
   With a secure random generator, `crypto.randomBytes(32)`, which gives 256 bits. Never `Math.random()`, never something based on the email or user ID.

3. **Why store a hash of the token instead of the token?**
   If the database leaks, the attacker can't use the hashes as links. SHA-256 is enough because the token is random, not guessable like a password.

4. **What properties should the token have?**
   Unguessable, single-use, short-lived (24 h or less), tied to one user, and stored as a hash.

5. **Can you use a JWT as a verification token instead?**
   Yes, a signed JWT with `userId` and `exp` works without a database table. But it's hard to make **single-use** or to cancel when you send a new link, so most apps use a random token in the DB.

6. **How do you stop the "resend" button from being abused?**
   A cooldown per user, rate limiting per IP, and the same reply for every email so it can't be used for enumeration.

7. **Should unverified users be allowed to log in?**
   It depends: a hard gate (block login) for sensitive apps, a soft gate (log in, but limit sensitive actions) for most consumer apps.

8. **How do you handle a user changing their email?**
   Keep the old email, verify the new one, switch only after the click, and notify the old address.

9. **What is pre-account takeover?**
   An attacker signs up with the victim's email first. If the app later merges a Google login into that unverified account, the attacker's password still works. Fix: never trust or merge unverified emails.

---

### Quick recap

- Verification **proves the user owns the email**
- Token = `crypto.randomBytes(32)`, **hashed** in the DB, **expires** in ≤ 24 h, **single-use**
- Link uses your own **`BASE_URL`**, never the `Host` header
- On click: **look up hash → delete → check expiry → `emailVerified = true`**
- One error message for every bad link: **"invalid or expired"**
- Login: check the **password first**, then the verified flag
- Resend: **same reply always**, **cooldown**, **old links die**
- Changing email: **verify the new one before switching**

## Code

A small **Express** API (plus Node's built-in `crypto` for tokens and hashing): signup creates an **unverified** user, the "email" is printed in the terminal (pretend it's your inbox), and login is blocked until you click the link. Users and tokens are kept in memory, so they disappear when you restart.

📄 **Full code: [server.js](server.js)**. Open it and read the comments, which follow the same steps as the notes above.

Install Express once (from this folder), then start the server:

```bash
npm install
```

```bash
node server.js
```

> Port 3000 busy? Run it on another port: `PORT=3012 node server.js` (Git Bash), then use that port in the commands below.

### Try it

✅ **Sign up:** the user is created as unverified.

```bash
curl -i -X POST http://localhost:3000/signup -H "Content-Type: application/json" -d '{"email":"rahul@mail.com","password":"correct horse battery"}'
```
→ `201 Created` with `{"id":"...","email":"rahul@mail.com","emailVerified":false,"message":"Account created. Check your email to verify it."}`

📧 **Check your "inbox":** look at the terminal where the server is running.

```
📧 To: rahul@mail.com
   Subject: Verify your email
   Click: http://localhost:3000/verify-email?token=0202e883...d011d5
   (This link works for 86400 seconds)
```

❌ **Try to log in before verifying:**

```bash
curl -i -X POST http://localhost:3000/login -H "Content-Type: application/json" -d '{"email":"rahul@mail.com","password":"correct horse battery"}'
```
→ `403 Forbidden` with `{"error":"Please verify your email first. Check your inbox or ask for a new link."}`

✅ **Click the link:** paste it in your browser, or use curl (put your own token in).

```bash
curl -i "http://localhost:3000/verify-email?token=PASTE_YOUR_TOKEN_HERE"
```
→ `200 OK` with `{"message":"Email verified! You can now log in.","email":"rahul@mail.com"}`

❌ **Click the same link again:** it's single-use.

```bash
curl -i "http://localhost:3000/verify-email?token=PASTE_YOUR_TOKEN_HERE"
```
→ `400 Bad Request` with `{"error":"This link is invalid or has expired"}`

✅ **Log in now:**

```bash
curl -i -X POST http://localhost:3000/login -H "Content-Type: application/json" -d '{"email":"rahul@mail.com","password":"correct horse battery"}'
```
→ `200 OK` with `{"message":"Logged in","id":"...","email":"rahul@mail.com","emailVerified":true}`

🛡️ **Resend for an email that doesn't exist:** the reply is the same, so attackers learn nothing.

```bash
curl -i -X POST http://localhost:3000/resend-verification -H "Content-Type: application/json" -d '{"email":"nobody@mail.com"}'
```
→ `202 Accepted` with `{"message":"If that account exists and isn't verified yet, we've sent a new link."}`, and no email is printed.

⏰ **Watch a link expire:** restart the server with a 10-second expiry.

```bash
VERIFY_TTL_SECONDS=10 node server.js
```

Sign up, wait 10 seconds, then click the link → `400` "invalid or expired". Wait one minute (the resend cooldown), then ask for a new link with `POST /resend-verification`. A new email appears in the terminal, and the old link is dead for good.

> **Windows PowerShell users:** the single quotes in the `-d '...'` part and `VAR=value node ...` work in Git Bash. In PowerShell, use Git Bash, Postman, or set the variable with `$env:VERIFY_TTL_SECONDS=10; node server.js`.
