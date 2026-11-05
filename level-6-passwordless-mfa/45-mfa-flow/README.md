# 45. MFA Flow

## Notes

### What is MFA?

**MFA (multi-factor authentication)** means logging in with **two or more different kinds** of proof. Topics 43 and 44 built the pieces (email/SMS codes, an authenticator app). This topic is about **the flow around them**: what the server does between the password and the code, which methods the user can pick, how "remember this device" works, and how to ask for MFA **again** before something dangerous.

> **One-line answer:** after the password, give a short single-use **`mfaToken`** (not a session) → let the user pick an enrolled factor (TOTP, email code, recovery code) → verify it with attempt limits → create a session that records **how** (`amr`) and **when** (`mfaAt`) they passed MFA → optionally set a **trusted-device** cookie to skip MFA on this device for 30 days → for sensitive actions, require a **recent** MFA (**step-up**), even on a trusted device.

---

### The three kinds of factors

| Factor | Means | Examples |
|---|---|---|
| **Something you know** | A secret in your head | Password, PIN, security question |
| **Something you have** | A device you hold | Phone with an authenticator app (topic 44), SMS phone (topic 43), security key, passkey (topic 46) |
| **Something you are** | Your body | Fingerprint, Face ID (usually unlocks a "have" factor, like a passkey) |

⚠️ **Two of the same kind is not MFA.** Password + security question = two things you **know**. A phishing page asks for both. Real MFA mixes **kinds**: password (know) + phone code (have).

---

### Why does it matter?

| Without MFA | With MFA |
|---|---|
| A leaked password from another site = your account is gone (credential stuffing, topic 52) | The attacker also needs your phone |
| A phished password works forever | The phished code works for 30 seconds, once |
| Rahul's password, typed at a cybercafé, is reused later | The next login from a new device asks for a code |
| One stolen session cookie can change the payout bank account | Changing payouts needs a **fresh** code (step-up) |

Microsoft reports that MFA blocks over 99% of automated account takeover attacks. That's why banks, GitHub, AWS and Google push it so hard.

---

### Real-life example: an ATM 🏧

Priya takes out ₹2,000 at an SBI ATM.

1. She inserts her **card** → something she **has**
2. She types her **PIN** → something she **knows**. Card alone or PIN alone is useless
3. Three wrong PINs and the card is **blocked** → attempt limits
4. For a small withdrawal the ATM asks nothing more. To **change her mobile number** she must visit the branch with ID → **step-up** for sensitive actions
5. Her **regular** branch knows her face and skips some checks; a new branch asks for everything → **trusted device**

---

### The flow, step by step

#### 📊 Diagrams

Open **[diagrams.html](diagrams.html)** in your browser (just double-click the file) to see:

- **Login state machine**: password → ticket → factor → session, with the trusted-device shortcut
- **Data flow**: a full login with "remember this device", then the next login that skips the code
- **Step-up**: why a trusted-device session must still confirm before changing the payout UPI ID

In short: `password ✓ → trusted device? → session (no MFA)` or `→ mfaToken → pick factor → verify → session { amr, mfaAt } (+ trusted-device cookie)` and `sensitive action → mfaAt recent? → do it : 403 stepUpRequired → verify → mfaAt = now`

#### The login is a small state machine

| State | What the user holds | What it can do |
|---|---|---|
| Logged out | Nothing | Send email + password |
| **Password OK** | `mfaToken` (5 min, one use, stored hashed) | Only: ask for an email code, or send a factor |
| **Logged in** | `sid` session cookie, with `amr` and `mfaAt` | Normal pages |
| **Recently verified** | Same session, `mfaAt` less than 5 min ago | Sensitive actions too |

---

### Step 1: Password first, then a ticket (not a session)

```js
POST /login { email, password }
→ 200 { "mfaRequired": true, "mfaToken": "1816A0wk…", "methods": ["totp", "email_otp", "recovery_code"] }
```

| ✅ Do | ❌ Don't |
|---|---|
| Return a short-lived, single-use **ticket** | Create a session and redirect to "/enter-code" (the attacker just skips that page) |
| Store `sha256(mfaToken)` with `userId`, `expiresAt`, attempts | Put `userId` in a cookie and trust it at the code step |
| List only the methods **this** user has set up | List every method (it tells attackers what to target) |
| Same "Invalid email or password" for every password failure | Say "wrong code" before the password was checked |

The order matters: **password first**, then the code. If you ask for the code first, anyone can trigger codes to Rahul's phone or inbox just by typing his email (spam, SMS bills, and MFA fatigue).

---

### Step 2: Let the user pick a factor

| Method | How | Strength |
|---|---|---|
| `totp` | Code from the authenticator app (topic 44) | ✅ Good, offline |
| `email_otp` | "Email me a code instead": `POST /login/mfa/email` sends one (topic 43) | ⚠️ Weak if the same email can reset the password |
| `recovery_code` | One of the codes saved at setup | Emergency only, single use |
| Passkey / security key | Topic 46 | ✅✅ Best: phishing-proof |

Show the **strongest** one first, and the others behind "Try another way".

⚠️ **Email as a second factor is weaker than it looks.** If an attacker controls Rahul's inbox, they can **reset the password** by email (topic 13) **and** receive the email code. So password + email OTP can fall to one stolen inbox. Use it as a fallback, not the main factor, and never let a password reset skip MFA.

---

### Step 3: Verify the factor (with limits)

```js
POST /login/mfa { mfaToken, method: "totp", code: "471168", rememberDevice: true }
```

Every rule from topics 43–44 still applies:

| Check | Why |
|---|---|
| Method must be one the user has | No guessing a method that isn't set up |
| **Attempts + 1 before** comparing | Parallel guesses can't sneak past the limit |
| **5 wrong** → ticket deleted, back to the password | One ticket can't be brute-forced |
| **10 wrong per user per hour** → `429` | The attacker already has the password, so they can get new tickets |
| TOTP: ±1 step, no replay; email code: HMAC, 5 min, single use; recovery: hashed, single use | Topics 43 and 44 |

After the second factor, delete the ticket. It can never be used again.

---

### Step 4: The session remembers HOW and WHEN

```json
{ "email": "rahul@mail.com", "amr": ["pwd", "totp"], "mfaAt": "2026-11-05T07:53:15.625Z", "viaTrustedDevice": false }
```

- **`amr`** (authentication methods references) = **how** the user logged in. OpenID Connect (topic 36) puts the same field in the ID token, with standard values from RFC 8176 like `pwd`, `otp`, `mfa`, `hwk`. Other parts of your app (or other apps in SSO) can check it.
- **`mfaAt`** = **when** they last passed a second factor. That's what step-up checks (Step 6). OIDC calls a similar idea `auth_time`, and `acr` for "how strong".

Like every login: a **brand-new** session id (session fixation, topic 50).

---

### Step 5: "Remember this device for 30 days"

Typing a code on every login is annoying. So after a successful second factor, with `rememberDevice: true`:

```
Set-Cookie: td=SXIfowPY…; Max-Age=2592000; Path=/login; HttpOnly; SameSite=Lax
```

The server stores `sha256(td)` with `userId`, a label ("Chrome on Windows") and `expiresAt`. At the next login:

```
password ✓  +  td cookie that belongs to THIS user and isn't expired  →  session, no code
```

| ✅ Do | ❌ Don't |
|---|---|
| **Random** token, stored hashed, with an expiry (30 days) | A cookie like `skip2fa=true` or `trusted=rahul` |
| Check that the device belongs to **this** user | Accept any valid device token for any account |
| Still require the **password** | Let the device cookie log in by itself (that's "remember me", topic 15, a different thing) |
| `Path=/login`: the cookie is sent only to login | Send it with every request |
| Show a **list of trusted devices** and a "forget all" button | Hide them |
| Forget all devices on **password change, 2FA reset**, or "log out everywhere" | Keep trusting a device after the password was changed because of a hack |
| Don't offer it after a **recovery code** login | Remember the cybercafé PC Rahul used with his last recovery code |

Logging out does **not** forget the device: the laptop is still Rahul's laptop.

---

### Step 6: Step-up for sensitive actions

Rahul logged in last week on his trusted laptop, without a code. Now someone wants to **change his payout UPI ID**. Being "logged in" isn't enough proof for that.

```js
function requireRecentMfa(req, res, next) {
  if (req.session.mfaAt && Date.now() - req.session.mfaAt <= 5 * 60 * 1000) return next();
  res.status(403).json({ error: "Please confirm it's you", stepUpRequired: true, methods: [...] });
}
app.post("/account/payout", requireSession, requireRecentMfa, ...);
```

The frontend sees `stepUpRequired`, shows the code box, calls `POST /step-up { method, code }`, and the server sets `session.mfaAt = now`. Then it retries the action.

**What counts as sensitive?** Changing the email, phone, password or payout/bank details; turning 2FA off; seeing or regenerating recovery codes; creating API keys (topic 32); deleting the account; big payments; forgetting trusted devices.

GitHub calls this "sudo mode". Banks do it for every new payee.

---

### 🤔 Tricky parts

**1. MFA fatigue (push bombing).** Apps with "Approve this login? [Yes] [No]" push notifications can be abused: an attacker with the password sends 50 pushes at 2 a.m. until the tired user taps **Yes** (this is how Uber was hacked in 2022). Fixes: **number matching** (the login screen shows "42", the user must type 42 in the app), rate limits on pushes, and showing the location of the request.

**2. Account recovery is the back door.** If "I lost my phone" can be solved by answering "mother's maiden name" or a support agent who believes a sad story, your MFA is only as strong as that process. Use recovery codes, a second enrolled factor, or a slow, ID-checked recovery with a waiting period and emails to the user.

**3. Enforcement policy.** Who must use MFA? Common rules: **admins always**; everyone after a grace period ("Turn on 2FA within 7 days"); orgs can require it for all members (GitHub, Google Workspace). While a required user isn't enrolled yet, give a session that can do **only one thing: set up 2FA**.

**4. Risk-based (adaptive) MFA.** Some apps only ask for a code when something looks unusual: a new device, a new country, impossible travel, a TOR exit node. The trusted-device cookie is the simplest version of this.

**5. MFA on every entry point.** If the website asks for a code but the **mobile API**, an old `/api/v1/login`, IMAP/SMTP, or **HTTP Basic** (topic 08) accepts just the password, attackers use that door. Same for "magic link" or "social login": decide whether they count as one factor or two.

**6. Password reset must not skip MFA.** After a reset by email link, the next login still needs the second factor. Otherwise, inbox = full account.

---

### Common beginner mistakes

1. **Creating the session before the second factor.** The code page becomes optional. Use a ticket.
2. **A `mfaVerified: false` flag on a normal session** that some routes forget to check. One missed route = MFA bypass. A ticket that can't reach any route is safer.
3. **Two factors of the same kind** (password + security question) and calling it MFA.
4. **Trusted-device cookie that's guessable or not tied to the user.**
5. **Never expiring trusted devices** or not clearing them after a password change.
6. **No step-up.** A stolen session cookie (XSS, topic 48) can change the bank account.
7. **Letting a trusted-device login count as "recent MFA"** for step-up.
8. **No attempt limits on the code step**, or limits per ticket only.
9. **Sending codes before the password is checked.** Anyone can spam a user's phone.
10. **Password reset that skips MFA.**
11. **Forgetting other entry points** (mobile API, legacy endpoints, Basic auth).
12. **Recovery by security questions or a friendly support chat.** That's the weakest link.

---

### Interview questions

1. **What are the three authentication factors?**
   Something you know (password), have (phone, security key) and are (fingerprint, face). MFA needs factors of **different** kinds.

2. **How do you implement the login flow with MFA?**
   Check the password, then return a short-lived, single-use `mfaToken` stored hashed. The client sends it with the code; the server verifies with attempt limits, deletes the token and creates a new session.

3. **Why not just create the session and redirect to a code page?**
   Because the session already works: an attacker can call any API and skip the page. Nothing should grant access until both factors pass.

4. **How does "remember this device" work safely?**
   A random token in an HttpOnly cookie, stored hashed with the user id and an expiry. It only skips the second factor for **that** user, still needs the password, and is cleared on password change, 2FA reset and "log out everywhere".

5. **What is step-up authentication?**
   Asking for MFA again before a sensitive action, based on how long ago the last MFA was (`mfaAt` / `auth_time`). A week-old session or a trusted-device login must re-verify before changing payout details.

6. **What are `amr` and `acr`?**
   OIDC claims: `amr` lists **how** the user authenticated (`pwd`, `otp`, `hwk`…), `acr` says **how strong** the authentication was. Apps use them to require MFA or step up.

7. **What is MFA fatigue and how do you stop it?**
   Spamming push approvals until the user taps "Approve". Use number matching, rate limits, context (location, app) in the prompt, and alerts on many rejected pushes.

8. **Is email OTP a good second factor?**
   It's weak if the same email can reset the password, because one stolen inbox gives both. Prefer TOTP or passkeys; keep email as a fallback.

9. **How should account recovery work when the user loses their MFA device?**
   Recovery codes first; otherwise a slow, verified process (ID check, waiting period, notifications to every contact), never security questions.

10. **Which actions should require step-up?**
    Changing email, phone, password, payout/bank details, disabling 2FA, viewing recovery codes, creating API keys, deleting the account, large payments.

---

### Quick recap

- MFA = **different kinds** of factors: know + have (+ are)
- Password → **`mfaToken`** (5 min, one use, hashed) → factor → **new session**. Never a session before the factor
- Offer the user's **enrolled** methods, strongest first; email OTP is the weakest second factor
- Limits: **5 tries per ticket**, **10 per user per hour**, codes only **after** the password
- Session stores **`amr`** (how) and **`mfaAt`** (when)
- **Trusted device**: random hashed cookie, per user, 30 days, `Path=/login`, still needs the password, cleared on password change
- **Step-up**: sensitive actions need `mfaAt` within ~5 minutes, even on a trusted device
- Watch out for MFA fatigue, weak recovery and **other entry points**

## Code

A small **Express** app: **PrintKaro** with a full MFA flow. The demo user already has **TOTP** (topic 44), **email codes** (topic 43) and **3 recovery codes**. It shows the `mfaToken` step, choosing a method, "remember this device", and **step-up** before changing the payout UPI ID. Part 1 of [server.js](server.js) is topic 44's TOTP code, trimmed.

📄 **Full code: [server.js](server.js)**. Open it and read the comments, which follow the same steps as the notes above.

Install Express once (from this folder), then start the server:

```bash
npm install
```

```bash
node server.js
```

> Port 3000 busy? Run it on another port: `PORT=3045 node server.js` (Git Bash), then use that port in the commands below. The outputs below were recorded on port 3045.

It prints the demo login, the TOTP secret and the recovery codes (they're new every time it starts):

```
🖨️  PrintKaro MFA flow on http://localhost:3045
   Demo user: rahul@mail.com / correct horse battery
   TOTP secret: TEMBNIH5JK4FUDPLHRIQZO2EBGGZKKE3  (add it to your authenticator app, or: node server.js code <secret>)
   Recovery codes: OENJ-WK5C-7JJV-BZSV  QKRC-JMCV-5IVQ-P7LP  OSKF-5W6L-KSUN-SUBE
```

### Try it with curl (Git Bash)

```bash
APP=http://localhost:3000
SECRET=PASTE_THE_TOTP_SECRET
LOGIN='{"email":"rahul@mail.com","password":"correct horse battery"}'
```

`node server.js code $SECRET` prints the current TOTP code, the same one an authenticator app would show.

🔑 **① Password:** you get a ticket and the list of methods, not a session.

```bash
curl -s -c laptop.jar -b laptop.jar $APP/login -H "Content-Type: application/json" -d "$LOGIN"
```
→ `{"mfaRequired":true,"mfaToken":"1816A0wknh-MO-g5l7htx8H2pOvlzhKxDoh84pjmRUI","methods":["totp","email_otp","recovery_code"]}`

```bash
MFA=PASTE_THE_MFA_TOKEN
```

✅ **② TOTP code + "remember this device":**

```bash
curl -s -i -c laptop.jar -b laptop.jar $APP/login/mfa -H "Content-Type: application/json" -d "{\"mfaToken\":\"$MFA\",\"method\":\"totp\",\"code\":\"$(node server.js code $SECRET)\",\"rememberDevice\":true}"
```
→
```
HTTP/1.1 200 OK
Set-Cookie: sid=t0n2Z3Nm8qTLRXFKfkdzBtiWDqykbfo--j6x2hX12Z0; Max-Age=604800; Path=/; Expires=...; HttpOnly; SameSite=Lax
Set-Cookie: td=SXIfowPYHfS-vMrxk5sEMdMZ5r1g8OS2WEExAqPIxZY; Max-Age=2592000; Path=/login; Expires=...; HttpOnly; SameSite=Lax
{"message":"Logged in with 2FA","method":"totp","rememberedFor":"30 days"}
```

③ **The session knows how and when:**

```bash
curl -s -b laptop.jar $APP/me
```
→ `{"email":"rahul@mail.com","amr":["pwd","totp"],"mfaAt":"2026-11-05T07:53:15.625Z","viaTrustedDevice":false,"payoutUpi":null}`

✅ **④ A sensitive action right after MFA works:**

```bash
curl -s -b laptop.jar $APP/account/payout -H "Content-Type: application/json" -d '{"upiId":"rahul@okaxis"}'
```
→ `{"message":"Payout UPI ID saved","upiId":"rahul@okaxis"}` (and a "your payout UPI ID was changed" email in the terminal)

⑤ **Trusted devices:**

```bash
curl -s -b laptop.jar $APP/devices
```
→ `{"trustedDevices":[{"label":"curl/8.23.0","createdAt":"2026-11-05T07:53:15.626Z","expiresAt":"2026-12-05T07:53:15.626Z"}]}`

💻 **⑥ Log out and log in again on the same "laptop":** the code is skipped.

```bash
curl -s -b laptop.jar -c laptop.jar -X POST $APP/logout
curl -s -c laptop.jar -b laptop.jar $APP/login -H "Content-Type: application/json" -d "$LOGIN"
curl -s -b laptop.jar $APP/me
```
→
```
{"message":"Logged out"}
{"message":"Logged in. Trusted device: 2FA skipped","trustedDevice":"curl/8.23.0"}
{"email":"rahul@mail.com","amr":["pwd"],"mfaAt":null,"viaTrustedDevice":true,"payoutUpi":"rahul@okaxis"}
```

🛡️ **⑦ Step-up:** the trusted-device session can't change the payout.

```bash
curl -s -i -b laptop.jar $APP/account/payout -H "Content-Type: application/json" -d '{"upiId":"rahul@okicici"}'
```
→ `403 Forbidden` with `{"error":"Please confirm it's you","stepUpRequired":true,"methods":["totp","email_otp","recovery_code"],"reason":"You skipped 2FA on a trusted device"}`

✅ **⑧ Confirm with an email code**, then retry:

```bash
curl -s -b laptop.jar -X POST $APP/step-up/email
```
→ `{"message":"We emailed you a 6-digit code"}`, and in the terminal:

```
📧 To: rahul@mail.com
   Subject: 390999 is your PrintKaro code (confirm a sensitive action)
   Didn't just enter your password? Someone else knows it: change it now.
```

```bash
curl -s -b laptop.jar $APP/step-up -H "Content-Type: application/json" -d '{"method":"email_otp","code":"PASTE_THE_CODE"}'
curl -s -b laptop.jar $APP/account/payout -H "Content-Type: application/json" -d '{"upiId":"rahul@okicici"}'
```
→
```
{"message":"Confirmed. You can do sensitive actions for the next few minutes.","validForSeconds":300}
{"message":"Payout UPI ID saved","upiId":"rahul@okicici"}
```
A wrong code here gives `{"error":"Wrong code","attemptsLeft":4}`.

📱 **⑨ A new device ("phone") with a recovery code:** no trusted-device cookie, so it needs a factor. "Remember this device" is **ignored** after a recovery code.

```bash
MFA=$(curl -s -c phone.jar -b phone.jar $APP/login -H "Content-Type: application/json" -d "$LOGIN" | grep -o '"mfaToken":"[^"]*"' | cut -d'"' -f4)
curl -s -i -c phone.jar -b phone.jar $APP/login/mfa -H "Content-Type: application/json" -d "{\"mfaToken\":\"$MFA\",\"method\":\"recovery_code\",\"recoveryCode\":\"PASTE_A_RECOVERY_CODE\",\"rememberDevice\":true}"
```
→
```
HTTP/1.1 200 OK
Set-Cookie: sid=zgy_XR5xMJfkRjrgrlXrIWwjpoJbbqi2d6_jpbwPgoo; Max-Age=604800; Path=/; Expires=...; HttpOnly; SameSite=Lax
{"message":"Logged in with 2FA","method":"recovery_code","rememberedFor":null,"recoveryCodesLeft":2,"tip":"Set up 2FA again on your new phone"}
```
(no `td` cookie)

📧 **⑩ Email code at login:** with a new `mfaToken`, ask for a code, then send it with `"method":"email_otp"`. Within a minute of the last email you get `{"error":"Please wait 60 seconds before asking for a new code"}`.

```bash
MFA=$(curl -s $APP/login -H "Content-Type: application/json" -d "$LOGIN" | grep -o '"mfaToken":"[^"]*"' | cut -d'"' -f4)
curl -s $APP/login/mfa/email -H "Content-Type: application/json" -d "{\"mfaToken\":\"$MFA\"}"
curl -s $APP/login/mfa -H "Content-Type: application/json" -d "{\"mfaToken\":\"$MFA\",\"method\":\"email_otp\",\"code\":\"PASTE_THE_CODE\"}"
```
→ `{"message":"We emailed you a 6-digit code"}`, then `{"message":"Logged in with 2FA","method":"email_otp","rememberedFor":null}`

🛡️ **⑪ Unknown method and brute force:**

```bash
MFA=$(curl -s $APP/login -H "Content-Type: application/json" -d "$LOGIN" | grep -o '"mfaToken":"[^"]*"' | cut -d'"' -f4)
curl -s $APP/login/mfa -H "Content-Type: application/json" -d "{\"mfaToken\":\"$MFA\",\"method\":\"sms\",\"code\":\"123456\"}"; echo
for g in 111111 222222 333333 444444 555555 666666; do curl -s $APP/login/mfa -H "Content-Type: application/json" -d "{\"mfaToken\":\"$MFA\",\"method\":\"totp\",\"code\":\"$g\"}"; echo; done
```
→
```
{"error":"Unknown method","methods":["totp","email_otp","recovery_code"]}
{"error":"Wrong code","attemptsLeft":4}
{"error":"Wrong code","attemptsLeft":3}
{"error":"Wrong code","attemptsLeft":2}
{"error":"Wrong code","attemptsLeft":1}
{"error":"Wrong code","attemptsLeft":0}
{"error":"Login expired, start again"}
```

🧹 **⑫ Forget all trusted devices** (itself a sensitive action, so it needs a recent MFA: do it within 5 minutes of step ⑧). The laptop needs a code again:

```bash
curl -s -b laptop.jar -X POST $APP/devices/revoke-all
curl -s -c laptop.jar -b laptop.jar $APP/login -H "Content-Type: application/json" -d "$LOGIN"
```
→
```
{"message":"Every device will need 2FA again at the next login","removed":1}
{"mfaRequired":true,"mfaToken":"f1_wPgNFvHJA8r_lk2uMge3spaaUp7kFYdy11Hhzf14","methods":["totp","email_otp","recovery_code"]}
```

⏰ **Watch step-up run out:** restart with a 20-second window, log in with a code, change the payout (works), wait 20 seconds, try again → `403` with `"reason":"Your last 2FA check was too long ago"`.

```bash
STEP_UP_SECONDS=20 node server.js
```

> **Windows PowerShell users:** the single quotes, `$(...)`, `grep`, `cut` and the `for` loop work in Git Bash. In PowerShell, use Git Bash or Postman, and set the variable with `$env:STEP_UP_SECONDS=20; node server.js`.
