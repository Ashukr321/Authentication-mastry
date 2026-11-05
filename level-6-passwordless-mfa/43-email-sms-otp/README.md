# 43. Email / SMS OTP

## Notes

### What is an OTP?

An **OTP (one-time password)** is a short code, usually **6 digits** like `283487`, that the server sends to your **email** or **phone (SMS)**. You type it back to prove you can read that inbox or that phone. Every Indian user knows it: the bank OTP, the Swiggy login OTP, the Aadhaar OTP.

It's the **code version of a magic link** (topic 42). Same idea, "prove you own this email or phone", but the secret is something you **type** instead of a link you **click**.

> **One-line answer:** the server makes a random 6-digit code with `crypto.randomInt`, stores an **HMAC** of it with a short expiry (5–10 min) and an **attempt counter**, sends it by email/SMS, and on verify compares in constant time, allows at most ~5 wrong tries per code (and a limit per phone/email per hour), deletes it on success and starts a session.

---

### Why use it?

| Problem | How an OTP helps |
|---|---|
| Users forget passwords | Nothing to remember: the code comes to you |
| The magic link opens on the wrong device (topic 42) | A code can be **typed on any device**: read it on your phone, type it on your laptop |
| Email scanners click links | Nobody "clicks" a code |
| Many users have a phone but rarely check email | SMS reaches them in seconds (that's why India runs on OTPs) |
| You need a **second factor** after the password | The same code flow is a classic 2FA step (topic 45) |

But a 6-digit code is **tiny**: only **1,000,000** possible values. A magic-link token has 2²⁵⁶. So OTPs live or die by **limits**:

| If you forget… | An attacker can… |
|---|---|
| Attempt limits | Try all 1,000,000 codes in a few minutes with a script |
| Expiry | Keep guessing for days |
| Rate limits on sending | Make you send 100,000 SMS (₹ lakhs on your SMS bill) |
| HMAC instead of plain hash | Crack every stored code from a DB leak in milliseconds |

---

### Real-life example: the bank OTP 🏦

Priya buys a ₹5,000 phone online with her card:

1. The bank **sends a 6-digit OTP** to the phone number it has on file → the server sends a code to the email/phone
2. Only the person holding Priya's phone can read it → only the owner can read the inbox / SMS
3. The OTP **expires in a few minutes** → short `expiresAt`
4. Type it wrong 3 times and the bank **blocks the transaction** → attempt limit per code
5. "**Bank staff will never ask for your OTP**" → the message tells you not to share it, because the #1 attack on OTPs is a phone call asking for it

---

### The flow, step by step

#### 📊 Diagrams

Open **[diagrams.html](diagrams.html)** in your browser (just double-click the file) to see:

- **Flow diagram**: every check on "send code" and "verify code"
- **Data flow**: the whole journey, from typing a phone number to being signed in
- **Brute force math**: why 6 digits are safe only with limits

In short: `email/phone → rate limits → code = randomInt(000000–999999) → store HMAC + expiry + attempts → send → verify: attempts++ → constant-time compare → delete → find or create user → new session`

#### Where does each value live? 🔍

| Value | Where | Stored as |
|---|---|---|
| The code `283487` | Only in the email / SMS | `HMAC(secret, challengeId + ":" + code)` |
| `challengeId` | Returned to the browser that asked | The key of the challenge record |
| Attempts left, expiry | Server only | Plain numbers in the challenge record |
| `sid` session cookie | Browser after success | `sha256(sid)` (topic 09) |

---

### Step 1: The user asks for a code

```js
POST /auth/otp/request   { "channel": "sms", "to": "+91 98765-43210" }
```

1. **Normalize** the destination: lowercase the email; turn the phone into international (E.164) format, `+919876543210`. Otherwise `+91 98765 43210` and `9876543210` become three different users with three different rate limits.
2. **Rate limit**:

| Limit | Stops |
|---|---|
| Per IP: 10 requests / 15 min | One bot sending codes to thousands of numbers |
| Per email/phone: one code a minute (the "Resend in 60s" timer) | Flooding someone's phone with SMS |
| Per email/phone: 10 wrong guesses an hour → no new codes | Guessing across many codes (Step 5) |
| SMS only to countries you serve | **SMS pumping fraud** (see Tricky parts) |

The reply contains a `challengeId`. The browser sends it back with the code, so a guess is always checked **against one specific code**.

---

### Step 2: Make the code

```js
const code = crypto.randomInt(0, 1_000_000).toString().padStart(6, "0"); // "000042" is valid too
```

| ✅ Do | ❌ Don't |
|---|---|
| `crypto.randomInt` (secure random) | `Math.random()` (predictable) |
| `padStart(6, "0")` | Drop leading zeros (now there are only ~900,000 codes, and `042` vs `000042` bugs) |
| 6 digits (8 for high-value actions) | 4 digits: 10,000 codes, too easy |
| Expire in **5–10 minutes** | 24 hours |
| A new code **kills the old one** | Three valid codes at once (three times the guessing chance) |

---

### Step 3: Store it as an HMAC, not a plain hash

In topic 12 we stored `sha256(token)`, because a 256-bit token can't be guessed. A 6-digit code **can**: a stolen `sha256("283487")` is cracked by hashing all 1,000,000 codes, which takes **milliseconds**.

So we use an **HMAC with a server secret** (like a pepper, topic 04), and mix in the challenge id:

```js
const hashCode = (challengeId, code) =>
  crypto.createHmac("sha256", OTP_SECRET).update(`${challengeId}:${code}`).digest();
```

A DB leak without `OTP_SECRET` is now useless. And because the code is only valid for 5 minutes, this is plenty.

---

### Step 4: Send it

**Email:**
```
Subject: 283487 is your PrintKaro sign-in code
Your code is 283487. It works for 300 seconds.
PrintKaro will never call you to ask for it. Didn't ask? Ignore this email.
```

**SMS:**
```
272625 is your PrintKaro code. Don't share it with anyone, not even PrintKaro staff.

@printkaro.in #272625
```

- Put the code **at the start** of the subject / SMS, so it's visible in the notification.
- Say "**we'll never ask for it**". The most common OTP attack is social engineering: "Sir, I'm from PrintKaro, please tell me the OTP to cancel your order".
- The last SMS line, `@printkaro.in #272625`, is the **origin-bound one-time code** format. iPhones and Android Chrome offer to autofill the code **only on `printkaro.in`**, never on a phishing site like `printkaro-offers.in`. Add `autocomplete="one-time-code"` to the input so the phone suggests it.
- In India, bulk SMS needs **DLT registration** (a registered sender id and message template) with your SMS provider (MSG91, Twilio, Gupshup).

---

### Step 5: Verify, with strict attempt limits

```js
POST /auth/otp/verify   { "challengeId": "eMPt8v…", "code": "283487" }
```

1. Find the challenge. Not found or expired → `400 "Wrong or expired code"`
2. Hourly failures for this email/phone ≥ 10 → `429`
3. **`attempts += 1` before comparing**, so 50 parallel requests can't all slip in before the counter moves
4. Compare `HMAC(challengeId, code)` with `crypto.timingSafeEqual` (no timing leak, topic 51)
5. Wrong → count a failure; after **5** wrong tries, **delete the code** (ask for a new one)
6. Right → **delete the challenge** (single use) and continue

**The brute-force math:**

| Setup | Chance an attacker guesses right |
|---|---|
| No limits | 100% (try all 1,000,000) |
| 5 tries per code, unlimited new codes | 5 in 1,000,000 per code, but they can ask for a new code every minute… |
| 5 tries per code **and** 10 wrong tries per phone per hour | about 240 guesses a day → about **1 in 4,000 per day**, and the owner gets a pile of codes they didn't ask for |

That's why you need **both** limits. For high-value actions, use 8 digits or lock the account for a human review.

---

### Step 6: Log in

Receiving the code **proves** ownership, so a new user is created **already verified**. Then, exactly like topic 42:

- **New** random session id, stored as `sha256(sid)` (no session fixation, topic 50)
- `HttpOnly`, `SameSite=Lax` cookie (plus `Secure` in production, topic 10)
- Reset the failure counter for this email/phone

---

### 🤔 Tricky parts

**1. SMS is the weakest channel.** An attacker can take over a phone number with a **SIM swap** (convincing the telecom shop to give them a new SIM for your number), or read SMS through **SS7** weaknesses in the phone network, or malware on the phone. NIST calls SMS OTP a "restricted" authenticator. It's still far better than a password alone, but for strong 2FA prefer TOTP (topic 44) or passkeys (topic 46).

**2. SMS pumping (toll fraud).** Attackers make your signup form send thousands of SMS to **premium numbers they own** in faraway countries, and earn a share of your SMS bill. Defenses: send SMS only to countries you serve, rate limit per IP and per number prefix, add a CAPTCHA after a few requests, and set a daily SMS budget alert.

**3. Real-time phishing still works.** A fake site asks for your phone number, triggers a real OTP on the real site, then asks **you** for the code and types it in before it expires. The origin-bound SMS format and passkeys (topic 46) are the fixes.

**4. The OTP alone shouldn't move money or change the email.** For a sensitive action, say **what** the code is for in the message ("Code 482913 to change your email to rahul@work.com"). Otherwise a phisher can ask for a "login" code and use it for something else.

**5. Sign-in OR sign-up.** Because we send a code to any email/phone, the request reply is the same for new and existing users (no enumeration). The `429` "wait 60 seconds" reply only tells someone that a code was **recently** sent to that number, not whether an account exists.

**6. Phone numbers get recycled.** In India an inactive number is given to someone else after about 90 days. If phone is the **only** login, the new owner of Rahul's old number can sign in to Rahul's account. Ask users to also add a verified email, and re-check the number regularly.

---

### Common beginner mistakes

1. **`Math.random()` for the code.** Predictable. Use `crypto.randomInt`.
2. **No attempt limit.** 1,000,000 guesses take minutes. 5 tries per code, then the code dies.
3. **Only a per-code limit.** The attacker asks for a new code and tries 5 more, forever. Add a per-email/phone limit too.
4. **Storing the code in plain text, or as `sha256(code)`.** Both are readable from a DB leak. Use an HMAC with a server secret.
5. **Long expiry.** Minutes, not hours.
6. **Codes that work more than once.** Delete on success.
7. **Comparing with `===`.** Use `crypto.timingSafeEqual` on the HMACs.
8. **Not normalizing phone numbers.** `98765 43210` and `+919876543210` become two users and dodge each other's rate limits.
9. **No resend cooldown or SMS budget.** Your SMS bill becomes the attacker's income.
10. **Returning the code in the API response "for testing" and forgetting to remove it.** It happens in real apps. Never.
11. **Logging the code.** Anyone with log access can sign in.
12. **Not saying "never share this code".** Social engineering is the #1 way OTPs are stolen.

---

### Interview questions

1. **How do you generate an OTP securely?**
   `crypto.randomInt(0, 1_000_000)` padded to 6 digits, never `Math.random()`.

2. **Why is a 6-digit code safe if there are only a million values?**
   Because of limits: a few tries per code, a short expiry, a cap on wrong tries per user per hour, and a resend cooldown. Without them it's broken in minutes.

3. **How do you store OTPs?**
   As an HMAC with a server-side secret (optionally bound to a challenge id), never plain and never a plain SHA-256, because the space is tiny and easy to brute-force offline.

4. **Email OTP vs magic link?**
   Same proof of ownership. A link has 256-bit strength and is one click, but opens on whatever device you click it on and can be burned by scanners. A code works across devices and survives scanners but needs strict attempt limits.

5. **Is SMS OTP secure enough for 2FA?**
   It stops password-only attacks, but SIM swap, SS7 and phishing can defeat it. NIST marks it "restricted". Prefer TOTP or passkeys, and allow SMS only as a fallback.

6. **What is SMS pumping and how do you stop it?**
   Bots trigger SMS to premium numbers the attacker profits from. Limit by IP, number and country, add a CAPTCHA, allow only the countries you serve, and alert on SMS spend.

7. **How do you stop parallel brute-force requests?**
   Increase the attempt counter **before** comparing (atomically in the DB, for example `UPDATE … SET attempts = attempts + 1 … RETURNING attempts`), and refuse once the limit is hit.

8. **What does `@example.com #123456` at the end of an SMS do?**
   It's the origin-bound one-time code format. The phone offers to autofill the code only on that domain, which helps against phishing sites.

9. **What should happen after 5 wrong codes?**
   Kill that code. After more failures across codes, stop sending codes to that email/phone for a while and, for sensitive accounts, alert the owner.

---

### Quick recap

- OTP = a **6-digit code** sent by **email or SMS**: proves you own it
- Code: `crypto.randomInt`, padded, **5–10 min**, **single use**, new code kills the old one
- Store **`HMAC(secret, challengeId:code)`**, never plain, never plain SHA-256
- Verify: **attempts++ first → `timingSafeEqual` → 5 tries per code → 10 fails per hour per destination**
- Send limits: **per IP**, **per destination (60 s)**, **allowed countries** (SMS pumping)
- Message: code first, "**never share it**", `@domain #code` + `autocomplete="one-time-code"`
- SMS is the weakest channel (SIM swap, SS7, phishing): stronger options are TOTP (topic 44) and passkeys (topic 46)

## Code

A small **Express** app: **PrintKaro** with OTP login by email **or** SMS. The "email" and "SMS" are printed in the terminal (pretend it's your inbox or phone). It has a tiny browser UI and also works with curl. Users, codes and sessions are kept in memory, so they disappear when you restart.

📄 **Full code: [server.js](server.js)**. Open it and read the comments, which follow the same steps as the notes above.

Install Express once (from this folder), then start the server:

```bash
npm install
```

```bash
node server.js
```

> Port 3000 busy? Run it on another port: `PORT=3043 node server.js` (Git Bash), then use that port in the commands below. The outputs below were recorded on port 3043.

### Try it in the browser

Open **http://localhost:3000**, pick **Email** or **SMS**, type an email or a `+91` number and press **Send code**. Copy the code from the terminal into the code box (spaces are fine) → **Verify** → "✅ Signed in as …".

### Try it with curl (Git Bash)

```bash
APP=http://localhost:3000
```

✅ **① Ask for an email code:**

```bash
curl -s $APP/auth/otp/request -H "Content-Type: application/json" -d '{"channel":"email","to":"Rahul@Mail.com"}'
```
→ `{"challengeId":"eMPt8vMDM6m7ef3-vpdSe1r8SvDKOzD4wpT6vUJ91Fg","message":"We sent a 6-digit code to rahul@mail.com","expiresInSeconds":300}`

📧 **Check your "inbox":** the terminal where the server is running.

```
📧 To: rahul@mail.com
   Subject: 283487 is your PrintKaro sign-in code
   Your code is 283487. It works for 300 seconds.
   PrintKaro will never call you to ask for it. Didn't ask? Ignore this email.
```

Save both values for the next commands:

```bash
CH=PASTE_THE_CHALLENGE_ID
CODE=PASTE_THE_CODE
```

⏳ **② Ask again right away:** the resend cooldown.

```bash
curl -s -i $APP/auth/otp/request -H "Content-Type: application/json" -d '{"channel":"email","to":"rahul@mail.com"}'
```
→ `429 Too Many Requests`, `Retry-After: 60`, `{"error":"Please wait 60 seconds before asking for a new code"}`

❌ **③ A wrong code:** you see how many tries are left.

```bash
curl -s $APP/auth/otp/verify -H "Content-Type: application/json" -d "{\"challengeId\":\"$CH\",\"code\":\"000000\"}"
```
→ `{"error":"Wrong or expired code","attemptsLeft":4}`

✅ **④ The right code:** signed in, and the account is created.

```bash
curl -s -i -c rahul.jar $APP/auth/otp/verify -H "Content-Type: application/json" -d "{\"challengeId\":\"$CH\",\"code\":\"$CODE\"}"
```
→
```
HTTP/1.1 200 OK
Set-Cookie: sid=1FV6lrjZF2RZn6hV41TagVwHRnSHN_vlFM0NfYBuOqk; Max-Age=604800; Path=/; Expires=...; HttpOnly; SameSite=Lax
{"message":"Signed in","isNewUser":true,"user":{"id":"d86887b0-7a9c-4634-852c-989a47fb850c","email":"rahul@mail.com"}}
```

❌ **⑤ The same code again:** single use → `{"error":"Wrong or expired code"}`

✅ **⑥ Who am I?**

```bash
curl -s -b rahul.jar $APP/me
```
→ `{"id":"d86887b0-...","channel":"email","destination":"rahul@mail.com","createdAt":"2026-11-05T07:33:13.348Z","lastLoginAt":"2026-11-05T07:33:13.348Z"}`

📱 **⑦ An SMS code:** the number is normalized to `+919876543210`.

```bash
curl -s $APP/auth/otp/request -H "Content-Type: application/json" -d '{"channel":"sms","to":"+91 98765-43210"}'
```
→ `{"challengeId":"tv1bt64d...","message":"We sent a 6-digit code to +919876543210","expiresInSeconds":300}`, and in the terminal:

```
📱 SMS to: +919876543210
   272625 is your PrintKaro code. Don't share it with anyone, not even PrintKaro staff.

   @localhost #272625
```

🛡️ **⑧ Brute force:** 5 wrong guesses kill the code. Even the **right** code fails after that.

```bash
CH2=PASTE_THE_SMS_CHALLENGE_ID
for g in 111111 222222 333333 444444 555555; do curl -s $APP/auth/otp/verify -H "Content-Type: application/json" -d "{\"challengeId\":\"$CH2\",\"code\":\"$g\"}"; echo; done
curl -s $APP/auth/otp/verify -H "Content-Type: application/json" -d "{\"challengeId\":\"$CH2\",\"code\":\"PASTE_THE_SMS_CODE\"}"
```
→
```
{"error":"Wrong or expired code","attemptsLeft":4}
{"error":"Wrong or expired code","attemptsLeft":3}
{"error":"Wrong or expired code","attemptsLeft":2}
{"error":"Wrong or expired code","attemptsLeft":1}
{"error":"Wrong or expired code","attemptsLeft":0}
{"error":"Wrong or expired code"}
```

🛡️ **⑨ The hourly limit:** wait a minute, ask for a new SMS code and make 5 more wrong guesses (the same loop with the new challenge id). That's 10 failures for this number in an hour, so:

```bash
curl -s $APP/auth/otp/request -H "Content-Type: application/json" -d '{"channel":"sms","to":"+919876543210"}'
```
→ `{"error":"Too many wrong codes. Try again in an hour."}`

🛡️ **⑩ SMS pumping guard:** only `+91` numbers get an SMS.

```bash
curl -s $APP/auth/otp/request -H "Content-Type: application/json" -d '{"channel":"sms","to":"+447700900123"}'
```
→ `{"error":"We can't send SMS to this country"}`

👋 **⑪ Log out:**

```bash
curl -s -b rahul.jar -c rahul.jar -X POST $APP/logout
curl -s -b rahul.jar $APP/me
```
→ `{"message":"Logged out"}`, then `{"error":"Not signed in"}`

⏰ **Watch a code expire:** restart with a 10-second expiry, ask for a code, wait 10 seconds, then verify → `"Wrong or expired code"`.

```bash
OTP_TTL_SECONDS=10 node server.js
```

> **Windows PowerShell users:** the single quotes in `-d '...'`, the `for` loop and `VAR=value node ...` work in Git Bash. In PowerShell, use Git Bash, Postman, or set the variable with `$env:OTP_TTL_SECONDS=10; node server.js`. Restart the server to reset all limits.
