# 44. TOTP (Authenticator App)

## Notes

### What is TOTP?

**TOTP (Time-based One-Time Password)** is the 6-digit code that changes **every 30 seconds** in apps like **Google Authenticator, Microsoft Authenticator, Authy** or **1Password**. When you turn on "two-factor authentication" on GitHub, AWS or your bank's net banking, this is usually what you scan.

The big idea: your phone and the server share **one secret**, set up once with a QR code. After that, both sides compute the same code **from the secret and the current time**, with **no network at all**. Nothing is sent to you, so there's no SMS to intercept (topic 43).

> **One-line answer:** at setup, the server makes a random 160-bit secret, shows it as a QR code (`otpauth://totp/…?secret=…`), and turns 2FA on only after the user types one correct code. At login, after the password, it computes `HOTP(secret, floor(now / 30))` for the current step ±1 and compares in constant time, refuses a code that was already used, limits wrong tries, and offers single-use recovery codes for a lost phone. The secret is stored **encrypted** (not hashed) because the server needs it to compute codes.

---

### Why use it?

| Problem | How TOTP helps |
|---|---|
| Passwords leak and get reused (credential stuffing, topic 52) | A stolen password alone is useless: the attacker also needs the code from your phone |
| SMS OTP can be stolen by SIM swap / SS7 (topic 43) | Nothing travels over the phone network. The code is made **on** the phone |
| SMS costs money and fails abroad | TOTP is **free** and works **offline**, even in flight mode |
| Email OTP is only as safe as the inbox | The secret lives only on the user's device and your server |

What it **doesn't** fix:

| Weakness | Why |
|---|---|
| **Real-time phishing** | A fake site asks for the password **and** the code, and uses both within 30 seconds. Only passkeys (topic 46) stop this. |
| **Lost phone** | No phone, no code. That's why you need recovery codes. |
| **Server secret leak** | If your DB **and** encryption key leak, attackers can make codes for everyone. Encrypt the secrets and keep the key elsewhere. |

---

### Real-life example: twin clocks in a bank locker room 🕰️

Rahul has a locker at a bank in Pune.

1. On day one, the manager gives Rahul a **special card** with a secret pattern and keeps a **copy** in the safe → the **shared secret** (the QR code)
2. To open the locker, Rahul looks at the **clock** and his card and reads out the number for **this half-minute** → the app computes the code from **secret + time**
3. The manager does the same with his copy and the same clock. Same numbers? Door opens → the server computes and compares
4. The manager accepts the number from a half-minute ago too, because Rahul's watch might be a bit slow → the **±1 step window**
5. A number that was already used today is refused, even if it's still "fresh" → **replay protection**
6. Lost the card? Rahul uses one of the **10 emergency slips** he got on day one, each works once → **recovery codes**

---

### The flow, step by step

#### 📊 Diagrams

Open **[diagrams.html](diagrams.html)** in your browser (just double-click the file) to see:

- **How a code is made**: secret + time → HMAC-SHA1 → 6 digits
- **Setup flow**: secret → QR → first code → 2FA on → recovery codes
- **Login data flow**: password → `mfaToken` → code → session, with every check

In short: `setup: secret → QR → verify one code → enable + recovery codes` and `login: password ✓ → mfaToken → code for step ±1 ✓, not used before ✓ → session`

#### Where does each secret live? 🔍

| Secret | Where | Stored as |
|---|---|---|
| TOTP secret (`63H4RT77…`) | The user's authenticator app + your DB | **Encrypted** (AES-256-GCM). The server must read it back, so it **can't** be hashed. |
| Encryption key | A KMS / secret manager, **not** the DB | Outside the database (topic 54) |
| The 6-digit code | The user's screen, for 30 s | Never stored. Only its **time step** is saved as "last used" |
| Recovery codes | Printed / saved by the user | `sha256(code)`, each deleted when used |
| `mfaToken` | Between the password step and the code step | `sha256(token)`, 5 minutes, one use |

---

### Step 1: How a code is made (HOTP + time)

TOTP is built on **HOTP** (RFC 4226): a code from a secret and a **counter**. TOTP (RFC 6238) just uses **time** as the counter.

```js
function hotp(secret, counter) {
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(counter));                     // counter as 8 bytes
  const hmac = crypto.createHmac("sha1", secret).update(msg).digest(); // 20 bytes
  const offset = hmac[hmac.length - 1] & 0x0f;                // last 4 bits = where to read
  const number = hmac.readUInt32BE(offset) & 0x7fffffff;      // 4 bytes, drop the sign bit
  return String(number % 1_000_000).padStart(6, "0");         // last 6 digits
}

const step = Math.floor(Date.now() / 1000 / 30); // how many 30-second steps since 1970
const code = hotp(secret, step);
```

- **SHA-1 here is fine.** SHA-1 is broken for *collisions*, but HMAC-SHA1 is still safe, and every authenticator app supports it. (SHA-256 is allowed by the standard but many apps ignore it.)
- `padStart(6, "0")`: codes like `012345` are normal.
- Our [server.js](server.js) builds this from scratch with Node's `crypto` and checks it against the **official RFC test vectors** on startup. In a real project use a tested library such as **otplib** or **speakeasy**.

---

### Step 2: Setup: make the secret and show the QR code

```js
const secret = crypto.randomBytes(20);  // 160 bits, as RFC 4226 recommends
const secretBase32 = base32Encode(secret); // "63H4RT77L3I2YXIGVEZE3QJP2N65EAO2"
```

The QR code is just this URL:

```
otpauth://totp/PrintKaro:rahul%40mail.com?secret=63H4RT77L3I2YXIGVEZE3QJP2N65EAO2&issuer=PrintKaro&algorithm=SHA1&digits=6&period=30
```

| Part | Meaning |
|---|---|
| `PrintKaro:rahul%40mail.com` | The label shown in the app (issuer + account) |
| `secret=` | The shared secret in **base32** (letters A–Z and digits 2–7) |
| `issuer=` | Your app's name, so users can tell their 15 accounts apart |
| `digits`, `period`, `algorithm` | 6 digits, 30 seconds, SHA1 (the defaults every app supports) |

| ✅ Do | ❌ Don't |
|---|---|
| Make the QR code **on your server or in the browser** | Send the secret to an **online QR generator** (you just gave away the secret) |
| Also show the secret as text ("Can't scan? Enter this key") | QR only (desktop users, screen readers) |
| Only allow setup for a **logged-in** user (ideally a recent login) | Let anyone call setup |
| Store the secret **encrypted** | Store it in plain text, or hashed (you can't compute codes from a hash) |

---

### Step 3: Enable: prove the app works before turning 2FA on

The setup step makes the secret, but **2FA stays off** until the user types one correct code:

```js
POST /2fa/enable { "code": "678117" }
```

Why? If Rahul scanned it wrong (or never scanned it), turning 2FA on would **lock him out** at the next login.

On success:
1. `enabled = true`
2. Save this code's time step as `lastUsedStep` (it can't be used again)
3. Make **10 recovery codes**, show them **once**, store only their hashes
4. In a real app: email "2FA was turned on" and log out other sessions

---

### Step 4: Login: password first, then the code

```
POST /login       { email, password }     → 200 { mfaRequired: true, mfaToken }   (NO session yet)
POST /login/2fa   { mfaToken, code }      → 200 + Set-Cookie: sid                   (now you're in)
```

The `mfaToken` is a short-lived ticket (5 minutes, one use, stored as a hash) that says "this person got the password right". It is **not** a session. It can do exactly one thing: be exchanged together with a code for a session. (Topic 45 covers the full MFA flow and how to remember devices.)

| ✅ Do | ❌ Don't |
|---|---|
| Give a **ticket** after the password, a **session** after the code | Give a session after the password and "ask" for the code on the next page (users skip the page) |
| Same error for a wrong code whether TOTP or recovery | Tell attackers which part was wrong |
| Count the attempt **before** comparing | Compare first, count later (parallel guesses sneak past) |

---

### Step 5: Check the code: window, replay, limits

```js
for (let step = now - 1; step <= now + 1; step++) {
  if (step <= user.totp.lastUsedStep) continue;          // already used: replay
  if (timingSafeEqual(hotp(secret, step), code)) return step;
}
```

| Check | Why |
|---|---|
| Accept steps **now − 1, now, now + 1** | Phone clocks drift, and people type slowly. That's a **90-second** window, no more |
| Refuse a step **≤ `lastUsedStep`** | Someone who saw the code (over your shoulder, or a phishing site) can't use it a second time |
| `crypto.timingSafeEqual` | No timing leaks (topic 51) |
| **5 wrong codes** per `mfaToken` | Then the ticket dies: type the password again |
| **10 wrong codes per user per hour** | Stops guessing across many tickets (the attacker already has the password!) |

The brute-force math: with ±1 there are **3 valid codes** at any moment, so one guess has a 3-in-1,000,000 chance. 10 guesses an hour ≈ 240 a day ≈ **1 in 1,400 per day**. Fine, plus the user should be alerted after a lockout, because the attacker clearly has the password.

---

### Step 6: Recovery codes (for a lost phone)

```
RPYG-GV33-43YG-WWMQ   6XYT-UOKC-S6Y5-CTLC   TJZZ-MMSO-HX5I-XFDJ  …  (10 codes)
```

- **80 random bits** each, so `sha256` is enough to store them (like topic 12's tokens)
- **Shown once**, at enable time. Tell the user to print or save them
- **Single use**: delete the hash when used, and show "9 recovery codes left"
- Accept them with or without dashes, any case
- When a user is down to a few, suggest making new ones (which kills the old ones)

Without recovery codes, a lost phone = a support ticket where someone has to prove who they are… which is exactly where attackers social-engineer your support team.

---

### Step 7: Turning 2FA off

Require a **current code** (or a recovery code), not just a session. Otherwise someone at Rahul's unlocked laptop can switch 2FA off in two clicks and then use his stolen password from anywhere. Email the user when it happens.

---

### 🤔 Tricky parts

**1. Hash or encrypt the secret?** Passwords are **hashed** because the server only needs to *check* them. The TOTP secret must be **used** to compute codes, so it must be **encrypted**, with the key stored **outside** the database (KMS, Vault, env from a secret manager). A DB dump alone is then useless.

**2. Clock drift.** If the server's clock is wrong, **everyone's** codes fail. Run NTP on servers. If one user's phone is off by minutes, tell them to turn on "automatic time" (Google Authenticator also has "Time correction for codes").

**3. TOTP is phishable.** A fake `printkaro-login.in` collects the password and the code and replays both to the real site within seconds. Replay protection doesn't help: the attacker uses the code **first**. Only origin-bound methods like passkeys (topic 46) stop this.

**4. Cloud-synced authenticator apps.** Google Authenticator and Authy can sync secrets to the cloud. Convenient (a new phone keeps the codes), but now the cloud account is part of your security. It's the user's choice; just know it.

**5. Don't trust the client.** The browser must never compute or check the code. It just sends what the user typed.

**6. HOTP vs TOTP.** HOTP uses a counter that goes up on each button press (old hardware tokens). It gets out of sync when the user presses without logging in. TOTP replaced it almost everywhere.

---

### Common beginner mistakes

1. **Storing the TOTP secret in plain text.** A DB leak = every user's 2FA is gone. Encrypt it.
2. **Hashing the secret.** Then the server can't compute codes. Encrypt, don't hash.
3. **Turning 2FA on before the first code is verified.** A bad scan locks the user out.
4. **Giving a full session after the password.** The 2FA page becomes optional. Use a short ticket.
5. **No replay protection.** A code seen once can be used again for up to 90 seconds.
6. **A huge window** (±10 steps = 10 minutes). Each extra step makes guessing easier. ±1 is the norm.
7. **No attempt limit on the code.** The attacker already has the password: 1,000,000 guesses will do it.
8. **Using an online QR generator.** It now knows the secret.
9. **No recovery codes**, or storing them in plain text.
10. **Letting a session turn 2FA off without a code.**
11. **Using `===` to compare.** Use `timingSafeEqual`.
12. **`Math.random()` for the secret.** Use `crypto.randomBytes(20)`.

---

### Interview questions

1. **How does TOTP work?**
   The server and app share a secret. Both compute `HMAC-SHA1(secret, floor(unixTime / 30))`, take 4 bytes using dynamic truncation, and keep the last 6 digits. Same secret + same time = same code, with no network needed.

2. **What's the difference between HOTP and TOTP?**
   HOTP uses an event counter, TOTP uses the current 30-second time step as the counter.

3. **How do you store the TOTP secret?**
   Encrypted (for example AES-256-GCM) with a key kept in a KMS or secret manager, not hashed, because the server needs the original to compute codes.

4. **How do you handle clock drift?**
   Accept the previous and next step (±30 s), keep server clocks synced with NTP, and tell users to enable automatic time on their phone.

5. **How do you stop a TOTP code from being reused?**
   Save the last accepted time step per user and refuse any step at or before it.

6. **Why verify a code before enabling 2FA?**
   To prove the app was set up correctly, otherwise the user is locked out on the next login.

7. **What happens if the user loses their phone?**
   They use a single-use recovery code (shown once at setup, stored hashed), then set up 2FA again. Without codes, an identity-checked support process.

8. **Is TOTP phishing-resistant?**
   No. A real-time phishing proxy can relay the password and the code. Passkeys / WebAuthn are phishing-resistant because they're bound to the site's origin.

9. **TOTP vs SMS OTP?**
   TOTP is free, works offline and can't be stolen by SIM swap or SS7. SMS works on any phone without an app. Both are phishable.

10. **How does login look with 2FA?**
    Password → a short-lived, single-use `mfaToken` (no session) → the code → a real session.

---

### Quick recap

- TOTP = `HOTP(secret, floor(now / 30))`: **6 digits, every 30 s, offline**
- Secret: `randomBytes(20)`, base32, shared via an **`otpauth://` QR code** made on **your** side
- Secret stored **encrypted**, key **outside** the DB
- **Verify one code before enabling**, then show **10 recovery codes once** (stored hashed, single use)
- Login: **password → `mfaToken` → code → session**
- Check: **window ±1**, **no replay** (`lastUsedStep`), **`timingSafeEqual`**, **5 tries per ticket**, **10 per user per hour**
- Disabling 2FA needs a **code**
- Still phishable: passkeys (topic 46) fix that

## Code

A small **Express** app: **PrintKaro** with password login and optional TOTP 2FA. **Part 1** of [server.js](server.js) is TOTP from scratch (base32, HOTP, TOTP, the verify window), checked against the RFC test vectors every time it starts. **Part 2** is the app: setup, enable, login with a code or a recovery code, and disable.

There's one demo user: **`rahul@mail.com` / `correct horse battery`** (signup was topic 06). Everything is kept in memory, so it resets when you restart.

📄 **Full code: [server.js](server.js)**. Open it and read the comments, which follow the same steps as the notes above.

Install Express once (from this folder), then start the server:

```bash
npm install
```

```bash
node server.js
```

> Port 3000 busy? Run it on another port: `PORT=3044 node server.js` (Git Bash), then use that port in the commands below. The outputs below were recorded on port 3044.

**Getting codes:** use a real authenticator app (Google Authenticator, Microsoft Authenticator, Authy…): choose **"Enter a setup key"**, type the `secret` from step ③, and pick **Time based**. Or use the built-in helper, which computes the same code your phone would:

```bash
node server.js code PASTE_YOUR_SECRET
```
→ `678117  (changes in 5 s)`

### Try it with curl (Git Bash)

```bash
APP=http://localhost:3000
```

✅ **① Log in without 2FA:** you get a session straight away.

```bash
curl -s -c rahul.jar $APP/login -H "Content-Type: application/json" -d '{"email":"rahul@mail.com","password":"correct horse battery"}'
```
→ `{"message":"Logged in (no 2FA yet: turn it on with POST /2fa/setup)"}`

② **Check:**

```bash
curl -s -b rahul.jar $APP/me
```
→ `{"id":"d82e6686-...","email":"rahul@mail.com","twoFactorEnabled":false,"recoveryCodesLeft":0}`

🔑 **③ Set up 2FA:** the server makes a secret. 2FA is **not** on yet.

```bash
curl -s -b rahul.jar -X POST $APP/2fa/setup
```
→
```json
{"secret":"63H4RT77L3I2YXIGVEZE3QJP2N65EAO2","otpauthUrl":"otpauth://totp/PrintKaro:rahul%40mail.com?secret=63H4RT77L3I2YXIGVEZE3QJP2N65EAO2&issuer=PrintKaro&algorithm=SHA1&digits=6&period=30","message":"Add this to your authenticator app, then send a code to POST /2fa/enable"}
```

```bash
SECRET=PASTE_YOUR_SECRET
```

❌ **④ Enable with a wrong code:**

```bash
curl -s -b rahul.jar $APP/2fa/enable -H "Content-Type: application/json" -d '{"code":"123456"}'
```
→ `{"error":"Wrong code. Check the time on your phone and try again."}`

✅ **⑤ Enable with the real code:** you get 10 recovery codes, **once**.

```bash
CODE=$(node server.js code $SECRET | cut -c1-6)
curl -s -b rahul.jar $APP/2fa/enable -H "Content-Type: application/json" -d "{\"code\":\"$CODE\"}"
```
→
```json
{"message":"2FA is on. Save these recovery codes somewhere safe: each works once, and we can't show them again.","recoveryCodes":["RPYG-GV33-43YG-WWMQ","6XYT-UOKC-S6Y5-CTLC","TJZZ-MMSO-HX5I-XFDJ","BLDN-GE3L-FXWD-PTH2","DLTE-HOLU-CE4I-IHL6","6M2G-IU52-PJWY-LCHQ","65W2-NLPQ-KGR4-D2ZJ","JZ4O-OGRI-UMHI-W5KM","EC5P-MXFE-D72U-OKHQ","JNWR-V5NP-YSJR-LELQ"]}
```

🔐 **⑥ Log out and log in again:** the password now gives only a ticket, **no** `Set-Cookie`.

```bash
curl -s -b rahul.jar -c rahul.jar -X POST $APP/logout
curl -s -i -c rahul.jar $APP/login -H "Content-Type: application/json" -d '{"email":"rahul@mail.com","password":"correct horse battery"}'
```
→
```
HTTP/1.1 200 OK
{"mfaRequired":true,"mfaToken":"lOBHj1m6uInVl1eHeLPyqj-mWht3oEsWutkDQ_jfwVo","methods":["totp","recovery_code"],"message":"Enter the 6-digit code from your authenticator app"}
```

```bash
MFA=PASTE_THE_MFA_TOKEN
```

🛡️ **⑦ Replay:** the code you used in ⑤ is refused, even if it's still on screen.

```bash
curl -s $APP/login/2fa -H "Content-Type: application/json" -d "{\"mfaToken\":\"$MFA\",\"code\":\"$CODE\"}"
```
→ `{"error":"Wrong code","attemptsLeft":4}`

✅ **⑧ Wait for the next code** (up to 30 seconds), then:

```bash
CODE=$(node server.js code $SECRET | cut -c1-6)
curl -s -i -c rahul.jar $APP/login/2fa -H "Content-Type: application/json" -d "{\"mfaToken\":\"$MFA\",\"code\":\"$CODE\"}"
```
→
```
HTTP/1.1 200 OK
Set-Cookie: sid=nQTvpH4cjI1BDLleDo7k0OR1pJPFe7YZbrTnun50cWw; Max-Age=604800; Path=/; Expires=...; HttpOnly; SameSite=Lax
{"message":"Logged in with 2FA","method":"totp"}
```

❌ **⑨ The ticket is single-use:** the same `mfaToken` again → `{"error":"Login expired, start again"}`

🆘 **⑩ Lost your phone? Use a recovery code** (dashes and case don't matter). Log in with the password first to get a new `mfaToken`:

```bash
MFA=$(curl -s $APP/login -H "Content-Type: application/json" -d '{"email":"rahul@mail.com","password":"correct horse battery"}' | grep -o '"mfaToken":"[^"]*"' | cut -d'"' -f4)
curl -s $APP/login/2fa -H "Content-Type: application/json" -d "{\"mfaToken\":\"$MFA\",\"recoveryCode\":\"rpyg-gv33-43yg-wwmq\"}"
```
→ `{"message":"Logged in with 2FA","method":"recovery_code","recoveryCodesLeft":9}`

Use the same recovery code again (with a new `mfaToken`) → `{"error":"Wrong code","attemptsLeft":4}`: each one works once.

🛡️ **⑪ Brute force:** 5 wrong codes kill the ticket.

```bash
MFA=$(curl -s $APP/login -H "Content-Type: application/json" -d '{"email":"rahul@mail.com","password":"correct horse battery"}' | grep -o '"mfaToken":"[^"]*"' | cut -d'"' -f4)
for g in 111111 222222 333333 444444 555555; do curl -s $APP/login/2fa -H "Content-Type: application/json" -d "{\"mfaToken\":\"$MFA\",\"code\":\"$g\"}"; echo; done
```
→
```
{"error":"Wrong code","attemptsLeft":4}
{"error":"Wrong code","attemptsLeft":3}
{"error":"Wrong code","attemptsLeft":2}
{"error":"Wrong code","attemptsLeft":1}
{"error":"Wrong code","attemptsLeft":0}
```
Then the ticket is gone: `{"error":"Login expired, start again"}`. Keep going with new tickets and after **10** wrong codes in an hour, even the **right** code gets `429` `{"error":"Too many wrong codes. Try again in an hour."}` (restart the server to reset it).

🔓 **⑫ Turn 2FA off:** needs a fresh code (a wrong one gives `{"error":"Wrong code"}`).

```bash
curl -s -b rahul.jar $APP/2fa/disable -H "Content-Type: application/json" -d "{\"code\":\"$(node server.js code $SECRET | cut -c1-6)\"}"
```
→ `{"message":"2FA is off"}`. If the code is the one you **just** used to log in, it's refused as a replay: wait for the next one.

> **Windows PowerShell users:** the single quotes in `-d '...'`, `$(...)`, `cut`, `grep` and the `for` loop work in Git Bash. In PowerShell, use Git Bash or Postman.
