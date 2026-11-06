# 52. Credential Stuffing Defense

## Notes

### What is credential stuffing?

**Credential stuffing** is when an attacker takes **email + password pairs leaked from another website** and tries them, automatically, on **your** login page. It works because people **reuse passwords**: if Rahul's password leaked from a hacked food-delivery app, it probably also opens his shopping account.

It's not guessing. Brute force tries many passwords on one account. Credential stuffing tries **one known-real password per account**, across millions of accounts, from thousands of IP addresses. OWASP lists it as automated threat **OAT-008**.

> **One-line answer:** Credential stuffing = replaying leaked passwords on your login, one try per account, from many IPs, so per-IP limits and lockout (topic 16) don't see it. Defend in layers: **reject breached passwords** (k-anonymity check), **watch failures site-wide** to detect the attack, **challenge unknown devices** while under attack, **trust known devices** with a cookie so real users aren't hurt, **verify new devices** by email, and above all **MFA / passkeys**, which make a stolen password useless.

---

### Why it matters

| Problem | Example |
|---|---|
| **Password reuse is normal** | Most people use the same few passwords everywhere. One leak elsewhere = a working key to your site |
| **Leaked lists are huge and cheap** | "Combo lists" with millions of `email:password` lines are sold or shared for free |
| **A tiny success rate is still a lot** | The hit rate is often quoted at about **0.1% to 2%**. 1% of 1 million tries = **10,000 hijacked accounts** |
| **It looks like normal traffic** | Each IP sends a few requests, each account gets **one** try. No single counter goes red |
| **Your site gets blamed** | "ChaiKart accounts hacked" is the headline, even though the passwords leaked from somewhere else |
| **Real incidents** | PayPal (2022, about 35,000 accounts), 23andMe (2023: about 14,000 accounts logged into, then data on millions of relatives exposed) |

---

### Real-life example: the stolen keyring 🔑

Rahul uses **the same key** for his house, his office locker and his scooter. One day his gym gets robbed, and the thief walks away with a box of **everyone's** keys, each with a name tag.

1. The thief doesn't pick locks (that's brute force). He walks down the street and tries **Rahul's tagged key in Rahul's door**, Priya's key in Priya's door → **one try per door, a real key each time**
2. The building guard watches each door: "lock it after 5 wrong tries" → never triggers, every door only gets **one** try (**per-account lockout fails**)
3. The thief sends **100 different helpers**, each trying a few doors → "stop anyone who tries many doors" fails too (**per-IP limits fail**)
4. What works: the guard notices **"suddenly lots of strangers are trying lots of doors"** and starts asking **every unknown face** to sign the register (**site-wide detection + challenge**)
5. Residents the guard **recognises** walk straight in (**trusted-device cookie**)
6. A stranger with the right key still gets a call to the flat owner: "someone's at your door, is it you?" (**new-device email code**)
7. The real fix: doors that need the key **and** your fingerprint (**MFA / passkeys**)
8. And the society refuses to let anyone register a key that's **already in the thief's box** (**breached-password check**)

---

### The attack, and where it's stopped

#### 📊 Diagrams

Open **[diagrams.html](diagrams.html)** in your browser (just double-click the file) to see:

- **Flow diagram**: one login request going through every defense layer
- **Data flow**: the bot's combo list hitting ChaiKart, the site switching to attack mode, and the email code stopping the one correct password
- **Why topic 16 isn't enough**: brute force vs password spraying vs credential stuffing, and which counter catches each
- **k-anonymity**: how you check a password against a breach list without sending the password

In short: `breach elsewhere → combo list → bot tries each pair once, from many IPs → site-wide failure spike → attack mode → unknown devices must solve a challenge → right password on a new device still needs the email code → MFA makes the password alone worthless`

#### Three attacks that look alike

| Attack | Tries | Caught by per-account lockout? | Caught by per-IP limit? |
|---|---|---|---|
| **Brute force** | Many passwords, **one** account | ✅ Yes | ✅ If from one IP |
| **Password spraying** | **One** common password (`Password@123`), many accounts | ❌ 1 try each | ❌ If spread over IPs |
| **Credential stuffing** | One **leaked, real** password per account, many accounts | ❌ 1 try each | ❌ Thousands of IPs (residential proxies, botnets) |

---

### Step 1: Know why topic 16 isn't enough

Topic 16 gave us two counters: failures **per IP** and failures **per account**. Keep them, they stop brute force. But look at what a stuffing bot sends:

```
203.0.113.1   amit.k@mail.com   qwerty123     ← 1 try for this account, 1 try from this IP
203.0.113.2   sneha.r@mail.com  iloveyou      ← 1 try, 1 try
...
203.0.113.7   rahul@mail.com    rahul@1995    ← 200 OK  😱
```

No IP and no account ever reaches 5 or 10. Our demo's `/vulnerable/login` has **exactly** topic 16's defenses, and the bot gets into Rahul's account on the first run.

So we need counters that look at the **whole site**, and defenses that don't depend on counting at all.

---

### Step 2: Reject breached passwords (k-anonymity)

If a password is **already in a breach list**, attackers will try it. NIST SP 800-63B says: when a user sets a password, **check it against known-breached and common passwords and refuse it**. (The same guideline says **no** forced complexity rules like "1 symbol, 1 number" and **no** forced change every 90 days.)

The famous list is **Have I Been Pwned → Pwned Passwords**: hundreds of millions of leaked passwords. But how do you check a password **without sending it** to someone else's server? **k-anonymity**:

```js
const hash = sha1(password).toUpperCase();       // "25C2C9AFDD83B8D34234AA2881CC341C09689AAA"
const prefix = hash.slice(0, 5);                 // "25C2C"  ← the ONLY thing we send
const suffix = hash.slice(5);                    // "9AFDD83B8D34…"  ← stays on our server
const body = await (await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, { headers: { "Add-Padding": "true" } })).text();
const hit = body.split("\r\n").find((line) => line.startsWith(suffix + ":"));  // "9AFDD83B…:120000" → breached
```

1. Hash the password with SHA-1 (only for this lookup, **never** to store passwords: storage stays scrypt/bcrypt/argon2, topic 04)
2. Send the **first 5 characters** of the hash
3. The API returns **every** hash suffix starting with those 5 characters (hundreds of them), with a count
4. You look for your suffix **locally**. The API can't tell which of the hundreds you cared about
5. `Add-Padding: true` adds fake lines with count `0`, so even the **size** of the reply reveals nothing

| ✅ Do | ❌ Don't |
|---|---|
| Check at **signup, password change and password reset** | Only check at signup and forget the other two |
| Also check at **login** and, if breached, ask for a reset / extra verification | Send the full password or full hash to any API |
| Show a clear message: "This password appeared in 1,20,000 breaches" | Fail **closed** (block every signup) when the API is down, unless you can afford it |
| Allow long passphrases (64+ characters) | Add complexity rules that push people to `Password@123` |

Our demo rejects `Password@123` at signup, and only `"25C2C"` ever leaves the server.

---

### Step 3: Detect the attack site-wide

One account or one IP looks innocent. The **whole site** does not. Signals a security team watches:

| Signal | Normal day | Stuffing attack |
|---|---|---|
| Failed logins per minute (site-wide) | Steady baseline | Sudden spike, many times the baseline |
| Share of failures for **emails that don't exist** | Low (typos) | **High**: the combo list is full of other sites' users |
| Login **success rate** | High (most people know their password) | Drops sharply |
| Distinct IPs / accounts per minute | Normal | Many IPs, each touching different accounts |
| Same User-Agent / TLS fingerprint on many IPs | Rare | Common (one bot tool) |
| Logins from data-centre or proxy IP ranges | Few | Many |

Our demo keeps a 5-minute list of failures and switches into **attack mode** when it passes a threshold:

```js
recentFailures.push({ at: Date.now(), ip, email, knownUser: !!user });
if (!isAttackMode() && recentFailures.length >= ATTACK_THRESHOLD) attackModeUntil = Date.now() + ATTACK_MODE_MS;
```

After the bot's first 5 failures, `/security/status` shows: `"failedLoginsLast5Min":5,"distinctIps":5,"distinctAccounts":5,"unknownEmailShare":"80%"`. Five IPs, five accounts, 80% of them not even our users: that's stuffing, not five forgetful people.

> The demo's threshold is a fixed `5` so you can trip it with curl. A real site compares to its **own baseline** (time of day, day of week) and also alerts a human (topic 55).

---

### Step 4: Under attack, challenge unknown devices

Once you know you're under attack, make **automated** login attempts expensive, without blocking anyone outright:

```js
if (isAttackMode() && !trustedDevice(req, email) && !challengeOk(req.body.challenge, req.body.solution)) {
  return res.status(403).json({ error: "Unusual login activity…", challengeRequired: true });
}
// only now do we check the password
```

- The challenge is checked **before the password**. The bot learns nothing about whether its password was right, and you don't spend a slow scrypt hash per guess.
- Our demo uses **proof of work**: "find a number `n` so that `sha256(challenge + n)` starts with `0000`". It took 0.15 seconds in Node. A browser barely notices, but a bot doing millions of tries pays for millions of these.
- Each challenge is **single-use** and **expires** in 2 minutes, so one solution can't be replayed.
- Real sites use a **bot-detection service** or CAPTCHA here (Cloudflare Turnstile, Google reCAPTCHA, hCaptcha, Akamai/Imperva bot management). They look at browser signals the bot can't easily fake.

| ✅ Do | ❌ Don't |
|---|---|
| Turn challenges on **when the signals say attack**, or always for risky logins | Show a CAPTCHA to every user on every login forever (people leave) |
| Check the challenge before the password | Tell the bot "password correct, now solve a CAPTCHA" |
| Treat CAPTCHAs as a **speed bump** | Treat them as a wall: CAPTCHA-solving farms exist and cost cents |

---

### Step 5: Trust known devices (so real users aren't punished)

During an attack, Priya, who logs in from the **same laptop every day**, shouldn't have to solve puzzles. After every successful login we set a long-lived random **device cookie**:

```js
const did = randomToken();
devices.set(sha256(did), { email, expiresAt: Date.now() + DEVICE_TTL_MS }); // stored hashed, like sessions
res.cookie("did", did, { httpOnly: true, sameSite: "lax", maxAge: DEVICE_TTL_MS });
```

On the next login, if `did` belongs to **the same email**, skip the challenge and the new-device check. The bot doesn't have Priya's cookie, so it still gets challenged. This is OWASP's "device cookie" idea, and it also stops attackers from **locking real users out** on purpose: you can lock out untrusted devices without touching trusted ones.

---

### Step 6: Right password, new device → verify by email

Even if the bot solves the challenge (or there's no attack right now), a correct password from a **new device** is suspicious when:

- the password is **in a breach list** (Step 2), or
- the site is **under attack** (Step 3)

Then don't log in yet. Send a 6-digit code to the account's email, and say "if this wasn't you, change your password":

```
📧 To: rahul@mail.com
   New sign-in from IP 198.51.100.7. Your code: 376818 (valid 10 minutes).
   Not you? Someone has your password: change it now. It appeared in a data breach.
```

The attacker has Rahul's password, but **not his inbox**. And Rahul just got a warning. This is what Amazon, Netflix, Google and banks do with "new device" emails and SMS codes. The code is single-use, short-lived, and allows only 5 guesses (topic 43).

---

### Step 7: MFA and passkeys, the real fix

Everything above makes stuffing **harder**. Only a second factor makes a leaked password **worthless**:

- **TOTP / authenticator app** (topic 44), **MFA flow** (topic 45): password + code from the phone
- **Passkeys** (topic 46): no password to leak at all, and they can't be phished
- Offer MFA to everyone; **require** it for admins and anyone handling money

Plus a few habits that help:

| Habit | Why |
|---|---|
| Same error for "no such email" and "wrong password" (topic 51) | Otherwise the bot learns which emails have accounts and focuses on them |
| Watch new public breaches; force a reset for your users whose credentials appear | Get ahead of the next combo list |
| Login alerts on new devices (topic 55) | The user notices before the attacker does damage |
| Re-ask for the password / MFA before changing email, password, payout details (step-up, topic 45) | A hijacked session can't lock the owner out |

---

### 🤔 Tricky parts

**1. "We have rate limiting" doesn't mean you're protected.** Per-IP and per-account limits stop brute force. Stuffing is designed to stay under both. You need **site-wide** signals.

**2. Residential proxies make IP blocking weak.** Bots rent millions of real home IPs (often from infected devices). Blocking an IP may block a real family. Prefer challenges to hard blocks.

**3. Attackers can lock out your real users.** If 5 failures lock an account, a bot can lock **everyone** just by trying wrong passwords. Device cookies let you keep trusted devices working during a lockout.

**4. Different responses leak "right password".** In our demo, a correct password from a new device returns `202 verify_email`, which tells the attacker the password works. That's an accepted trade-off: they still can't get in, and the owner is warned. Never leak it in a **cheaper** way (like "right password, but your account is locked").

**5. SHA-1 for the breach check is fine, SHA-1 for storing is not.** The k-anonymity lookup uses SHA-1 because that's the API's format. Passwords are still **stored** with scrypt, bcrypt or argon2 (topic 04).

**6. `trust proxy` decides which IP you count.** The demo trusts `X-Forwarded-For` from anyone so you can fake many IPs with curl. In production trust only your own proxy, or the bot sets its own "IP" (topic 16).

**7. The attack also hits other doors.** Password reset, signup ("email already exists"), mobile APIs and old API versions are all login pages to a bot. Protect every endpoint that checks a password or reveals an account.

---

### Common beginner mistakes

1. **Relying only on per-IP rate limits.**
   Stuffing spreads over thousands of IPs. Add site-wide detection.

2. **Locking accounts on a few failures with no way back.**
   It helps the attacker lock out real users. Use backoff, device cookies and challenges.

3. **Never checking passwords against breach lists.**
   `Password@123` and `rahul@1995` are in every combo list. Refuse them at signup, change and reset.

4. **Sending the full password (or full hash) to a breach-check API.**
   Use the k-anonymity range API: only 5 hash characters leave your server.

5. **Showing a CAPTCHA after the password check.**
   Check the challenge first, so the bot can't learn which passwords were right.

6. **Different errors for "unknown email" and "wrong password".**
   It hands the bot a list of your real users (topic 51).

7. **No alert to the user on a new-device login.**
   The account owner is your best detector.

8. **Treating MFA as optional for everyone, including admins.**
   One reused admin password = the whole company.

9. **Forgetting the other doors.**
   Mobile API, `/api/v1/login`, password reset and signup need the same protection.

---

### Interview questions

1. **What is credential stuffing, and how is it different from brute force and password spraying?**
   Replaying leaked `email:password` pairs from other breaches. Brute force tries many passwords on one account. Spraying tries one common password on many accounts. Stuffing tries one **known-real** password per account, so its hit rate is much higher.

2. **Why don't per-IP rate limits and account lockout stop it?**
   Each account gets one attempt and the requests come from thousands of IPs, so neither counter crosses its threshold.

3. **How do you detect it?**
   Site-wide signals: a spike in failed logins, a high share of failures for non-existent accounts, a falling success rate, many IPs touching many accounts, the same client fingerprint across IPs, traffic from proxy/data-centre ranges.

4. **How do you check a password against Have I Been Pwned without sending it?**
   k-anonymity: SHA-1 the password, send the first 5 hex characters to the range API, get back all matching suffixes with counts, and compare locally. Padding hides the response size.

5. **What do you do once you detect an attack?**
   Challenge untrusted devices (bot detection / CAPTCHA / proof of work) before checking passwords, require email or MFA verification for new-device logins, keep trusted devices working, alert the security team, and force resets for accounts that were actually accessed.

6. **What is a device cookie and why use it?**
   A long-lived random cookie set after a successful login. Logins carrying it are treated as lower risk, so real users skip challenges and aren't hit by lockouts aimed at attackers.

7. **What's the single best defense?**
   MFA, ideally phishing-resistant (passkeys). A leaked password alone is then useless.

8. **What does NIST say about passwords?**
   Minimum 8 characters, allow long ones (64+), check new passwords against breached/common lists, no forced composition rules, no forced periodic changes (only change on evidence of compromise).

---

### Quick recap

- Credential stuffing = **leaked passwords from another site**, one try per account, **many IPs**
- Topic 16's per-IP and per-account limits are needed but **don't catch it**
- **Reject breached passwords** with the k-anonymity range API (only 5 SHA-1 characters leave your server)
- **Watch the whole site**: failure spikes, unknown-email share, success rate → **attack mode**
- In attack mode, **challenge unknown devices before checking the password**
- **Device cookies** keep real users working; **new-device email codes** stop the right password in the wrong hands
- **MFA / passkeys** (topics 44–46) make a stolen password worthless; alerts and audit logs next (topic 55)

## Code

A small **Express** app, **ChaiKart**, with **two servers in one file**: the shop's login (on `PORT`) and a mock **Pwned Passwords API** (on `PORT + 1`) that works like `api.pwnedpasswords.com/range/{prefix}`. There are two login routes, so you can run the same bot against both:

| Route | Defenses |
|---|---|
| `/vulnerable/login` | ❌ Only topic 16: per-IP limit (10 failures / 15 min) and per-account lockout (5 failures) |
| `/login` | ✅ The above, plus site-wide attack detection, a proof-of-work challenge for unknown devices, a trusted-device cookie, and a breached-password / new-device email code |

Other routes: `POST /signup` (breached-password check), `GET /login/challenge`, `POST /login/verify` (the email code), `GET /me`, `GET /security/status` (what the security dashboard sees).

Test accounts: **rahul@mail.com** / `rahul@1995` (reused, and in the breach list) and **priya@mail.com** / `masala-dosa-on-sunday-7` (long and unique). To fake "a bot with many IPs" from one terminal, the demo trusts the `X-Forwarded-For` header (never do this in production). Everything is in memory, so a restart resets it.

📄 **Full code: [server.js](server.js)**. Open it and read the comments, which follow the same steps as the notes above.

Install Express once (from this folder), then start the server:

```bash
npm install
```

```bash
node server.js
```

> Port 3000 busy? Run it on another port: `PORT=3052 node server.js` (Git Bash). The mock Pwned API then runs on 3053, so that port must be free too (if it isn't, the server stops with `EADDRINUSE`: pick another `PORT`). The outputs below were recorded this way, on a fresh server.

### Try it (Git Bash)

```bash
APP=http://localhost:3052
```

🔐 **① Signup refuses a breached password**, then accepts a unique one:

```bash
curl -s $APP/signup -H "Content-Type: application/json" -d '{"email":"amit@mail.com","password":"Password@123"}'
curl -s $APP/signup -H "Content-Type: application/json" -d '{"email":"amit@mail.com","password":"auto-rickshaw-at-midnight"}'
```
→
```
{"error":"This password has appeared in 1,20,000 data breaches. Attackers try it first. Choose another."}
{"message":"Account created. You can log in now."}
```
The server terminal shows that only 5 hash characters left the app:
```
🌐 Pwned API: someone asked for prefix 25C2C (that's all it ever sees)
🔎 Pwned check: sent only "25C2C", got 11 suffixes back, breached: yes (120000)
```

🔎 **② What the Pwned API answers** for that prefix (10 padding lines with count `0`, and one real match):

```bash
curl -s -H "Add-Padding: true" http://127.0.0.1:3053/range/25C2C
```
→
```
1555A89638462D10475A36AC60F4CB0C8F7:0
2504DB29FAEDAE976366D67577A4E9D16AF:0
…
9AFDD83B8D34234AA2881CC341C09689AAA:120000
B0D2A5E57D8FE2743EBF6DDBD6A787113C9:0
```
`25C2C` + `9AFDD83B…` is the SHA-1 of `Password@123`. The API never learned which line we were looking for.

💻 **③ Priya logs in from her laptop**, before any attack. She gets a session **and** a trusted-device cookie:

```bash
curl -s -c priya.jar $APP/login -H "Content-Type: application/json" -d '{"email":"priya@mail.com","password":"masala-dosa-on-sunday-7"}'
```
→ `{"message":"Logged in as priya@mail.com"}` (and `priya.jar` now holds `sid` and `did`)

📜 **④ The bot's combo list**, leaked from some other hacked site:

```bash
cat > combo.txt <<'EOF'
amit.k@mail.com:qwerty123
sneha.r@mail.com:iloveyou
priya@mail.com:priya@123
rohan.m@mail.com:password1
neha.s@mail.com:welcome@1
karan.v@mail.com:dragon2020
rahul@mail.com:rahul@1995
anjali.p@mail.com:sunshine
vivek.t@mail.com:123456
meera.j@mail.com:Password@123
EOF
```

❌ **⑤ Attack on `/vulnerable/login`**: one try per account, a different IP each time:

```bash
i=0; while IFS=: read -r email pass; do i=$((i+1)); printf "%-18s " "$email"; curl -s $APP/vulnerable/login -H "X-Forwarded-For: 203.0.113.$i" -H "Content-Type: application/json" -d "{\"email\":\"$email\",\"password\":\"$pass\"}" -w " [%{http_code}]\n"; done < combo.txt
```
→
```
amit.k@mail.com    {"error":"Wrong email or password"} [401]
sneha.r@mail.com   {"error":"Wrong email or password"} [401]
priya@mail.com     {"error":"Wrong email or password"} [401]
rohan.m@mail.com   {"error":"Wrong email or password"} [401]
neha.s@mail.com    {"error":"Wrong email or password"} [401]
karan.v@mail.com   {"error":"Wrong email or password"} [401]
rahul@mail.com     {"message":"Logged in as rahul@mail.com"} [200]
anjali.p@mail.com  {"error":"Wrong email or password"} [401]
vivek.t@mail.com   {"error":"Wrong email or password"} [401]
meera.j@mail.com   {"error":"Wrong email or password"} [401]
```
No IP and no account came close to a limit. Rahul's reused password worked. The bot logs in and reads his data:

```bash
curl -s -c stolen.jar $APP/vulnerable/login -H "X-Forwarded-For: 203.0.113.77" -H "Content-Type: application/json" -d '{"email":"rahul@mail.com","password":"rahul@1995"}'
curl -s -b stolen.jar $APP/me
```
→ `{"message":"Logged in as rahul@mail.com"}` then `{"email":"rahul@mail.com","name":"Rahul","address":"Flat 302, Koramangala, Bengaluru"}` 😱

✅ **⑥ The same attack on `/login`**, from a new batch of IPs:

```bash
i=0; while IFS=: read -r email pass; do i=$((i+1)); printf "%-18s " "$email"; curl -s $APP/login -H "X-Forwarded-For: 198.51.100.$i" -H "Content-Type: application/json" -d "{\"email\":\"$email\",\"password\":\"$pass\"}" -w " [%{http_code}]\n"; done < combo.txt
```
→
```
amit.k@mail.com    {"error":"Wrong email or password"} [401]
sneha.r@mail.com   {"error":"Wrong email or password"} [401]
priya@mail.com     {"error":"Wrong email or password"} [401]
rohan.m@mail.com   {"error":"Wrong email or password"} [401]
neha.s@mail.com    {"error":"Wrong email or password"} [401]
karan.v@mail.com   {"error":"Unusual login activity. Get a challenge from /login/challenge, solve it, and try again.","challengeRequired":true} [403]
rahul@mail.com     {"error":"Unusual login activity. Get a challenge from /login/challenge, solve it, and try again.","challengeRequired":true} [403]
anjali.p@mail.com  {"error":"Unusual login activity. …","challengeRequired":true} [403]
vivek.t@mail.com   {"error":"Unusual login activity. …","challengeRequired":true} [403]
meera.j@mail.com   {"error":"Unusual login activity. …","challengeRequired":true} [403]
```
After 5 failures the server printed `🚨 ATTACK MODE ON: 5 failed logins from 5 IPs in 5 min. New devices must now solve a challenge.` Rahul's line never reached the password check.

📊 **⑦ What the security dashboard sees:**

```bash
curl -s $APP/security/status
```
→ `{"attackMode":true,"attackModeUntil":"2026-11-06T02:10:13.275Z","failedLoginsLast5Min":5,"distinctIps":5,"distinctAccounts":5,"unknownEmailShare":"80%"}`

😌 **⑧ Real users during the attack.** Priya on her **trusted laptop** walks straight in; the same password from a **new device** must solve the challenge:

```bash
curl -s -b priya.jar $APP/login -H "X-Forwarded-For: 192.0.2.10" -H "Content-Type: application/json" -d '{"email":"priya@mail.com","password":"masala-dosa-on-sunday-7"}'
curl -s $APP/login -H "X-Forwarded-For: 192.0.2.11" -H "Content-Type: application/json" -d '{"email":"priya@mail.com","password":"masala-dosa-on-sunday-7"}'
```
→ `{"message":"Logged in as priya@mail.com"}` then `{"error":"Unusual login activity. …","challengeRequired":true}`

🧮 **⑨ The bot pays for a challenge** (proof of work: about 0.15 s of CPU here), then tries Rahul again:

```bash
CH=$(curl -s $APP/login/challenge | sed -E 's/.*"challenge":"([0-9a-f]+)".*/\1/')
N=$(node -e 'const c=process.argv[1];let n=0;while(!require("crypto").createHash("sha256").update(c+n).digest("hex").startsWith("0000"))n++;console.log(n)' $CH)
curl -s $APP/login -H "X-Forwarded-For: 198.51.100.7" -H "Content-Type: application/json" -d "{\"email\":\"rahul@mail.com\",\"password\":\"rahul@1995\",\"challenge\":\"$CH\",\"solution\":\"$N\"}"
```
→ `{"status":"verify_email","message":"New device. We sent a 6-digit code to your email.","pendingId":"6AJ--NkzzGmAR6fMU40ta7EeSIWm7yeFryfVqRZhyBM"}`

The right password, but a new device **and** a breached password, so the code goes to **Rahul's** inbox (the server terminal):
```
📧 To: rahul@mail.com
   New sign-in from IP 198.51.100.7. Your code: 376818 (valid 10 minutes).
   Not you? Someone has your password: change it now. It appeared in a data breach.
```
Sending the same `challenge` again fails: each one is single-use.

🔢 **⑩ The bot guesses the code; the real Rahul types it** (use your own `pendingId` and code):

```bash
PID=PASTE_THE_PENDING_ID
curl -s $APP/login/verify -H "Content-Type: application/json" -d "{\"pendingId\":\"$PID\",\"code\":\"111111\"}"
curl -s -c rahul-phone.jar $APP/login/verify -H "Content-Type: application/json" -d "{\"pendingId\":\"$PID\",\"code\":\"PASTE_THE_CODE\"}"
curl -s -b rahul-phone.jar $APP/me
```
→
```
{"error":"Wrong code"}
{"message":"Logged in as rahul@mail.com. This device is now trusted.","warning":"Your password appeared in a data breach. Change it now (topic 14)."}
{"email":"rahul@mail.com","name":"Rahul","address":"Flat 302, Koramangala, Bengaluru"}
```
After 5 wrong codes the pending login is deleted. Rahul's phone now has a `did` cookie, so his next login skips the challenge and the code.

> **Windows PowerShell users:** the single quotes in `-d '...'`, the `while read` loop and `VAR=value node ...` work in Git Bash. In PowerShell, use Git Bash or Postman, or set the port with `$env:PORT=3052; node server.js`. Restart the server to leave attack mode and clear all counters.
