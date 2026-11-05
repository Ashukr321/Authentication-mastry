# 16. Account Lockout & Rate Limiting

## Notes

### What are account lockout and rate limiting?

Your login form answers one question: "is this password right?". Without limits, an attacker can ask that question **millions of times**. Two tools stop that:

- **Rate limiting**: "this **IP address** (or client) may only try **N times per minute**". It protects your **server** and slows down attackers who try many accounts.
- **Account lockout**: "this **account** has had **5 wrong passwords in a row**, so pause logins **for this account** for a while". It protects **one user** from someone guessing their password.

> **One-line answer:** count attempts per IP **and** per account; past the limit, answer `429 Too Many Requests` with `Retry-After`, lock accounts **temporarily** with growing waits (never forever), refuse even the correct password while locked, and give the exact same answers for accounts that don't exist.

---

### Why does it matter?

| Attack | What it looks like | What stops it |
|---|---|---|
| **Brute force** | One account, thousands of passwords (`rahul123`, `rahul@123`…) | **Account lockout** |
| **Password spraying** | Thousands of accounts, one common password each (`Password@123`) | **Rate limit per IP** + blocking common passwords (topic 06) |
| **Credential stuffing** | Email + password pairs leaked from another site, tried on yours | Rate limits, MFA (Level 6), breached-password checks, bot detection |
| **Server overload (DoS)** | Spamming login: each check costs ~300 ms of CPU (topic 04) | **Rate limit per IP**, checked **before** hashing |
| **Email / SMS bombing** | Spamming "forgot password" or "send code" | Rate limits + cooldowns (topics 12, 13) |

Without any limit, a 6-digit code (Level 6) can be guessed in 1,000,000 tries, and a weak password in a few thousand.

---

### Real-life example: the ATM and the bank branch 🏧

Rahul's ₹ debit card at an ATM in Bengaluru:

1. **3 wrong PINs** → the card is **blocked for 24 hours** → **account lockout**. It's about **the card**, whatever ATM you're at.
2. The ATM itself can serve only **so many people per minute**, and a man feeding it 50 different cards gets noticed by the guard → **rate limiting per IP**. It's about **who's standing at the machine**, whatever card they use.
3. Even if the 4th PIN is **correct**, a blocked card stays blocked → **refuse the correct password while locked**
4. The block is for **24 hours**, not forever. Otherwise anyone could type 3 wrong PINs into someone else's card on purpose → **temporary lock, not permanent**
5. Rahul gets an SMS: "3 wrong PIN attempts on your card" → **notify the owner**

---

### The flow, step by step

#### 📊 Diagrams

Open **[diagrams.html](diagrams.html)** in your browser (just double-click the file) to see:

- **Flow diagram**: the order of checks on `POST /login`: IP limit → account lock → password → count the failure
- **Data flow**: Priya guesses Rahul's password, the account locks, then her script runs into the IP limit
- **Two layers**: what the per-IP limit stops vs what the per-account lock stops

In short: `POST /login → IP over 20/min? 429 → account locked? 429 (even with the right password) → check password → wrong: failures+1, at 5 lock for 1, 2, 4… min → right: reset the counters`

#### Two counters, two jobs 🔢

| | Rate limit (per IP) | Account lockout (per account) |
|---|---|---|
| Counts | Requests from one **IP** | Wrong passwords for one **email** |
| Stops | Spraying, stuffing from one machine, DoS | Brute force on one account |
| Doesn't stop | Attackers with many IPs (botnets) | Attackers trying many accounts |
| Example limit | 20 login attempts / minute | 5 wrong in a row → lock |
| Reply | `429` + `Retry-After` + `RateLimit-*` headers | `429` + `Retry-After` |
| Risk | Blocks a whole office behind one IP | Attackers lock out **real users** on purpose |

You need **both**: each one covers the other's blind spot.

---

### Step 1: Rate limit per IP (before anything expensive)

```js
const loginLimiter = rateLimit({ limit: 20, windowMs: 60 * 1000, keyOf: (req) => `login:${req.ip}` });
app.post("/login", loginLimiter, async (req, res) => { ... });
```

The limiter runs **before** the password is hashed, so a flood of requests doesn't burn your CPU.

**How the counting works.** Our demo uses the simplest method, a **fixed window**: "20 per minute, counter resets every minute". The common algorithms:

| Algorithm | Idea | Good / bad |
|---|---|---|
| **Fixed window** | Count per clock window (12:00–12:01) | Simplest. A burst at 12:00:59 + 12:01:00 lets 2× through |
| **Sliding window** | Count the last 60 seconds, always | Smoother, a bit more memory |
| **Token bucket** | A bucket refills 1 token / 3 s, each request takes one | Allows short bursts, then a steady rate. Used by most APIs |

**Tell the client.** Good limiters send headers so well-behaved apps can slow down:

```
RateLimit-Limit: 20        ← allowed per window
RateLimit-Remaining: 19    ← left in this window
RateLimit-Reset: 60        ← seconds until the window resets
Retry-After: 36            ← only on 429: wait this long
```

**Which limits?** Typical starting points (tune them with real traffic):

| Route | Limit (per IP) |
|---|---|
| `POST /login` | 10–20 / minute |
| `POST /signup` | 5–10 / hour |
| `POST /forgot-password` | 5 / hour (+ a per-email cooldown, topic 13) |
| Verify a 6-digit code (Level 6) | 5 tries per code, then the code dies |
| Normal API calls | 100–1000 / minute |

---

### Step 2: ⚠️ Which IP? (`trust proxy`)

`req.ip` is the address that opened the connection. In production you're usually behind a **load balancer** (Nginx, AWS ALB, Cloudflare), so every request seems to come from the load balancer's IP, and **everyone shares one limit**.

The real client IP is in the `X-Forwarded-For` header, and Express reads it if you set:

```js
app.set("trust proxy", 1); // trust ONE proxy hop in front of us
```

| ✅ Do | ❌ Don't |
|---|---|
| `trust proxy` = the number of proxies **you control** | `app.set("trust proxy", true)` when you're **not** behind a proxy |
| Read the IP from `req.ip` | Read `req.headers["x-forwarded-for"]` yourself |

If you trust the header without a proxy, the attacker just sends `X-Forwarded-For: 1.2.3.4`, then `1.2.3.5`… and gets a **fresh IP on every request**. The rate limit is gone.

---

### Step 3: Account lockout: refuse first, even the right password

```js
if (lockStatus(email) > 0) {
  res.set("Retry-After", String(seconds));
  return res.status(429).json({ error: `Too many failed attempts. Try again in ${seconds} seconds, or reset your password.` });
}
```

Check the lock **before** the password, and refuse **even if the password is correct**. If a locked account still said "Logged in" for the right password, the attacker would keep guessing and simply wait for the one different answer. The lock would only slow them down a little.

It also skips the expensive hash, which saves CPU during an attack.

---

### Step 4: Count failures, lock with exponential backoff

```js
entry.failures++;
if (entry.failures >= 5) {
  const lockMs = Math.min(60_000 * 2 ** entry.lockCount, 60 * 60_000); // 1, 2, 4, 8… minutes, max 1 hour
  entry.lockedUntil = now + lockMs;
  entry.lockCount++;
  entry.failures = 0;
}
```

| Choice | Our demo | Why |
|---|---|---|
| Failures before lock | 5 | Real users mistype 1–3 times. Attackers need thousands |
| Forget failures after | 15 minutes | 1 typo today + 1 next week shouldn't add up |
| First lock | 1 minute | Barely bothers a real user |
| Next locks | **Double** each time (max 1 hour) | Guessing becomes useless: ~5 tries per hour at worst |
| On success | Reset everything | The owner is back |

**Never lock forever** (or "until an admin unlocks it"). Then an attacker can type 5 wrong passwords into **every** account and lock out all your users. That's a **denial of service** on your users, called a **lockout DoS**. Short locks that grow are the balance.

**Notify the owner.** When an account locks, email the real owner (only if the account exists): "Someone typed your password wrong 5 times." Include a link to reset the password (topic 13), which should also clear the lock.

---

### Step 5: Lock emails that don't exist too

```js
const loginFailures = new Map(); // keyed by the EMAIL TYPED, not by user id
```

If only real accounts could be locked, an attacker types 6 wrong passwords for `priya@mail.com`:

- 6th answer is `429 locked` → **Priya has an account**
- 6th answer is `401 invalid` → **she doesn't**

That's **account enumeration** again (topics 06, 07). So we count failures for **the email that was typed**, whether or not an account exists. `nobody@mail.com` gets locked exactly like `rahul@mail.com`. Only the **notice email** differs, and that goes to the real inbox, not to the attacker.

---

### Step 6: Store counters where every server can see them

Our demo keeps counters in a `Map` in memory. That breaks when:

- you run **2+ servers**: each one has its own counters, so the attacker gets 20 tries **per server**
- the server **restarts**: all counters reset to zero

Real apps keep them in **Redis** (fast, shared, with automatic expiry):

```
INCR  login:ip:203.0.113.7       → 1, 2, 3…
EXPIRE login:ip:203.0.113.7 60   → the key deletes itself after 60 s
```

Libraries: `express-rate-limit` with `rate-limit-redis`, or `rate-limiter-flexible`. Many teams also rate-limit at the edge (Nginx `limit_req`, Cloudflare, AWS WAF), before requests even reach Node.

---

### 🤔 Tricky parts

**1. Botnets: thousands of IPs.**
Credential stuffing often comes from residential botnets, with 1–2 tries per IP. Per-IP limits barely notice. Add: a **global** failed-login rate alarm, **CAPTCHA** after suspicious patterns (instead of hard locks), **breached-password checks** (topic 06), **MFA** (Level 6), and "new device" emails.

**2. Many real users behind one IP.**
Offices, colleges and mobile carriers (CGNAT) put hundreds of people behind one IP. Too-strict IP limits block all of them. Keep IP limits generous, and combine with per-account limits.

**3. Lock vs slow down vs CAPTCHA.**
A hard lock is simple but can be abused (lockout DoS). Alternatives: **progressive delays** (wait 1 s, 2 s, 4 s…), or a **CAPTCHA** after 3 failures. Big sites use a mix based on risk.

**4. `429` or `423`?**
`429 Too Many Requests` with `Retry-After` is the standard answer for both. `423 Locked` exists (from WebDAV) but few clients understand it.

**5. Rate-limit everything that sends something or checks a secret.**
Login, signup, forgot password, resend verification, OTP / 2FA codes, change password (topic 14), and any "does this exist?" endpoint.

---

### Common beginner mistakes

1. **No limits at all.**
   Any password can be brute-forced eventually, and your CPU melts on the way.

2. **Only per-IP limits.**
   One account can still be attacked slowly from many IPs. Add per-account lockout.

3. **Only per-account lockout.**
   Password spraying tries 1 password on 10,000 accounts and never triggers it. Add per-IP limits.

4. **Permanent locks.**
   Attackers lock out your real users on purpose. Use short locks that grow.

5. **Letting the correct password through while locked.**
   The lock becomes a speed bump, not a wall.

6. **Different answers for existing and non-existing accounts.**
   Lock unknown emails too, with the same message.

7. **Trusting `X-Forwarded-For` without a proxy.**
   Attackers fake a new IP on every request. Set `trust proxy` only to the proxies you control.

8. **Counters in memory with several servers.**
   Each server counts separately, so limits multiply. Use Redis.

9. **Rate-limiting after the expensive work.**
   Check limits **before** hashing passwords or sending emails.

10. **No `Retry-After` and no notice to the owner.**
    Clients can't back off politely, and the real user never learns their account is under attack.

---

### Interview questions

1. **What's the difference between rate limiting and account lockout?**
   Rate limiting counts requests per client (IP, API key) and protects the server and against attacks across many accounts. Account lockout counts failed logins per account and protects one user from password guessing. You need both.

2. **How would you protect a login endpoint from brute force?**
   A per-IP rate limit (before hashing), a per-account failure counter with temporary, exponentially growing locks, the same responses for existing and non-existing accounts, a notice email on lock, and MFA / CAPTCHA for higher risk.

3. **Why shouldn't account lockout be permanent?**
   Attackers could lock every user out on purpose (lockout DoS). Temporary locks with exponential backoff make guessing useless while real users recover by themselves.

4. **Should a locked account accept the correct password?**
   No. Otherwise the attacker keeps guessing and just watches for a different response.

5. **How do you avoid account enumeration with lockout?**
   Count failures per typed email, even for emails with no account, and give identical responses. Only the notification email depends on the account existing.

6. **Explain fixed window, sliding window, and token bucket.**
   Fixed window counts per clock interval (simple, bursty at edges). Sliding window counts the last N seconds (smoother). Token bucket refills tokens at a steady rate and each request spends one (allows short bursts, then a steady rate).

7. **How do you rate-limit across multiple servers?**
   Keep counters in a shared store like Redis (`INCR` + `EXPIRE`, or Lua scripts for atomic sliding windows), or rate-limit at the edge (API gateway, WAF, Nginx).

8. **What's the problem with `X-Forwarded-For`?**
   Clients can set it to anything. Only trust it from proxies you run (`app.set("trust proxy", 1)`), or attackers bypass IP limits by faking a new IP on every request.

9. **What status code and headers do you return when rate limited?**
   `429 Too Many Requests` with `Retry-After`, plus `RateLimit-Limit`, `RateLimit-Remaining` and `RateLimit-Reset`.

10. **How do you handle credential stuffing from a botnet?**
    Per-IP limits don't help much. Use breached-password checks, MFA, CAPTCHA or bot detection on suspicious traffic, global failure-rate alerts, and notify users about logins from new devices.

---

### Quick recap

- **Two layers**: rate limit **per IP** + lockout **per account**
- Check limits **first**: before hashing, before sending emails
- Over the limit → **`429`** + **`Retry-After`** (+ `RateLimit-*` headers)
- Lockout: **5 wrong → lock**, **1, 2, 4… minutes** (max 1 h), **never forever**
- While locked, refuse **even the correct password**
- Lock **non-existent emails too**, with the same message (no enumeration)
- **Email the owner** when their account locks. A password reset clears the lock
- `trust proxy` only for **your own** proxies. Shared counters in **Redis** for 2+ servers
- Also limit **signup, forgot password, OTP codes, change password**

## Code

A small **Express** API with both layers on `POST /login`: a reusable fixed-window **rate limiter** (20 attempts per IP per minute, with `RateLimit-*` headers), and a per-account **lockout** (5 wrong passwords → locked, the wait doubles each time). It's written by hand so you can see how it works. In a real app you'd use a library like `express-rate-limit` with Redis. Everything is kept in memory, so it resets when you restart.

📄 **Full code: [server.js](server.js)**. Open it and read the comments, which follow the same steps as the notes above.

Install Express once (from this folder), then start the server. `LOCK_SECONDS=5` makes the first lock 5 seconds instead of 1 minute, so you don't have to wait long:

```bash
npm install
```

```bash
LOCK_SECONDS=5 node server.js
```

> Port 3000 busy? Run it on another port: `LOCK_SECONDS=5 PORT=3016 node server.js` (Git Bash), then use that port in the commands below.

### Try it

Run these in order, **within one minute** (the per-IP window is 60 seconds and allows 20 login attempts).

✅ **Sign up, then log in, and look at the rate-limit headers:**

```bash
curl -X POST http://localhost:3000/signup -H "Content-Type: application/json" -d '{"email":"rahul@mail.com","password":"correct horse battery"}'
```

```bash
curl -i -X POST http://localhost:3000/login -H "Content-Type: application/json" -d '{"email":"rahul@mail.com","password":"correct horse battery"}'
```
→ `200 OK` with
```
RateLimit-Limit: 20
RateLimit-Remaining: 19
RateLimit-Reset: 60
{"message":"Logged in","email":"rahul@mail.com"}
```

❌ **Priya guesses 5 times:** each line prints only the status code.

```bash
for i in 1 2 3 4 5; do curl -s -o /dev/null -w "%{http_code} " -X POST http://localhost:3000/login -H "Content-Type: application/json" -d '{"email":"rahul@mail.com","password":"guess"}'; done
```
→ `401 401 401 401 401`. The terminal prints an email to Rahul: "Someone is trying to log in to your account… paused for 5 seconds".

🔒 **Now even the correct password is refused:**

```bash
curl -i -X POST http://localhost:3000/login -H "Content-Type: application/json" -d '{"email":"rahul@mail.com","password":"correct horse battery"}'
```
→ `429 Too Many Requests` with `Retry-After: 5` and `{"error":"Too many failed attempts. Try again in 5 seconds, or reset your password."}`

⏫ **Wait 5 seconds, guess 5 more times: the lock doubles.**

```bash
for i in 1 2 3 4 5; do curl -s -o /dev/null -w "%{http_code} " -X POST http://localhost:3000/login -H "Content-Type: application/json" -d '{"email":"rahul@mail.com","password":"guess"}'; done
```
→ `401 401 401 401 401`, then the correct password gets `429` with `Retry-After: 10` and "Try again in 10 seconds". The next lock would be 20 s, then 40 s…

🛡️ **An email with no account gets locked the same way** (no enumeration):

```bash
for i in 1 2 3 4 5 6; do curl -s -o /dev/null -w "%{http_code} " -X POST http://localhost:3000/login -H "Content-Type: application/json" -d '{"email":"nobody@mail.com","password":"guess"}'; done
```
→ `401 401 401 401 401 429`, exactly like a real account, but no email is printed.

✅ **Wait 10 seconds, log in with the right password:**

```bash
curl -i -X POST http://localhost:3000/login -H "Content-Type: application/json" -d '{"email":"rahul@mail.com","password":"correct horse battery"}'
```
→ `200 OK`, `RateLimit-Remaining: 0` and `{"message":"Logged in","email":"rahul@mail.com"}`. The failures are reset, but this IP has used all 20 attempts for this minute.

🚦 **The per-IP limit:** any account, any password, from this IP:

```bash
curl -i -X POST http://localhost:3000/login -H "Content-Type: application/json" -d '{"email":"rahul@mail.com","password":"correct horse battery"}'
```
→ `429 Too Many Requests` with
```
RateLimit-Limit: 20
RateLimit-Remaining: 0
RateLimit-Reset: 36
Retry-After: 36
{"error":"Too many requests. Try again in 36 seconds."}
```
(The exact seconds depend on how fast you ran the commands.) Wait until the minute is over and you can log in again.

> **Windows PowerShell users:** the `for` loops, the single quotes in `-d '...'` and `VAR=value node ...` work in Git Bash. In PowerShell, use Git Bash, Postman, or set the variables with `$env:LOCK_SECONDS=5; node server.js`.
