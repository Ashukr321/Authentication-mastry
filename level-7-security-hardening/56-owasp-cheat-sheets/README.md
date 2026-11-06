# 56. OWASP Auth Cheat Sheets

## Notes

### What is OWASP?

**OWASP (Open Worldwide Application Security Project)** is a free, non-profit community that writes down how web apps get hacked and how to stop it. You don't install it. You **read it, and check your app against it**.

For login code, the most useful thing they publish is the **OWASP Cheat Sheet Series**: short, practical pages like "Authentication", "Password Storage" and "Session Management", each a list of rules written by people who have seen these mistakes many times.

> **One-line answer:** OWASP cheat sheets are the **industry checklist for auth**: hash passwords with Argon2id/scrypt/bcrypt, give **one generic error** for every login/signup/reset failure, accept long passphrases and block breached ones, **limit guessing**, **rotate the session id at login and kill it on the server at logout**, set the right cookie flags and headers, block CSRF, and **never leak stack traces**. Turn the rules into **automated checks** so they stay true.

This is the last topic of Level 7. It puts topics 04–55 together into one checklist and a tool that runs it.

---

### Why it matters

| Without a checklist… | What happens |
|---|---|
| Every developer has their own idea of "secure enough" | One endpoint says "No account for that email" and undoes the generic login error |
| Old code never gets re-checked | The 2015 login still uses MD5 and 12-character max passwords |
| Security reviews are opinions | "Looks fine to me" instead of "fails rule 9 of the Session Management cheat sheet" |
| Interviews and audits ask "do you follow OWASP?" | You can't answer with specifics |
| Fixes regress | Someone removes `httpOnly: true` while debugging and it ships |

Authentication bugs are **A07** in the OWASP Top 10, both in the 2021 list ("Identification and Authentication Failures") and the 2025 list ("Authentication Failures").

---

### Real-life example: the food inspector's checklist 🍽️

Priya's uncle runs a restaurant in Mumbai. Once a year the food-safety inspector comes.

1. A **list of the most common reasons restaurants get shut down** (rats, dirty water, no fridge) → the **OWASP Top 10**: what usually goes wrong
2. **Recipe cards** on the kitchen wall: "store raw chicken below cooked food, at under 5°C" → the **Cheat Sheet Series**: exactly how to do each thing right
3. The **inspector's form** with tick boxes, stricter for a 5-star hotel than a tea stall → **ASVS**, with levels L1/L2/L3
4. **How the inspector checks**: thermometer in the fridge, torch behind the stove → **WSTG**, the testing guide
5. Priya's uncle does a **mock inspection every month** so the real one is boring → our `/audit` endpoint: run the checklist automatically, often

---

### OWASP's main documents

#### 📊 Diagrams

Open **[diagrams.html](diagrams.html)** in your browser (just double-click the file) to see:

- **Flow diagram**: one login request going through every cheat-sheet check, and where each failure lands
- **Data flow**: the auditor probing the legacy app, with the real responses from our run
- **Which cheat sheet covers which topic**: a map from the cheat sheets to topics 04–55

In short: `Top 10 (what goes wrong) → Cheat Sheets (how to do it right) → ASVS (testable requirements) → WSTG (how to test) → your own automated audit`

| Document | What it is | Use it when… |
|---|---|---|
| **OWASP Top 10** | The 10 most common/serious risk categories, updated every few years | Explaining risks to a team, interviews |
| **Cheat Sheet Series** | 100+ short "do this, not that" pages | **Writing** the code |
| **ASVS** (Application Security Verification Standard) | Hundreds of numbered, testable requirements in 3 levels: **L1** basic, **L2** most apps with user data, **L3** banking/health/critical | Security requirements for a project, audits, "we are ASVS L2" |
| **WSTG** (Web Security Testing Guide) | How a tester checks each thing | Pentests, writing security tests |

### The cheat sheets for auth (and where we covered them)

| Cheat sheet | The key rules | Our topics |
|---|---|---|
| **Authentication** | Generic errors, password length rules, breached-password check, limit guessing, re-auth for sensitive actions | 06, 07, 16, 51, 52 |
| **Password Storage** | Argon2id / scrypt / bcrypt / PBKDF2, unique salt, optional pepper | 03, 04 |
| **Session Management** | Long random id, cookie flags, new id at login, server-side logout, idle + absolute timeouts | 09, 10, 11, 50 |
| **Forgot Password** | Same answer for every email, random single-use expiring token, no security questions | 13 |
| **Multifactor Authentication** | TOTP / passkeys over SMS, recovery codes, MFA on password change | 43–46 |
| **Credential Stuffing Prevention** | MFA, rate limits, breached-password check, alerts | 52 |
| **CSRF Prevention** / **XSS Prevention** / **Content Security Policy** | SameSite + Origin checks + tokens; output escaping; nonce CSP | 47, 48 |
| **HTTP Headers** / **Transport Layer Security** | `no-store`, `nosniff`, `frame-ancestors`, HSTS, HTTPS everywhere | 02, 05 |
| **JSON Web Token**, **OAuth 2.0**, **SAML Security** | Pin the algorithm, validate claims; PKCE + state; signature wrapping | 18–27, 33–41, 53, 59 |
| **Secrets Management**, **Logging**, **Error Handling** | No secrets in code, rotate keys; log auth events without passwords/tokens; generic errors | 54, 55 |
| **Authorization** | Deny by default, check ownership on every request | 28–31 |

You don't memorise 100 pages. You know these exist, and you open the right one when you build that feature.

---

### Step 1: Authentication cheat sheet

```js
if (password.length < 8 || password.length > 128) return 400 "Password must be 8 to 128 characters";
if (BREACHED.has(password.toLowerCase())) return 400 "This password has appeared in a data breach";
// login: one message for both cases
return res.status(401).json({ error: "Wrong email or password" });
```

| ✅ Do | ❌ Don't |
|---|---|
| Minimum **8** characters (NIST SP 800-63B-4 says **15** if the password is the only factor) | A maximum like 12 or 16 ("we store it in a VARCHAR(16)") |
| Allow at least **64** characters, spaces, emoji: passphrases are good | "Must contain a digit, a capital and a symbol": people write `Password@1` |
| Check against **breached passwords** (Have I Been Pwned, topic 52) | Force a password change every 90 days |
| **One generic error** for login, signup and reset | "No account for that email" / "Email already registered" |
| Limit guessing per account **and** per IP (topic 16) | Unlimited attempts |
| Ask for the password / MFA again before changing email, password or MFA (topic 45) | Let a stolen session change the password without the old one |

The signup trap: "Email already registered" tells an attacker who has an account, exactly like a bad login error. The fix is to always say "Check your email to continue" and **email** the existing user instead.

---

### Step 2: Password Storage cheat sheet

| Algorithm | OWASP's minimum settings | Notes |
|---|---|---|
| **Argon2id** (first choice) | 19 MiB memory, 2 iterations, 1 thread | `argon2` npm package |
| **scrypt** | N=2^17 (128 MiB), r=8, p=1 | Built into Node: `crypto.scrypt` (our demo) |
| **bcrypt** | Cost 10 or more | Only the first **72 bytes** count |
| **PBKDF2** | 600,000 iterations of HMAC-SHA256 | When FIPS rules force it |

```
❌ legacy: 065e749317381bb6b0fc20d37c8866b3          (unsalted MD5: cracked in seconds)
✅ safe:   $scrypt$N=131072,r=8,p=1$S6elEiam…$…      (algorithm + settings + salt + hash in one string)
```

Store the settings with the hash, so you can raise the cost later and **re-hash at the next successful login**. Never encrypt passwords (topic 03): you never need them back.

---

### Step 3: Session Management cheat sheet

| Rule | Why | Our demo |
|---|---|---|
| Session id from a CSPRNG, at least 64 bits of entropy | Can't be guessed | `randomBytes(32)`: 256 bits. Legacy: `sess-1001`, `sess-1002`… |
| Generic cookie name | `connect.sid` tells attackers "Express" | `sid` |
| `HttpOnly`, `Secure`, `SameSite` (topic 10) | No theft by JavaScript, no plain HTTP, less CSRF | `HttpOnly; SameSite=Lax` (+ `Secure` in production) |
| **New id at login** (and at any privilege change) | Session fixation (topic 50) | The guest id is deleted, a new one is issued |
| **Logout deletes the session on the server** | A copied cookie must die (topic 11) | Legacy only clears the browser cookie |
| Idle timeout (2–5 min for banking, 15–30 for low-risk) **and** an absolute timeout (4–8 h) | Limits a stolen or forgotten session | 5 min idle, 8 h absolute |
| Store `sha256(sid)`, not the id | A database leak doesn't hand out live sessions | Legacy stores the raw id |

---

### Step 4: Forgot Password cheat sheet

| ✅ Do | ❌ Don't |
|---|---|
| Same message **and** same timing for known and unknown emails | `404 No account with that email` |
| Random token (32 bytes), stored **hashed**, **single use**, expires in 15–60 min | `/reset?email=rahul@mail.com` (no token at all!) |
| After a reset: notify the user and end their other sessions | Log the user in automatically from the reset link |
| Send the link to the **registered** email only | Security questions ("mother's maiden name": public on Facebook) |

Full flow in topic 13.

---

### Step 5: The supporting cheat sheets

The login can be perfect and still be beaten around the side:

- **HTTP Headers**: `Cache-Control: no-store` on anything private, `X-Content-Type-Options: nosniff`, `frame-ancestors 'none'` (or `X-Frame-Options: DENY`), `Strict-Transport-Security` on HTTPS, and remove `X-Powered-By` (`app.disable("x-powered-by")`).
- **CSRF Prevention**: `SameSite` cookies + check `Origin` / `Sec-Fetch-Site` on every state-changing request, + tokens for old browsers (topic 47).
- **Error Handling**: the client gets `"Something went wrong"`; the stack trace goes to **your** logs. Our legacy app leaks `E:\Job switch\...\node_modules\body-parser\lib\types\json.js:93:21` to anyone who sends broken JSON.
- **Logging**: log logins, failures, resets, MFA changes (topic 55), but **never** passwords, tokens or full session ids.
- **Multifactor Authentication / Credential Stuffing**: MFA stops most stolen-password attacks (topics 45, 52).

---

### Step 6: Turn the cheat sheets into automated checks

A checklist in a document gets old. A checklist that **runs** stays true. Our demo's auditor makes real HTTP requests and checks 16 rules:

```js
const l1 = await call("POST", "/login", { body: { email: randomEmail(), password } }); // unknown email
const l2 = await call("POST", "/login", { body: { email, password: "Wrong-pass-1" } }); // wrong password
check("Authentication", "Login gives the same error for unknown email and wrong password", same(l1, l2), …);
```

In a real project, put checks like these in your **integration tests** and run them in CI on every pull request. Add a scanner (OWASP ZAP baseline scan) for headers and cookies, and pick an ASVS level for the bigger review.

| ✅ Do | ❌ Don't |
|---|---|
| Test the **behaviour** over HTTP (what an attacker sees) | Only read the code and trust it |
| Run the checks in CI, so a regression fails the build | A one-time audit before launch |
| Use a fresh test account per run | Test on a real user's account (the brute-force check locks it) |
| Keep a short list of "accepted risks" with a reason | Silently skip checks that fail |

---

### 🤔 Tricky parts

**1. Cheat sheets are a minimum, not a certificate.** Passing 16 checks doesn't make an app secure. Business logic bugs (topic 31, IDOR), misconfigured cloud storage and leaked keys aren't on this list.

**2. "Generic error" has to be generic everywhere.** Login, signup, forgot password, "resend verification email", the **timing** (topic 51) and even the **rate limiter** (it should count unknown emails too, or a 429 reveals real accounts).

**3. Locking accounts can be a weapon.** "5 wrong passwords = locked for an hour" lets anyone lock Rahul out by typing his email. Prefer short, growing delays, limit per IP as well, and let a password reset or MFA unlock the account (topics 16, 52).

**4. Memory-hard hashing costs memory.** scrypt with N=2^17 uses **128 MiB per login**. Ten logins at once = over 1 GB. Limit concurrent hashing, or pick settings that fit your server (the cheat sheet lists equally strong combinations).

**5. Some rules need HTTPS to test.** `Secure` cookies and HSTS can't be checked on `http://localhost`. Our auditor says so instead of pretending.

**6. The cheat sheets change.** Password rules flipped around 2017 (no composition rules, no forced rotation), and NIST SP 800-63B-4 (2025) raised the single-factor minimum to 15. Re-read the page when you build the feature, not what you remember from five years ago.

**7. Security questions, SMS OTP, "remember me forever".** All discouraged or weak by today's cheat sheets. If an old system uses them, plan a migration (topics 15, 43, 44).

---

### Common beginner mistakes

1. **Different error messages** for "no such user" and "wrong password" (or on signup / forgot password).

2. **Fast hashes** (MD5, SHA-256) for passwords, or no salt.

3. **A maximum password length of 12–20**, or "must contain a symbol" rules.

4. **No limit on login attempts.**

5. **Keeping the same session id after login** (session fixation).

6. **Logout that only deletes the cookie** in the browser.

7. **Session cookies without `HttpOnly` / `SameSite`**, named after the framework.

8. **No `Cache-Control: no-store`** on pages with personal data.

9. **Stack traces in error responses** (and `X-Powered-By: Express` in every response).

10. **Treating OWASP as a one-time task.** Without automated checks, the next refactor undoes it.

---

### Interview questions

1. **What is OWASP, and which of its documents do you use?**
   A non-profit security community. The **Top 10** for awareness, the **Cheat Sheet Series** while coding, **ASVS** as a requirements/audit checklist (L1–L3), and **WSTG** for testing.

2. **What does the OWASP Authentication cheat sheet recommend for passwords?**
   At least 8 characters (15 with no MFA per NIST), allow at least 64, all characters allowed, no composition rules, no forced rotation, check breached lists, generic error messages, and rate limiting.

3. **Which password hashing algorithm does OWASP recommend?**
   Argon2id first (19 MiB, 2 iterations, 1 thread). Then scrypt (N=2^17, r=8, p=1), bcrypt (cost ≥ 10, 72-byte limit), or PBKDF2 (600,000 iterations of SHA-256) for FIPS.

4. **List the Session Management cheat sheet's main rules.**
   Random id with ≥ 64 bits of entropy, generic cookie name, `HttpOnly`/`Secure`/`SameSite`, regenerate the id at login and privilege change, server-side invalidation at logout, idle and absolute timeouts.

5. **How do you prevent user enumeration?**
   Same status, body and timing for existing and non-existing accounts in login, signup and forgot password; email the real owner instead of telling the requester; count failed attempts for unknown emails too.

6. **What is ASVS and what do its levels mean?**
   A list of testable security requirements. L1 is the minimum for every app, L2 for most apps that handle personal data, L3 for critical systems like banking and healthcare.

7. **How would you check an existing login system against OWASP?**
   Map each cheat-sheet rule to a test: send real requests (unknown vs wrong password, cookie flags, session id before/after login, reuse after logout, cross-site POST, broken JSON, repeated failures), read how passwords are stored, run a scanner like ZAP, then fix by priority and keep the tests in CI.

8. **Is passing the OWASP checklist enough?**
   No. It covers common mistakes. You still need threat modelling, authorization checks per resource, secure configuration, dependency updates and real pentests.

---

### Quick recap

- **OWASP**: Top 10 (what goes wrong), **Cheat Sheets** (how to do it right), **ASVS** (testable requirements, L1–L3), WSTG (how to test)
- **Authentication**: 8+ (15 if no MFA), allow 64+, no composition rules, **block breached**, **one generic error**, **limit guessing**
- **Password Storage**: **Argon2id** / scrypt / bcrypt / PBKDF2 with OWASP's settings, never MD5/SHA
- **Session Management**: 128+ random bits, `HttpOnly`/`Secure`/`SameSite`, **new id at login**, **server-side logout**, idle + absolute timeouts
- **Forgot Password**: same answer for every email, hashed single-use expiring token
- **Headers, CSRF, errors**: `no-store`, `nosniff`, `frame-ancestors`, no `X-Powered-By`, Origin checks, no stack traces
- **Automate it**: checks in CI keep the checklist true. Level 8 (SSO, SAML, enterprise) is next, starting with topic 57.

## Code

A small **Express** app that runs **two copies of the same login API** for PaisaPay, a payments app:

| App | Port | Code |
|---|---|---|
| **safe** | `PORT` | Follows the cheat sheets. Each rule is marked in the code, like `// [Session Management CS]` |
| **legacy** | `PORT + 1` | The 2015 code Priya inherited: MD5, `sess-1001` ids, "No account for that email", stack traces… |

Both apps share one `createApp(name)` function, so every `if (SAFE)` shows the right way and the wrong way side by side. The safe app also has an **auditor**: `GET /audit/safe` or `GET /audit/legacy` runs 16 cheat-sheet checks over real HTTP and prints a report. Each run signs up its own test account. Everything is in memory, so a restart resets it. Test account on both apps: **rahul@mail.com** / **chai-and-code-42**.

📄 **Full code: [server.js](server.js)**. Open it and read the comments, which follow the same steps as the notes above.

Install Express once (from this folder), then start the server:

```bash
npm install
```

```bash
node server.js
```

> Port 3000 busy? Run it on another port: `PORT=3056 node server.js` (Git Bash). The legacy app then runs on 3057. The outputs below were recorded on port 3056.

### Try it with curl (Git Bash)

```bash
S=http://localhost:3056
L=http://localhost:3057
```

❌ **① Audit the legacy app** (takes under a second):

```bash
curl -s $S/audit/legacy
```
→
```
OWASP cheat sheet audit of the legacy app (http://localhost:3057)
Test account: audit-873a5230@example.com

❌ FAIL  [Authentication] Signup gives the same answer for a new and an existing email
         new: 201 {"message":"Account created"} · again: 409 {"error":"Email already registered"}  → topic 06, 51
❌ FAIL  [Authentication] Rejects passwords shorter than 8 characters
         "short12" → 201 {"message":"Account created"}  → topic 06
❌ FAIL  [Authentication] Accepts a 64+ character passphrase (no 'must contain a number' rule)
         65-char passphrase → 400 {"error":"Password must be 6-12 characters and contain a number"}  → topic 06
❌ FAIL  [Authentication] Rejects passwords known from data breaches
         "password123" → 201 {"message":"Account created"}  → topic 52
❌ FAIL  [Password Storage] Hashed with a slow, salted algorithm (Argon2id, scrypt, bcrypt, PBKDF2)
         stored value: 065e749317381bb6b0fc20d37c8866b3  → topic 04
❌ FAIL  [Authentication] Login gives the same error for unknown email and wrong password
         unknown: 404 {"error":"No account for that email"} · wrong pw: 401 {"error":"Wrong password"}  → topic 07, 51
❌ FAIL  [Session Management] Session cookie is HttpOnly + SameSite with a generic name
         connect.sid=…; Path=/  (Secure is off on http://localhost; turn it on in production)  → topic 10
❌ FAIL  [Session Management] Session ID is long and random (128+ bits)
         "sess-1001" (9 chars)  → topic 09
❌ FAIL  [Session Management] Session ID changes at login
         login 200, before: sess-1001… after: sess-1001…  → topic 50
❌ FAIL  [HTTP Headers] Private pages send Cache-Control: no-store
         GET /me (200) → Cache-Control: (missing)  → topic 02
❌ FAIL  [HTTP Headers] nosniff + anti-framing headers set, X-Powered-By removed
         nosniff: no, framing blocked: no, X-Powered-By: Express  → topic 47, 48
❌ FAIL  [CSRF Prevention] A cross-site POST is refused
         POST /transfer from evil.example → 200 {"message":"Sent ₹5000 to vikram@mail.com"}  → topic 47
❌ FAIL  [Session Management] Logout ends the session on the server
         old cookie after logout → 200 {"email":"audit-873a5230@example.com","balance":"₹12,500"}  → topic 11
❌ FAIL  [Forgot Password] Same answer for a known and an unknown email
         known: 200 {"message":"Reset link sent to audit-873a5230@example.com"} · unknown: 404 {"error":"No account with that email"}  → topic 13
❌ FAIL  [Error Handling] Broken input gets a generic error, no stack trace
         broken JSON → 400 {"error":"Unexpected end of JSON input","stack":"SyntaxError: Unexpect…
❌ FAIL  [Authentication] Repeated wrong passwords get blocked
         wrong guess #10 → 401 {"error":"Wrong password"}  → topic 16, 52

Score: 0/16
```

✅ **② Audit the safe app** (about 4 seconds: every scrypt hash uses 128 MiB on purpose):

```bash
curl -s $S/audit/safe
```
→
```
OWASP cheat sheet audit of the safe app (http://localhost:3056)
Test account: audit-6cc58c4c@example.com

✅ PASS  [Authentication] Signup gives the same answer for a new and an existing email
         new: 202 {"message":"Thanks! Check your email to continue."} · again: 202 {"message":"Thanks! Check your email to continue."}
✅ PASS  [Authentication] Rejects passwords shorter than 8 characters
         "short12" → 400 {"error":"Password must be 8 to 128 characters"}
✅ PASS  [Authentication] Accepts a 64+ character passphrase (no 'must contain a number' rule)
         65-char passphrase → 202 {"message":"Thanks! Check your email to continue."}
✅ PASS  [Authentication] Rejects passwords known from data breaches
         "password123" → 400 {"error":"This password has appeared in a data breach. Please choose a…
✅ PASS  [Password Storage] Hashed with a slow, salted algorithm (Argon2id, scrypt, bcrypt, PBKDF2)
         stored value: $scrypt$N=131072,r=8,p=1$S6elEiamwf/wq+kDN…
✅ PASS  [Authentication] Login gives the same error for unknown email and wrong password
         unknown: 401 {"error":"Wrong email or password"} · wrong pw: 401 {"error":"Wrong email or password"}
✅ PASS  [Session Management] Session cookie is HttpOnly + SameSite with a generic name
         sid=…; Path=/; HttpOnly; SameSite=Lax  (Secure is off on http://localhost; turn it on in production)
✅ PASS  [Session Management] Session ID is long and random (128+ bits)
         "PbHI0axAJScg…" (43 chars)
✅ PASS  [Session Management] Session ID changes at login
         login 200, before: FA7N0McpLGH6… after: PbHI0axAJScg…
✅ PASS  [HTTP Headers] Private pages send Cache-Control: no-store
         GET /me (200) → Cache-Control: no-store
✅ PASS  [HTTP Headers] nosniff + anti-framing headers set, X-Powered-By removed
         nosniff: yes, framing blocked: yes, X-Powered-By: (hidden)
✅ PASS  [CSRF Prevention] A cross-site POST is refused
         POST /transfer from evil.example → 403 {"error":"Cross-site request refused"}
✅ PASS  [Session Management] Logout ends the session on the server
         old cookie after logout → 401 {"error":"Not signed in"}
✅ PASS  [Forgot Password] Same answer for a known and an unknown email
         known: 202 {"message":"If that email has an account, we've sent a reset link."} · unknown: 202 {"message":"If that email has an account, we've sent a reset link."}
✅ PASS  [Error Handling] Broken input gets a generic error, no stack trace
         broken JSON → 400 {"error":"Body must be valid JSON"}
✅ PASS  [Authentication] Repeated wrong passwords get blocked
         wrong guess #6 → 429 {"error":"Too many attempts. Try again later or reset your password."}

Score: 16/16
```

The server terminal shows the "emails" from the safe app, including the warning to an existing user instead of an error to the requester:

```
📧 To: audit-6cc58c4c@example.com: welcome to PaisaPay!
📧 To: audit-6cc58c4c@example.com: someone tried to sign up with your email. If it was you, just log in or reset your password.
```

Now repeat a few of the checks by hand.

🔎 **③ User enumeration at login**: legacy vs safe.

```bash
curl -s $L/login -H "Content-Type: application/json" -d '{"email":"nobody@mail.com","password":"x"}'
curl -s $L/login -H "Content-Type: application/json" -d '{"email":"rahul@mail.com","password":"x"}'
curl -s $S/login -H "Content-Type: application/json" -d '{"email":"nobody@mail.com","password":"x"}'
curl -s $S/login -H "Content-Type: application/json" -d '{"email":"rahul@mail.com","password":"x"}'
```
→
```
{"error":"No account for that email"}
{"error":"Wrong password"}
{"error":"Wrong email or password"}
{"error":"Wrong email or password"}
```

😈 **④ Session fixation on legacy**: Vikram gets a guest id, makes Rahul log in with it, then uses it himself.

```bash
curl -s -c v.jar $L/
grep connect.sid v.jar | awk '{print $6"="$7}'
curl -s -b v.jar $L/login -H "Content-Type: application/json" -d '{"email":"rahul@mail.com","password":"chai-and-code-42"}'
curl -s -b v.jar $L/me
```
→
```
{"app":"PaisaPay (legacy)","signedInAs":null}
connect.sid=sess-1002
{"message":"Welcome back, rahul@mail.com"}
{"email":"rahul@mail.com","balance":"₹12,500"}
```
The id `sess-1002` was Vikram's before the login and is Rahul's after it. Topic 50 shows how the id gets planted.

✅ **⑤ The safe app issues a new id at login:**

```bash
curl -s -c s.jar $S/ > /dev/null
grep sid s.jar | awk '{print $6"="$7}'
curl -s -b s.jar -c s.jar $S/login -H "Content-Type: application/json" -d '{"email":"rahul@mail.com","password":"chai-and-code-42"}'
grep sid s.jar | awk '{print $6"="$7}'
```
→
```
sid=3VZ16XIBQ40Zf9v076TZF0g08n0sdPV-9oMXQTJFk-g
{"message":"Welcome back, rahul@mail.com"}
sid=lGo0-luXXmqdeYqF7MZ480ZoArd2hxLFoUjHqmxSc-Q
```

🛡️ **⑥ Response headers on a private page:**

```bash
curl -s -i -b s.jar $S/me
curl -s -i -b v.jar $L/me
```
→ (headers trimmed)
```
HTTP/1.1 200 OK
Cache-Control: no-store
X-Content-Type-Options: nosniff
Content-Security-Policy: default-src 'none'; frame-ancestors 'none'
Referrer-Policy: no-referrer
{"email":"rahul@mail.com","balance":"₹12,500"}

HTTP/1.1 200 OK
X-Powered-By: Express
{"email":"rahul@mail.com","balance":"₹12,500"}
```

💥 **⑦ Broken JSON**: the legacy app leaks its file paths and library names.

```bash
curl -s $L/login -H "Content-Type: application/json" -d '{"email": '
curl -s $S/login -H "Content-Type: application/json" -d '{"email": '
```
→
```
{"error":"Unexpected end of JSON input","stack":"SyntaxError: Unexpected end of JSON input\n    at JSON.parse (<anonymous>)\n    at parse (E:\\Job switch\\...\\node_modules\\body-parser\\lib\\types\\json.js:93:21)\n ...
{"error":"Body must be valid JSON"}
```

🔑 **⑧ Signup on the safe app**: a breached password is refused, a passphrase is welcome.

```bash
curl -s $S/signup -H "Content-Type: application/json" -d '{"email":"priya@mail.com","password":"password123"}'
curl -s $S/signup -H "Content-Type: application/json" -d '{"email":"priya@mail.com","password":"monsoon chai on a quiet balcony"}'
```
→
```
{"error":"This password has appeared in a data breach. Please choose another one."}
{"message":"Thanks! Check your email to continue."}
```

> **Windows PowerShell users:** the single quotes in `-d '...'`, `grep`/`awk` and `VAR=value node ...` work in Git Bash. In PowerShell, use Git Bash or Postman, or set the port with `$env:PORT=3056; node server.js`. The audits work in any shell: `curl.exe -s http://localhost:3056/audit/legacy`.
