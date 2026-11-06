# 51. Timing Attacks & User Enumeration

## Notes

### What is user enumeration?

**User enumeration** means an attacker can find out **whether an email (or username) has an account** on your site, just by watching how your server answers. They don't need to log in. They try an email on the login, signup or forgot-password page and look for any difference: the **message**, the **status code**, or **how long the reply takes**.

A **timing attack** is the "how long" part: the attacker learns a secret from **response times**. It leaks "this user exists" (the server did more work), and it can even leak a **secret key one character at a time** when the key is compared with `===`.

Topics 06, 07 and 13 already said "use a generic message". This topic shows why the message alone isn't enough, and measures the leak with curl.

> **One-line answer:** Make "account exists" and "account doesn't exist" look **identical**: same status, same body, **same amount of work** (hash against a dummy hash for unknown users, send emails in the background). Compare secrets with **`crypto.timingSafeEqual`** on equal-length hashes, never `===`. Add **rate limits** so measuring is slow and noisy.

---

### Why it matters

| A leak lets the attacker… | Example |
|---|---|
| **Build a list of real users** | Check 1 million leaked emails against your login, keep the ones that "exist" |
| **Credential stuffing with a better hit rate** | Only try leaked passwords on emails that are real users here (topic 52) |
| **Targeted phishing** | "Dear ChaiWallet customer, your account is locked…" sent only to real customers |
| **Privacy harm** | An account on a dating, health or loan app is itself sensitive. "Is Priya on this site?" should have no answer |
| **Recover a secret** | A key compared with `===` leaks how many leading characters were right |

User enumeration is in the OWASP Testing Guide (WSTG-IDNT-04) and the OWASP Authentication Cheat Sheet. Bug bounty programs often pay for it when the app is sensitive.

---

### Real-life example: the society watchman 🏢

Rahul lives in a gated society in Bengaluru. Vikram wants to know which flats have people who matter, without being let in.

1. Vikram asks the watchman: "Is there a Mr. Sharma in B-402?" → tries an email on the login page
2. Watchman A says: "No such person here" or "Yes, but he's out" → **different messages** (leak)
3. Watchman B always says "I can't let you in", **but** for real residents he picks up the intercom and calls the flat first, which takes 30 seconds → **same message, different time** (timing leak)
4. Good watchman: always says "I can't let you in" and always takes the same time. If a resident exists, he tells **the resident** later ("someone asked for you") → **the difference goes to the owner's inbox, not to the stranger**
5. And if Vikram asks 500 times an hour, the watchman calls the society office → **rate limiting** (topic 16)

---

### Where the leaks hide

#### 📊 Diagrams

Open **[diagrams.html](diagrams.html)** in your browser (just double-click the file) to see:

- **Flow diagram**: every way a login/signup/reset reply can differ, and the fix for each
- **Data flow**: Vikram measuring login times, then cracking the vault key character by character
- **Leaky vs safe compare**: `===` stopping early vs `timingSafeEqual`

In short: `attacker sends email → server does different work or says different things → attacker sees a difference → "this email has an account"`

| Endpoint | ❌ Leaks with… | ✅ Same for everyone |
|---|---|---|
| Login | "No account with this email" vs "Wrong password"; unknown email returns in 2 ms, real one in 50 ms | "Wrong email or password", always hash |
| Signup | `409 This email is already registered` | `202 Check your email to finish signing up` |
| Forgot password | "No user found"; or the reply waits for the email to send | `202 If an account exists…`, email sent in the background |
| Email-available check | `GET /check-email?e=…` → `{ available: false }` | Don't have one, or rate-limit it hard and require a CAPTCHA |
| Account lockout | "Account locked" only appears for real accounts | Lock quietly or lock by IP too (topic 16) |
| MFA / OTP step | Asking for the OTP only when the password was right is fine; asking only when the **email** exists is not | Check password first, same reply on failure |
| Public profile URL | `/u/rahul` is 200, `/u/nobody` is 404 | Fine if profiles are public on purpose; otherwise require login |

---

### Step 1: One message, one status code

```js
// ❌ two answers
if (!user) return res.status(404).json({ error: "No account with this email" });
if (!passwordOk) return res.status(401).json({ error: "Wrong password" });

// ✅ one answer
if (!user || !passwordOk) return res.status(401).json({ error: "Wrong email or password" });
```

Check **everything** the attacker can see, not just the text:

| ✅ Same in both cases | ❌ Easy to forget |
|---|---|
| Status code | `404` vs `401` |
| Body (and its **length**) | `"Wrong password"` is 2 characters shorter than `"No account found"` |
| Headers | A `Set-Cookie` or a `Retry-After` only for real accounts |
| Redirect target | `/login?error=nouser` vs `/login?error=badpass` |
| Error from a later step | "Please verify your email first" before checking the password |

Validation errors are fine to show (`"Email looks invalid"`), because they're about the **input**, not about who has an account.

---

### Step 2: Same work, so same time

The generic message isn't enough. Password hashing is **slow on purpose** (scrypt / bcrypt / argon2, about 50 ms, topic 04). If the code skips it for unknown emails, the stopwatch tells the truth:

```
nobody@mail.com  404  0.0019s   ← no user, no hashing
rahul@mail.com   401  0.0499s   ← real user, scrypt ran
```

Fix: **always hash**, against a dummy hash when there's no user:

```js
const DUMMY_SALT = crypto.randomBytes(16);
const DUMMY_HASH = crypto.scryptSync("not-a-real-password", DUMMY_SALT, 64);

const user = users.get(email);
const hash = crypto.scryptSync(password, user?.salt ?? DUMMY_SALT, 64);   // always runs
const ok = crypto.timingSafeEqual(hash, user?.passwordHash ?? DUMMY_HASH) && !!user;
```

| ✅ Do | ❌ Don't |
|---|---|
| Hash with the **same algorithm and cost** as real users | A dummy `bcrypt` with cost 4 while users have cost 12 |
| Keep `&& !!user` so the dummy hash can never log anyone in | Let a dummy password accidentally match |
| Do the same DB lookups on both paths | `if (!user) return` before the slow parts |
| Re-check after upgrading hash cost: old users have the old cost | Assume all users are on the same parameters |

---

### Step 3: Slow side effects go in the background

Forgot password and signup send **emails**, and an SMTP call takes hundreds of milliseconds. If the reply waits for it, only real users are slow, even with a perfect message:

```
nobody@mail.com  202  0.0023s
rahul@mail.com   202  0.3071s   ← same message, but it waited for the email
```

```js
// ❌ reply waits for the email
if (user) await sendEmail(email, …);
res.status(202).json({ message: "If an account exists for this email, we've sent a reset link" });

// ✅ reply first, send later (a job queue in real apps: BullMQ, SQS, a worker)
if (user) setImmediate(() => sendEmail(email, …));
res.status(202).json({ message: "If an account exists for this email, we've sent a reset link" });
```

**Signup** is the hardest one, because "create account" and "email already taken" are different actions. The trick: give the **same reply** and put the difference **in the email**, which only the real owner can read.

| Email is new | Email already has an account |
|---|---|
| Create unverified account, send "verify your email" (topic 12) | Create nothing, send "someone tried to sign up with your email. Forgot your password?" |
| Reply `202 Check your email to finish signing up` | Reply `202 Check your email to finish signing up` |

> Some products decide the UX cost isn't worth it (a public social network where usernames are visible anyway). That's a valid choice, but make it **on purpose**, and still rate-limit.

**Another option: a minimum response time.** "Never reply before 500 ms" hides small differences, but it slows everyone down, and work done **after** the deadline still leaks. Doing the same work is better.

---

### Step 4: Compare secrets in constant time

`===` on strings stops at the **first different character**. A guess with more correct leading characters takes slightly longer. Over HTTP that's nanoseconds, but attackers send thousands of requests and average out the noise (it's been done over a network, against real systems).

Our demo exaggerates it (40 ms per matching character) so you can see it with curl:

```
0xxxxx 0.0025s
3xxxxx 0.0015s
4xxxxx 0.0550s   ← first character is "4"
5xxxxx 0.0016s
```

Then the attacker keeps "4" and tries the second character, and so on. 6 characters × 16 tries = **96 requests** instead of 16 million.

Fix: hash both sides (so the lengths are equal) and use `timingSafeEqual`, which always checks every byte:

```js
const sha256 = (v) => crypto.createHash("sha256").update(v).digest();
crypto.timingSafeEqual(sha256(guess), sha256(secret));   // ✅ no early exit, no length leak
guess === secret;                                         // ❌
```

| ✅ Use constant-time compare for | Why |
|---|---|
| API keys, webhook signatures (HMAC), CSRF tokens, reset/magic-link tokens, OTP codes | The attacker sends guesses and watches the time |
| Already-hashed lookups (`tokens.get(sha256(token))`) | A hash-map lookup on the **hash** leaks nothing useful about the token |
| Passwords | Don't compare passwords at all: compare their **scrypt/bcrypt hashes** with `timingSafeEqual` (bcrypt's `compare()` does this for you) |

`crypto.timingSafeEqual` **throws** if the two buffers have different lengths. That's why we hash first: never "check the length, then compare", because that leaks the length.

---

### Step 5: Make measuring expensive

Timing differences that remain (DB caches, network jitter) need **many** samples to measure. Don't give the attacker many:

- **Rate limit** login, signup and forgot-password per IP **and** per email (topic 16)
- **CAPTCHA** or proof-of-work after a few failures
- **Monitor**: one IP trying 5,000 different emails is enumeration, alert on it (topic 55)
- **Don't expose** "is this email available?" endpoints without login

---

### 🤔 Tricky parts

**1. The message is fixed but the timing isn't.** This is the most common real-world bug, and our `/vulnerable/forgot-password` has exactly it: perfect generic message, 300 ms slower for real users.

**2. `&& !!user` matters.** Without it, if someone's password happens to match the dummy hash, they're logged in as `undefined`. Rare, but it's a security bug.

**3. Error responses from other layers.** A WAF, a database "user is disabled" check or an exception that only fires for real users can change the status code or add a header. Test the **whole** response, end to end.

**4. Username-based sites.** If usernames are public (`/u/rahul`), hiding them on the login page doesn't help much. Enumeration matters most when the account itself is private or sensitive.

**5. OAuth / magic link.** "We've sent a magic link" must be the same reply for unknown emails too (topic 42). Social login "an account with this email already exists, log in with Google instead" is a leak too (topic 40).

**6. Timing tests are noisy.** One request proves nothing. Measure many times (our safe login varied from 0.05 s to 0.15 s because of machine load) and compare averages or medians.

**7. `timingSafeEqual` isn't magic.** It only makes the **compare** constant time. If you do `if (!keyExists) return` before it, you've leaked anyway.

---

### Common beginner mistakes

1. **Different messages for "no user" and "wrong password".**
   Use one: "Wrong email or password".

2. **Returning early when the user doesn't exist.**
   Hash against a dummy hash so both paths cost the same.

3. **`await sendEmail()` before replying** in forgot-password or signup.
   Reply first, send from a queue.

4. **Signup that says "email already registered".**
   Same reply for both; send the "you already have an account" note to the inbox.

5. **Comparing secrets with `===`** (API keys, HMAC signatures, tokens).
   Use `crypto.timingSafeEqual` on equal-length buffers (hash first).

6. **Checking length before `timingSafeEqual`** and returning early.
   That leaks the length. Hash both sides instead.

7. **Different status codes** (404 vs 401) or headers with the same message.

8. **No rate limit**, so the attacker can take 10,000 samples per email.

9. **An "is this email taken?" endpoint** for the signup form, open to everyone.

10. **Testing with one request** and deciding "the timing is fine".

---

### Interview questions

1. **What is user enumeration and why is it a problem?**
   Learning whether an account exists from differences in the server's response. It gives attackers a list of real users for credential stuffing and phishing, and it's a privacy leak on sensitive apps.

2. **How do you prevent it on login?**
   Same status and message for "no user" and "wrong password", and always run the password hash (against a dummy hash for unknown users) so the response time is the same. Plus rate limiting.

3. **The error message is generic. Can there still be enumeration?**
   Yes: through timing (skipped hashing, an email sent before replying), status codes, headers, body length, or later steps like "verify your email first".

4. **How do you handle signup without revealing taken emails?**
   Always reply "check your email". If the email is new, send a verification link; if it's taken, send "someone tried to sign up with your address" to that inbox. Only the owner learns the difference.

5. **What is a timing attack on string comparison?**
   `===` stops at the first mismatch, so a guess with more correct leading characters takes longer. By measuring many requests the attacker finds the secret one character at a time, turning an impossible brute force into a few hundred requests per character.

6. **How does `crypto.timingSafeEqual` help, and what's its catch?**
   It compares every byte with no early exit, so the time doesn't depend on where the first difference is. It throws on different lengths, so hash both values first (SHA-256) to make them equal length without leaking the length.

7. **Why not just add a random delay?**
   Random noise averages out over many requests; the difference is still there. A fixed minimum response time helps a little but slows everyone. Doing the same work on both paths is the real fix.

8. **Do you need constant-time compare for passwords?**
   You never compare plain passwords. You compare hashes, and the library's verify function (`bcrypt.compare`, `argon2.verify`) or `timingSafeEqual` on scrypt output does it in constant time.

---

### Quick recap

- Enumeration = "does this email have an account?" answered by **message, status, headers or time**
- One generic reply: **"Wrong email or password"**, same status, same shape
- **Always hash** (dummy hash for unknown users); keep `&& !!user`
- **Send emails in the background**; signup puts the difference **in the inbox**
- Compare secrets with **`timingSafeEqual` on SHA-256 hashes**, never `===`
- **Rate limit + monitor** so measuring takes forever (topic 16, 55); credential stuffing is next (topic 52)

## Code

A small **Express** app, **ChaiWallet**, with each endpoint in two versions:

| ❌ Vulnerable | Leak | ✅ Safe |
|---|---|---|
| `POST /vulnerable/login` | Different messages + unknown emails skip scrypt (fast) | `POST /login` |
| `POST /vulnerable/signup` | `409 already registered` | `POST /signup` |
| `POST /vulnerable/forgot-password` | Generic message, but waits 300 ms for the email for real users | `POST /forgot-password` |
| `GET /vulnerable/vault?key=` | Character-by-character compare (exaggerated to 40 ms per matching character) | `GET /vault?key=` |

Test accounts: `rahul@mail.com` / `chai-and-code-42` and `priya@mail.com` / `masala-dosa-77`. The vault key is 6 random hex characters, new on every start, and printed in the terminal only so you can check the attack found it. Emails are printed to the terminal. Everything is in memory, so a restart resets it.

📄 **Full code: [server.js](server.js)**. Open it and read the comments, which follow the same steps as the notes above.

Install Express once (from this folder), then start the server:

```bash
npm install
```

```bash
node server.js
```

> Port 3000 busy? Run it on another port: `PORT=3051 node server.js` (Git Bash). The outputs below were recorded on port 3051. Your times will differ a little; look at the **gap** between the two rows.

### Try it with curl (Git Bash)

```bash
APP=http://localhost:3051
```

❌ **① Login with two different messages.** Vikram learns Rahul has an account without knowing his password:

```bash
curl -s $APP/vulnerable/login -H "Content-Type: application/json" -d '{"email":"nobody@mail.com","password":"x"}'
curl -s $APP/vulnerable/login -H "Content-Type: application/json" -d '{"email":"rahul@mail.com","password":"x"}'
```
→
```
{"error":"No account with this email"}
{"error":"Wrong password"}
```

⏱️ **② Even if the message were fixed, the time leaks.** `-w` prints the status and how long the request took:

```bash
for e in nobody@mail.com rahul@mail.com nobody@mail.com rahul@mail.com; do curl -s -o /dev/null -w "$e %{http_code} %{time_total}s\n" $APP/vulnerable/login -H "Content-Type: application/json" -d "{\"email\":\"$e\",\"password\":\"guess123\"}"; done
```
→
```
nobody@mail.com 404 0.001923s
rahul@mail.com 401 0.049914s
nobody@mail.com 404 0.001794s
rahul@mail.com 401 0.048552s
```
About 2 ms vs 50 ms: real users are the ones where scrypt ran.

✅ **③ The safe login:** same message, same status, same work.

```bash
for e in nobody@mail.com rahul@mail.com nobody@mail.com rahul@mail.com; do curl -s -o /dev/null -w "$e %{http_code} %{time_total}s\n" $APP/login -H "Content-Type: application/json" -d "{\"email\":\"$e\",\"password\":\"guess123\"}"; done
```
→
```
nobody@mail.com 401 0.096722s
rahul@mail.com 401 0.113933s
nobody@mail.com 401 0.082883s
rahul@mail.com 401 0.085570s
```
Both are in the same range (the wobble is machine load, and it goes both ways). The body is always `{"error":"Wrong email or password"}`, and the right password still works:

```bash
curl -s $APP/login -H "Content-Type: application/json" -d '{"email":"rahul@mail.com","password":"chai-and-code-42"}'
```
→ `{"message":"Welcome back, rahul@mail.com"}`

❌ **④ Signup that tells you who's registered:**

```bash
curl -s -w " %{http_code}\n" $APP/vulnerable/signup -H "Content-Type: application/json" -d '{"email":"priya@mail.com","password":"anything-123"}'
curl -s -w " %{http_code}\n" $APP/vulnerable/signup -H "Content-Type: application/json" -d '{"email":"neha@mail.com","password":"anything-123"}'
```
→
```
{"error":"This email is already registered"} 409
{"message":"Account created"} 201
```

✅ **⑤ Safe signup:** the same reply, and the difference goes to the inbox.

```bash
curl -s -w " %{http_code} %{time_total}s\n" $APP/signup -H "Content-Type: application/json" -d '{"email":"priya@mail.com","password":"anything-123"}'
curl -s -w " %{http_code} %{time_total}s\n" $APP/signup -H "Content-Type: application/json" -d '{"email":"amit@mail.com","password":"anything-123"}'
```
→
```
{"message":"Check your email to finish signing up"} 202 0.081374s
{"message":"Check your email to finish signing up"} 202 0.075276s
```
The server terminal shows what each person actually got:
```
📧 To: priya@mail.com
   Subject: Someone tried to sign up with your email
   You already have a ChaiWallet account. Forgot your password? http://localhost:3051/forgot-password

📧 To: amit@mail.com
   Subject: Welcome to ChaiWallet
   Click the link to verify your email: …
```

⏱️ **⑥ Forgot password: perfect message, leaky timing.**

```bash
for e in nobody@mail.com rahul@mail.com; do curl -s -w " $e %{http_code} %{time_total}s\n" $APP/vulnerable/forgot-password -H "Content-Type: application/json" -d "{\"email\":\"$e\"}"; done
```
→
```
{"message":"If an account exists for this email, we've sent a reset link"} nobody@mail.com 202 0.002330s
{"message":"If an account exists for this email, we've sent a reset link"} rahul@mail.com 202 0.307052s
```

✅ **⑦ Safe forgot password** replies first and sends the email in the background:

```bash
for e in nobody@mail.com rahul@mail.com; do curl -s -w " $e %{http_code} %{time_total}s\n" $APP/forgot-password -H "Content-Type: application/json" -d "{\"email\":\"$e\"}"; done
```
→
```
{"message":"If an account exists for this email, we've sent a reset link"} nobody@mail.com 202 0.002796s
{"message":"If an account exists for this email, we've sent a reset link"} rahul@mail.com 202 0.004097s
```
The reset email (with a real token) still shows up in the terminal a moment later.

🔑 **⑧ The leaky vault compare.** Try every first character and watch the time (the key in this run was `4d0fe2`):

```bash
for c in 0 1 2 3 4 5 6 7 8 9 a b c d e f; do curl -s -o /dev/null -w "${c}xxxxx %{time_total}s\n" "$APP/vulnerable/vault?key=${c}xxxxx"; done
```
→
```
0xxxxx 0.002526s
1xxxxx 0.002805s
2xxxxx 0.002575s
3xxxxx 0.001498s
4xxxxx 0.054981s
5xxxxx 0.001558s
...
fxxxxx 0.002131s
```

😈 **⑨ Crack the whole key**, one character at a time (keep the slowest guess, move on). This takes about 40 seconds:

```bash
KNOWN=""
for pos in 1 2 3 4 5 6; do
  BEST=""; BEST_T=0
  for c in 0 1 2 3 4 5 6 7 8 9 a b c d e f; do
    GUESS=$(printf "%-6s" "$KNOWN$c" | tr ' ' x)
    T=$(curl -s -o /dev/null -w "%{time_total}" "$APP/vulnerable/vault?key=$GUESS")
    if awk "BEGIN{exit !($T > $BEST_T)}"; then BEST=$c; BEST_T=$T; fi
  done
  KNOWN="$KNOWN$BEST"; echo "position $pos: $KNOWN (slowest: ${BEST_T}s)"
done
curl -s "$APP/vulnerable/vault?key=$KNOWN"; echo
```
→
```
position 1: 4 (slowest: 0.042531s)
position 2: 4d (slowest: 0.094084s)
position 3: 4d0 (slowest: 0.137298s)
position 4: 4d0f (slowest: 0.196522s)
position 5: 4d0fe (slowest: 0.230050s)
position 6: 4d0fe2 (slowest: 0.301035s)
{"message":"🔓 Vault open","balance":"₹12,40,000"}
```
96 requests instead of 16,777,216 possible keys.

✅ **⑩ The safe vault** (SHA-256 both sides + `timingSafeEqual`) takes the same time for every guess, so there's nothing to climb:

```bash
for k in 0xxxxx 4xxxxx 4d0fex; do curl -s -o /dev/null -w "$k %{http_code} %{time_total}s\n" "$APP/vault?key=$k"; done
```
→
```
0xxxxx 403 0.002284s
4xxxxx 403 0.001942s
4d0fex 403 0.001923s
```

> **Windows PowerShell users:** the single quotes in `-d '...'`, the `for` loops and `VAR=value node ...` work in Git Bash. In PowerShell, use Git Bash or Postman (its response time is shown next to the status), or set the port with `$env:PORT=3051; node server.js`. Restart the server to reset the accounts and get a new vault key.
