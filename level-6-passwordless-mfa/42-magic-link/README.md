# 42. Magic Link Login

## Notes

### What is a magic link?

A **magic link** is a login **with no password**. The user types only their email. The server emails them a **secret, one-time link**. Clicking it logs them in. Slack, Notion, Medium and many shopping apps work this way.

It's the same machine you already built twice: email verification (topic 12) and password reset (topic 13) also email a random, single-use, short-lived link. A magic link just **ends in a login session** instead of a "verified" flag or a new password.

> **One-line answer:** the user enters their email → the server emails a random, hashed, single-use link that works for ~15 minutes → clicking it opens a confirm page → the button POSTs the token → the server deletes it, finds (or creates) the user and starts a normal session. The inbox becomes the password.

---

### Why use it? (and what it doesn't fix)

| Problem with passwords | How a magic link helps |
|---|---|
| Users pick weak passwords (`rahul123`) and reuse them | There is no password to pick, reuse or leak |
| Your DB leak exposes password hashes to cracking | There are no password hashes to crack |
| "Forgot password" is half your support tickets | Every login **is** a "forgot password" flow, so there is nothing to forget |
| Signup forms scare people away | Sign-up and sign-in are the same box: type email, click link |
| Credential stuffing (topic 52) with leaked passwords | Nothing to stuff: the attacker needs the inbox |

But be honest about the costs:

| Downside | Why |
|---|---|
| **The inbox is now the only key** | Whoever controls Rahul's email controls his account. Email security = your security. |
| **Slow** | Open the mail app, wait for the email, maybe check spam. Fine for a monthly app, annoying for one you open 20 times a day. |
| **Email scanners click links** | Corporate mail filters open every link. If GET logs in, the scanner uses up the link (Step 5). |
| **Wrong device** | Rahul asks on his laptop, opens the email on his phone: now his **phone** is logged in, not the laptop. |
| **Not phishing-proof** | Better than passwords, but a fake site can still trick you. Passkeys (topic 46) are the real fix. |

👉 Magic links are a great **first** factor for low-to-medium risk apps. For banking, add a second factor (topics 44–45) or use passkeys.

---

### Real-life example: the society gate pass 🏢

Priya orders a parcel to her flat in a Bengaluru housing society.

1. The guard doesn't ask for a password. He sends a **one-time OTP link to Priya's phone** ("Approve this visitor?") → the server emails a **sign-in link**
2. Only someone holding Priya's phone can approve → only the inbox owner can click
3. The approval works **once** and only for **the next 15 minutes** → **single-use**, **short-lived** token
4. The app shows "**Delivery from Flipkart** at Gate 2. Approve?" before letting anyone in → the **confirm page** shows "Sign in as priya@mail.com?" and where the request came from
5. If Priya never asked for a delivery, she ignores it and nobody gets in → "Didn't ask for this? Ignore this email."

---

### The flow, step by step

#### 📊 Diagrams

Open **[diagrams.html](diagrams.html)** in your browser (just double-click the file) to see:

- **Flow diagram**: every check from "type your email" to "you're logged in"
- **Data flow**: the whole journey with the real requests, cookies and tokens
- **Attacks**: what the link scanner, login CSRF and a stranger's link look like, and which check stops each one

In short: `email → rate limit → random token (hash stored, 15 min) → email the link → GET shows a confirm page (token NOT used) → POST → delete token → find or create user → new session`

#### Where does each secret live? 🔍

| Secret | Where | Stored as | Lives |
|---|---|---|---|
| Magic-link token | Only in the email | `sha256(token)` in the DB | 15 min, **one** use |
| `ml_attempt` cookie | The browser that asked for the link | `sha256(attempt)` inside the token record | 15 min |
| `sid` session cookie | The browser that clicked | `sha256(sid)` in the sessions table | 7 days (topic 09) |

---

### Step 1: The user types their email (and we rate limit)

```js
POST /auth/magic-link   { "email": "rahul@mail.com", "next": "/orders" }
```

This endpoint makes your server **send emails**, so attackers love it. Two limits:

| Limit | Stops |
|---|---|
| **Per email**: one link per minute | Someone flooding Rahul's inbox with 500 sign-in emails |
| **Per IP**: 10 requests per 15 minutes | One bot making your server email 50,000 random people (your email reputation dies, real emails go to spam) |

And the reply is **always the same** `202`, for known emails, unknown emails and emails in cooldown:

```json
{ "message": "If that email can sign in, a link is on its way. It works once, for 15 minutes." }
```

Otherwise this box tells anyone which emails have accounts (account enumeration, topic 51).

---

### Step 2: Create the token (same rules as topic 12)

```js
const token = crypto.randomBytes(32).toString("base64url"); // 256 random bits
magicTokens.set(sha256(token), { email, attemptHash, next, expiresAt: Date.now() + 15 * 60 * 1000 });
```

| ✅ Do | ❌ Don't |
|---|---|
| `crypto.randomBytes(32)` | `Math.random()`, the user id, `base64(email)` |
| Store `sha256(token)` | Store the plain token (a DB leak = working logins) |
| Expire in **10–15 minutes** | 24 hours like email verification. This link **logs you in**, so keep it short. |
| A new link **kills the older links** | Ten valid links sitting in the inbox |
| Save `next` (where to go after login) **on the server** | Put `?redirect=` in the link (open redirect, Step 6) |

Why shorter than email verification? A verification link only flips a flag. A magic link is a **login**. It's as powerful as a password, so it should be dead before anyone else can find it.

---

### Step 3: Send the email

```
To: rahul@mail.com
Subject: Your PrintKaro sign-in link
Click: https://printkaro.in/auth/verify?token=j9QecUZg...
Works once, for 15 minutes. Requested from: 49.36.x.x, Chrome on Windows
Didn't ask for this? Ignore this email. Nobody can sign in without clicking it.
```

- Build the link from **your own `BASE_URL`**, never the `Host` header (topic 12).
- Say **where the request came from**, so Rahul can spot a request he didn't make.
- Say **"ignore it if it wasn't you"**: unlike a password reset, an unwanted magic link is harmless if nobody clicks it.
- **Unknown email?** Two common choices: send a "finish creating your account" link (sign-up and sign-in in one box, what our demo does), or send "you don't have an account, sign up here". Both keep the API reply identical.

---

### Step 4: Bind the link to the browser that asked (the `ml_attempt` cookie)

When Rahul asks for a link, the server also sets a random cookie in **his** browser:

```
Set-Cookie: ml_attempt=siwqlKkp...; HttpOnly; SameSite=Lax; Max-Age=900
```

and stores `sha256(attempt)` in the token record. When the link is opened, the server compares:

| Clicked in… | Cookie matches? | What we do |
|---|---|---|
| The same browser that asked | ✅ | Normal confirm page |
| His phone (same person, different device) | ❌ | Confirm page with a **yellow warning**: "requested from a different browser (Chrome on Windows)…" |
| A browser that got a link from **someone else** | ❌ | Same warning, which is exactly what stops Step 7's attack |

Some apps are stricter: a link opened in another browser **can't** log in there, and instead shows a short code to type into the original device. That's safer but more annoying. The warning is a common middle ground.

---

### Step 5: The click: GET shows a page, POST logs in

This is the step beginners get wrong. **A GET request must not log anyone in or use up the token.**

Why? Outlook Safe Links, Gmail, antivirus tools and Slack previews **open every link** in a message to check it for malware. If `GET /auth/verify` logs in and deletes the token:

- The scanner "logs in" (into a session nobody uses), and
- When Rahul clicks, he gets "this link has expired". 😤

So:

```
GET  /auth/verify?token=…   → look the token up (don't delete it), show "Sign in as rahul@mail.com?" + a button
POST /auth/verify  token=…  → now check, delete and log in
```

Scanners follow links (GET); they don't press buttons (POST).

Two more things on the GET page:

- **`Referrer-Policy: strict-origin`**: the token is in the page's URL. If the page loads anything from another site, the browser would send that URL in the `Referer` header. `strict-origin` sends only `https://printkaro.in`, never the path.
- **Show the email** you're about to sign in as. If a stranger's link would sign you into **their** account, you can see it.

---

### Step 6: The POST: check, delete, log in

```js
if (origin && origin !== BASE_URL) return 403;  // login CSRF (Step 7)
const record = magicTokens.get(sha256(token));
if (!record) return invalid();                   // never existed or already used
magicTokens.delete(key);                         // single use, BEFORE anything else
if (Date.now() > record.expiresAt) return invalid();
let user = users.get(record.email) ?? createUser(record.email, { emailVerified: true });
// new session id, stored as a hash; clear ml_attempt; 303 → record.next
```

| Check | Why |
|---|---|
| `Origin` must be your site | Another site can't auto-submit this form (login CSRF) |
| Same error for unknown / used / expired | Attackers learn nothing about which tokens were real |
| Delete the token **before** checking expiry | One use, even if two clicks arrive at once |
| New user is created **verified** | Clicking the link **proved** they own the inbox |
| Delete **all other** links for this email | No spare working links left in the inbox |
| **New** random session id | Never reuse a session id from before login (session fixation, topic 50) |
| `303` redirect to the stored `next` | A refresh doesn't re-POST, and the redirect target was checked in Step 2 (`/orders` ✅, `//evil.com` ❌) |

---

### 🤔 Tricky parts

**1. Login CSRF with a magic link.** Vikram requests a link for **his own** account and sends it to Rahul ("check out this deal!"), or hides an auto-submitting form on his site. If it works, Rahul is silently logged in **as Vikram**. Rahul then saves his card or his address, and it's in Vikram's account. Defenses: the `Origin` check on the POST, the confirm page that shows **whose** account it is, and the "requested from a different browser" warning.

**2. "Approve the other device" flows are phishable.** Some apps keep the laptop waiting and the link just **approves** it ("click to log in on your laptop"). Then Vikram can start a login for Rahul's email on **his** laptop, and Rahul, getting an email he half-expects, clicks it and logs Vikram in. If you build this, show the requesting device and location very clearly, or use a code the user types instead.

**3. `no-referrer` breaks the Origin check.** We first used `Referrer-Policy: no-referrer` on the confirm page. Then the browser sent `Origin: null` on the form POST, and our own check refused the real user. `strict-origin` hides the token **and** keeps `Origin` working. (Found while testing this demo.)

**4. The inbox is the password, so protect email changes.** Changing the account email (topic 12's bonus) now means changing the **only** login. Require a fresh magic link to **both** the old and the new address, and notify the old one.

**5. Account linking.** A magic-link user is a **verified** email user. If Rahul later uses "Sign in with Google" with the same verified email, topic 40's rules apply. If an **unverified** password account already exists with that email, delete its password before the magic link logs in (pre-account takeover, topics 12 and 40).

---

### Common beginner mistakes

1. **Logging in on GET.**
   Email scanners use up the link before the user clicks. Show a confirm page, log in on POST.

2. **Long-lived links (24 hours, or forever).**
   A magic link is a password that sits in an inbox. 10–15 minutes.

3. **Reusable links.**
   Delete the token the moment it's used, and delete the user's other links too.

4. **Storing the plain token.**
   A DB leak gives working logins. Store `sha256(token)`.

5. **Different replies for known and unknown emails.**
   "No account with that email" leaks who uses your app. Always the same `202`.

6. **No rate limit.**
   Your "send link" button becomes a free spam cannon. Limit per email and per IP.

7. **`?redirect=` in the link without checks.**
   `/auth/verify?token=…&redirect=https://evil.com` turns your trusted email into a phishing redirect. Store `next` on the server and allow only same-site paths.

8. **Building the link from the `Host` header.**
   Attackers make your real email point to their site. Use `BASE_URL`.

9. **No `Origin` check on the POST.**
   Another site can log your user into the attacker's account (login CSRF).

10. **Reusing the old session id after login.**
    Always issue a new one (session fixation).

11. **Logging the full link.**
    Your logs (and anyone who reads them) can log in as your users.

---

### Interview questions

1. **How does magic link login work?**
   The user submits their email. The server creates a random 256-bit token, stores its hash with the email and a 15-minute expiry, and emails a link. Clicking opens a confirm page; the button POSTs the token; the server deletes it, finds or creates the user, and starts a session.

2. **Is a magic link more secure than a password?**
   It removes weak, reused and leaked passwords and credential stuffing. But the account is only as safe as the email account, it can still be phished, and it's slower. It's better than passwords alone, worse than passkeys.

3. **Why not log in directly on the GET request?**
   Email security scanners and link previews open links automatically. A GET that logs in would burn the single-use token (and create a session for the scanner). GET shows a confirm page; POST logs in.

4. **What expiry would you choose and why?**
   10–15 minutes and single use. It's equivalent to a password, so it should be useless by the time anyone else could find it.

5. **How do you stop someone from using the endpoint to spam inboxes?**
   A per-email cooldown, a per-IP rate limit, and the same reply for every request so it can't be used for enumeration either.

6. **What is login CSRF and how does it apply here?**
   The attacker makes the victim's browser log in to the **attacker's** account (with the attacker's link). The victim then saves private data into it. Stop it with an `Origin` check on the POST, a confirm page that shows the account email, and binding the link to the browser that asked for it.

7. **The user requests the link on a laptop and opens it on a phone. What happens?**
   The phone gets logged in, not the laptop. You can accept that (with a warning), show a code to type on the laptop, or let the click approve the waiting laptop (convenient but phishable).

8. **Should clicking a magic link for an unknown email create an account?**
   It can: clicking proves the email is real and owned, so the user is created verified. The API reply must be identical either way.

9. **Magic link vs email OTP?**
   Same idea, different delivery. A link is one click but can open on the wrong device. A 6-digit code (topic 43) can be typed on any device, but has only a million values, so it needs strict attempt limits.

---

### Quick recap

- Magic link = **passwordless login by email**; the **inbox is the password**
- Token: `randomBytes(32)`, stored as **`sha256`**, **15 minutes**, **single use**, new link kills old ones
- `POST /auth/magic-link`: **same `202` reply** always, **cooldown per email**, **rate limit per IP**
- Link built from **`BASE_URL`**, `next` stored **on the server**, only same-site paths
- **GET shows a confirm page, POST logs in** (email scanners!)
- POST: **`Origin` check → find → delete → expiry → find or create (verified) user → new session**
- `ml_attempt` cookie: warn when the link is opened in **another browser**
- Next: codes instead of links (topic 43), a second factor (topics 44–45), phishing-proof passkeys (topic 46)

## Code

A small **Express** app: **PrintKaro** with passwordless login. Type an email on the home page, the "email" is printed in the terminal (pretend it's your inbox), open the link, press the button, and you're in. It has a tiny browser UI and also works with curl. Users, tokens and sessions are kept in memory, so they disappear when you restart.

📄 **Full code: [server.js](server.js)**. Open it and read the comments, which follow the same steps as the notes above.

Install Express once (from this folder), then start the server:

```bash
npm install
```

```bash
node server.js
```

> Port 3000 busy? Run it on another port: `PORT=3042 node server.js` (Git Bash), then use that port in the commands below. The outputs below were recorded on port 3042.

### Try it in the browser

Open **http://localhost:3000**, type any email, and press **Email me a sign-in link**. Copy the `Click:` link from the terminal into the **same** browser → **Sign in as …** → "✅ Signed in as …". Open the link in a **different** browser (or a private window) and you'll see the yellow "requested from a different browser" warning.

### Try it with curl (Git Bash)

```bash
APP=http://localhost:3000
```

✅ **① Ask for a link.** The `-c rahul.jar` saves the `ml_attempt` cookie, like a browser would.

```bash
curl -i -c rahul.jar -b rahul.jar $APP/auth/magic-link -H "Content-Type: application/json" -d '{"email":"rahul@mail.com","next":"/orders"}'
```
→
```
HTTP/1.1 202 Accepted
Set-Cookie: ml_attempt=siwqlKkpB4fpsfZXt1A9tWTDgWNsk-eU7okE1ni9a08; Max-Age=900; Path=/; Expires=...; HttpOnly; SameSite=Lax
{"message":"If that email can sign in, a link is on its way. It works once, for 15 minutes."}
```

📧 **Check your "inbox":** the terminal where the server is running.

```
📧 To: rahul@mail.com
   Subject: Finish creating your PrintKaro account
   Click: http://localhost:3042/auth/verify?token=j9QecUZgXGMtTkubrg8MH-FKXcnuIhs_Vf5e6T3pqlo
   Works once, for 900 seconds. Requested from: ::1, curl/8.23.0
   Didn't ask for this? Ignore this email. Nobody can sign in without clicking it.
```

Copy your token into a variable:

```bash
TOKEN=PASTE_YOUR_TOKEN_HERE
```

✅ **② Open the link (GET):** only a confirm page. The token is **not** used yet, so an email scanner can't burn it.

```bash
curl -s -b rahul.jar "$APP/auth/verify?token=$TOKEN" | grep -o "<p>Sign in to.*</p>\|⚠️.*"
```
→ `<p>Sign in to PrintKaro as <b>rahul@mail.com</b>?</p>`

⚠️ **③ Open it without the cookie** (like another device, or a link someone sent you):

```bash
curl -s "$APP/auth/verify?token=$TOKEN" | grep -o "<p>Sign in to.*</p>\|⚠️.*"
```
→
```
<p>Sign in to PrintKaro as <b>rahul@mail.com</b>?</p>
⚠️ This link was requested from a different browser or device (::1, curl/8.23.0).
```

🛡️ **④ Login CSRF:** a POST from another site is refused.

```bash
curl -i -b rahul.jar -c rahul.jar $APP/auth/verify -H "Origin: http://evil.example" -d "token=$TOKEN"
```
→ `403 Forbidden` with `{"error":"Cross-site request refused"}`

✅ **⑤ Press the button (POST):** you get a session and go to `next`.

```bash
curl -i -b rahul.jar -c rahul.jar $APP/auth/verify -d "token=$TOKEN"
```
→
```
HTTP/1.1 303 See Other
Set-Cookie: sid=RbrSVcsJyG_MgCPmyBaO908HPT0nmcVJ8EBD0ZALBek; Max-Age=604800; Path=/; Expires=...; HttpOnly; SameSite=Lax
Set-Cookie: ml_attempt=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; SameSite=Lax
Location: /orders
```

❌ **⑥ Use the same link again:** it's single-use.

```bash
curl -i -b rahul.jar $APP/auth/verify -d "token=$TOKEN"
```
→ `400 Bad Request` with `{"error":"This link is invalid or has expired"}`

✅ **⑦ Who am I?** The account was created on the click, already verified.

```bash
curl -s -b rahul.jar $APP/me
```
→ `{"id":"f2703317-...","email":"rahul@mail.com","emailVerified":true,"createdAt":"2026-11-05T07:27:47.469Z","lastLoginAt":"2026-11-05T07:27:47.469Z"}`

🛡️ **⑧ Same reply for everyone:** an unknown email, or Rahul again inside the 1-minute cooldown (no email is printed for him this time).

```bash
curl -s $APP/auth/magic-link -H "Content-Type: application/json" -d '{"email":"nobody@mail.com"}'
curl -s $APP/auth/magic-link -H "Content-Type: application/json" -d '{"email":"rahul@mail.com"}'
```
→ both: `{"message":"If that email can sign in, a link is on its way. It works once, for 15 minutes."}`

🛡️ **⑨ Rate limit per IP:** the 11th request in 15 minutes is refused (the first 3 came from the steps above).

```bash
for i in $(seq 1 10); do curl -s -o /dev/null -w "%{http_code} " $APP/auth/magic-link -H "Content-Type: application/json" -d "{\"email\":\"user$i@mail.com\"}"; done; echo
```
→ `202 202 202 202 202 202 202 429 429 429`

👋 **⑩ Log out:** the session is deleted on the server.

```bash
curl -s -i -b rahul.jar -c rahul.jar -X POST $APP/logout
curl -s -b rahul.jar $APP/me
```
→ `303 See Other` to `/`, then `{"error":"Not signed in"}`

⏰ **Watch a link expire:** restart with a 10-second expiry, ask for a link, wait 10 seconds, then open it → "invalid or expired".

```bash
MAGIC_TTL_SECONDS=10 node server.js
```

> **Windows PowerShell users:** the single quotes in `-d '...'`, `$(seq ...)` and `VAR=value node ...` work in Git Bash. In PowerShell, use Git Bash, Postman, or set the variable with `$env:MAGIC_TTL_SECONDS=10; node server.js`. Restart the server to reset the rate limit.
