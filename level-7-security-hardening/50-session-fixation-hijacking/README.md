# 50. Session Fixation & Hijacking

## Notes

### What are session fixation and session hijacking?

A session id (the `sid` cookie from topic 09) is a **bearer credential**: whoever sends it **is** the user. Attackers have two ways to get a working one:

- **Session hijacking:** the attacker **steals** your session id **after** you log in (from a log file, an XSS script, an unencrypted Wi-Fi, malware, a shared computer) and uses it.
- **Session fixation:** the attacker **gives you** a session id **before** you log in. You log in, the server keeps the same id, and now the attacker's copy is logged in too. Nothing had to be stolen.

> **One-line answer:** Fixation = "the attacker picks your session id before login"; fix it by **issuing a brand-new id at login** (and at every privilege change) and never accepting ids from the URL or ids you didn't issue. Hijacking = "the attacker copies your id after login"; make it **hard to steal** (`HttpOnly`, `Secure`, `SameSite`, HTTPS, no ids in URLs or logs) and **worth little when stolen** (idle + absolute timeouts, browser binding, password re-check for dangerous actions, kill all sessions on password change, real server-side logout).

---

### Why it matters

| Problem | What goes wrong |
|---|---|
| Login keeps the pre-login session id | Anyone who knew that id is now logged in as you (**fixation**) |
| Session id accepted from the URL (`?sid=`, `;jsessionid=`) | A link is enough to plant an id. It also leaks through `Referer`, browser history, proxy logs, screenshots |
| Server accepts ids it never issued ("permissive") | The attacker doesn't even need to visit: he just makes one up |
| Cookie without `HttpOnly` / `Secure` | XSS reads it (topic 48), plain-HTTP Wi-Fi sniffs it (topic 05) |
| Sessions that never expire | A cookie copied last month still works today |
| Password change / logout doesn't end sessions on the server | The attacker's copy keeps working after the victim "fixes" things |

Both are in the OWASP Top 10 under *A07: Identification and Authentication Failures*.

---

### Real-life example: the bank locker key 🔑

Rahul rents a locker at a bank in Delhi. The bank gives a numbered **token** at the counter, and whoever shows that token gets into the locker room.

1. **Fixation:** Vikram takes a token from the counter, then hands it to Rahul in the queue: "Sir, use this one, it's faster." Rahul shows his ID (logs in) and the bank links **that** token to Rahul's locker. Vikram remembered the number → he's in.
   **Fix:** the bank **throws away** whatever token you walked in with and prints a **fresh** one the moment you prove who you are.
2. **Hijacking:** Rahul gets a fresh token, but leaves it on the table at the chai stall. Vikram copies it.
   **Fixes:** tokens **expire** if unused for 30 minutes and after 12 hours anyway; the guard notices **the person** is different (browser binding); the locker itself still needs Rahul's **signature** for big things (password re-check); and when Rahul reports a problem, **every** token of his is cancelled.

---

### The big picture

#### 📊 Diagrams

Open **[diagrams.html](diagrams.html)** in your browser (just double-click the file) to see:

- **Flow diagram**: every check a session id goes through, and where fixation and hijacking are stopped
- **Data flow (fixation)**: Vikram plants an id, Rahul logs in, vulnerable vs safe login side by side
- **Data flow (hijacking)**: Rahul's id is copied, and what each defense does to the copy

In short: `fixation: attacker plants id → victim logs in → same id now logged in` · `fix: new id at login`. `hijacking: victim logs in → id copied → attacker replays it` · `fix: hard to steal + short-lived + bound + re-check password + revoke`.

| | Session fixation | Session hijacking |
|---|---|---|
| When does the attacker get the id? | **Before** login (he chooses it) | **After** login (he steals it) |
| How? | Link with `?sid=`, a subdomain setting a cookie for the parent domain, XSS, a shared/kiosk computer | XSS (topic 48), sniffing plain HTTP, logs, `Referer`, malware, physical access |
| Main fix | **Regenerate the id at login** | `HttpOnly`/`Secure`/`SameSite`, timeouts, binding, revocation |

---

### Step 1: Regenerate the session id at login (the fixation fix)

```js
const old = getSession(req);
if (old) sessions.delete(sha256(old.sid));          // the pre-login id dies
const { sid } = newSession(res, {
  email: user.email,
  cart: old?.s.cart ?? [],                           // copy the guest data you want to keep
  ua: ua(req),
});
```

Why does a session exist **before** login at all? Guest carts, language choice, CSRF tokens (topic 47), the OAuth `state` (topic 35). That's normal, and exactly why login must not reuse it.

| ✅ Do | ❌ Don't |
|---|---|
| New id at **login**, **logout**, **MFA step done** (topic 45), **role change**, **password change** | Just set `session.userId = …` on the existing session |
| In `express-session`: `req.session.regenerate(cb)` then set the user | Forget the callback; the new session must be saved before you respond |
| Use Passport 0.6+ (it regenerates in `req.login()`, topic 41) | Stay on an old library version that doesn't |
| Copy over only the guest data you need (cart) | Copy "everything", including some old flag like `isAdmin` |

---

### Step 2: Only accept ids that you issued, only from a cookie

```js
// ✅ cookie only. A ?sid= in the URL is ignored.
const sid = parseCookies(req).sid;
const s = sid && sessions.get(sha256(sid));
if (!s) return null;   // unknown id (maybe made up by an attacker): ignored, a fresh one is issued
```

- **Never** put session ids in URLs. They leak through `Referer` headers, history, server logs and screenshots, and they make fixation a one-click attack.
- Be **strict**: an id the server doesn't know is never "adopted". (PHP calls this `session.use_strict_mode=1`; in old PHP and Java apps it was off.)
- Ids come from the server's CSPRNG: `crypto.randomBytes(32)`, at least 128 bits of randomness. Store only `sha256(sid)`, so a leaked sessions table can't be replayed.
- Use the cookie name **`__Host-sid`** in production. The browser then refuses that cookie unless it has `Secure`, `Path=/` and **no `Domain`**, so `evil.example.com` can't "toss" a cookie onto `example.com` (topic 10).

---

### Step 3: Make the id hard to steal

| Flag / rule | Stops |
|---|---|
| `HttpOnly` | `document.cookie` in an XSS script (topic 48) |
| `Secure` + HTTPS + HSTS | Sniffing on café Wi-Fi (topic 05) |
| `SameSite=Lax` | Most cross-site request tricks (topic 47) |
| No id in URLs, logs or error messages | Leaks through `Referer`, log files, support tickets |
| `Cache-Control: no-store` on session pages | A shared proxy caching a logged-in page |

In our demo, the safe cookie is `sid=…; Path=/; HttpOnly; SameSite=Lax` and the vulnerable one is just `sid=…; Path=/`.

---

### Step 4: Make a stolen id worth little

Assume a copy **will** leak one day. Then:

**a) Timeouts.** Two clocks, both checked on the server:

```js
if (now - s.lastSeenAt > IDLE_TIMEOUT_MS || now - s.createdAt > ABSOLUTE_TIMEOUT_MS) { sessions.delete(key); return null; }
```

| Timeout | Typical value | Why |
|---|---|---|
| **Idle** | 15–30 min (banks: 5–10) | A forgotten tab on a shared computer dies on its own |
| **Absolute** | 8–24 h (or 30 days with "remember me", topic 15) | Even a busy stolen session ends eventually |

Cookie `Max-Age` alone is not a timeout: the attacker controls his copy of the cookie and ignores it.

**b) Binding / anomaly detection.** Remember **where** the session logged in and react when that changes:

```js
if (s.email && s.ua !== ua(req)) { sessions.delete(key); alertUser(s.email); return null; }
```

| Signal | Reliability |
|---|---|
| User-Agent (browser family + OS) | Cheap, but **the attacker can copy it**. A Chrome auto-update also changes the full string |
| IP address | **Don't** hard-bind: mobile networks and office NATs change IPs all the time. Use the country / ASN as a risk signal |
| Device-bound tokens (DPoP, Device Bound Session Credentials in Chrome) | Strong: the key never leaves the device (Level 8) |

Treat these as **risk signals**: end the session, or ask for the password/MFA again (step-up, topic 45). In our demo a different browser ends the session for **both** sides (we can't tell who is the real Rahul) and Rahul gets an email.

**c) Re-check the password for dangerous actions.** A hijacker has the cookie, not the password:

```js
if (!checkPassword(cur.s.email, req.body.currentPassword)) return res.status(403).json({ error: "Confirm this change with your current password" });
```

Use it for: change password / email / phone, add a payout account, disable MFA, delete account.

**d) Kill every session when it matters.** Password change, "log out of all devices" (topic 26), suspected theft: delete **all** of the user's sessions on the server, then give the current browser a new id.

**e) Real logout.** Delete the session on the server, not just the cookie (topic 11).

---

### 🤔 Tricky parts

**1. "We use JWTs, so no fixation."** JWTs are issued at login, so classic fixation is rare. But a stolen JWT is pure hijacking, and it **can't be revoked** without a blocklist (topic 24). Short expiry + refresh-token rotation (topic 23) is your timeout.

**2. Regenerate, then lose the cart.** Beginners regenerate correctly and then wonder where the cart went. Copy the guest data you need into the new session.

**3. `req.session.regenerate()` is async.** In `express-session`, setting `req.session.userId` before the callback runs writes to the **old** session.

**4. Subdomains can plant cookies.** `blog.example.com` (maybe hosted by someone else) can set a cookie with `Domain=example.com`. `__Host-` prefix blocks this.

**5. Logging the cookie.** Request loggers that dump all headers write every session id into your logs. Redact `Cookie` and `Authorization`.

**6. Binding too strictly locks out real users.** Hard IP binding logs out every mobile user on the move. Score signals, don't block on one.

**7. The fixated session from earlier is still alive.** Part A of our demo (vulnerable login) left a logged-in session that Vikram knows. When Rahul changes his password in Part C, `sessionsEnded` is **2**: that one dies too. Revoking **all** sessions is what cleans up leftovers you don't know about.

---

### Common beginner mistakes

1. **Not issuing a new session id at login.**
   Classic session fixation.

2. **Reading a session id from the URL or a header the attacker controls.**
   Cookie only.

3. **Accepting session ids the server never issued.**
   Look it up; unknown means "new session".

4. **Weak ids** like `userId + timestamp` or `Math.random()`.
   Use `crypto.randomBytes(32)`.

5. **Missing `HttpOnly`, `Secure`, `SameSite`.**
   Every one of them closes a theft route.

6. **No server-side expiry.**
   Cookie `Max-Age` is a suggestion to the browser, not to the attacker.

7. **Logout and password change that only clear the cookie.**
   The stolen copy keeps working.

8. **Letting the cookie alone authorize dangerous actions.**
   Ask for the password (or MFA) again.

9. **Hard-binding to IP address.**
   Real users get logged out; attackers on the same Wi-Fi share the IP anyway.

10. **Logging full `Cookie` headers.**

---

### Interview questions

1. **What is session fixation?**
   The attacker gets the victim to use a session id the attacker already knows (via a URL, a planted cookie, a shared computer). The victim logs in, the server keeps the id, and the attacker is logged in as the victim.

2. **How do you prevent session fixation?**
   Issue a new session id at login and every privilege change, delete the old one, never accept ids from URLs, and reject ids the server didn't issue (strict mode). `__Host-` cookies stop subdomain cookie planting.

3. **What is session hijacking, and how is it different?**
   Stealing a valid session id **after** login and replaying it. Fixation **plants** the id before login; hijacking **steals** it after.

4. **How do you defend against hijacking?**
   Make theft hard (`HttpOnly`, `Secure`, `SameSite`, HTTPS + HSTS, no ids in URLs or logs, prevent XSS) and limit the damage (idle + absolute timeouts, anomaly detection on browser/location, re-authentication for sensitive actions, revoke all sessions on password change, server-side logout).

5. **Should you bind a session to the IP address?**
   Not strictly. IPs change on mobile and are shared behind NAT. Use IP/ASN/country changes as a risk signal that triggers re-authentication.

6. **What's the difference between idle and absolute timeout?**
   Idle ends a session after a period with no requests (a forgotten tab). Absolute ends it a fixed time after login, however active it is (a stolen but busy session). Both must be enforced on the server.

7. **In Express, how do you regenerate a session?**
   `req.session.regenerate((err) => { req.session.userId = user.id; req.session.save(() => res.json(...)); })`. Passport 0.6+ does it in `req.login()`.

8. **What do you do when you detect a session used from a new browser?**
   End it (or require step-up auth), alert the user (topic 55), and offer "log out of all devices" and a password change.

---

### Quick recap

- **Fixation** = attacker plants the id **before** login. **Hijacking** = attacker steals it **after**
- **New session id at login** and every privilege change; copy only the guest data you need
- Ids only from the **cookie**, only ones **you issued**, 256 random bits, stored hashed, cookie named `__Host-sid`
- **Hard to steal:** `HttpOnly`, `Secure`, `SameSite`, HTTPS, no ids in URLs or logs, no XSS (topic 48)
- **Worth little:** idle + absolute timeouts, browser/location signals, password re-check for dangerous actions
- **Revoke on the server:** all sessions on password change, the session on logout
- Next: timing attacks and user enumeration (topic 51)

## Code

A small **Express** shop, **ChaiCart**, with a guest cart (so a session exists before login). Every attack has a vulnerable and a safe route:

| | ❌ Vulnerable | ✅ Safe |
|---|---|---|
| Get a session | `GET /vulnerable/shop?sid=…` adopts **any** id from the URL | `GET /shop` reads the cookie only, issues a fresh id otherwise |
| Log in | `POST /vulnerable/login` keeps the same id | `POST /login` deletes the old id, issues a new one, copies the cart |
| Who am I? | `GET /vulnerable/me`: no timeouts, no browser check | `GET /me`: idle + absolute timeout, ends the session if the browser changes |
| Cookie | `sid=…; Path=/` | `sid=…; Path=/; HttpOnly; SameSite=Lax` |

Plus `POST /cart`, `POST /account/password` (needs the current password, ends **all** sessions) and `POST /logout`. Each response shows a short `session` tag (the first 8 hex characters of `sha256(sid)`) so you can see when the id changes. Everything is in memory, so a restart resets it.

📄 **Full code: [server.js](server.js)**. Open it and read the comments, which follow the same steps as the notes above.

Install Express once (from this folder), then start the server:

```bash
npm install
```

```bash
node server.js
```

> Port 3000 busy? Run it on another port: `PORT=3050 node server.js` (Git Bash). The outputs below were recorded on port 3050.

### Try it (Git Bash)

```bash
APP=http://localhost:3050
J="Content-Type: application/json"
R="Rahul-Laptop-Chrome"
```

`-A` sets the User-Agent, so `$R` is "Rahul's browser" and `Vikram-PC` is Vikram's. `-c` saves cookies to a file, `-b` sends them.

#### Part A: session fixation on the vulnerable routes ❌

😈 **① Vikram makes up a session id.** The permissive server adopts it:

```bash
curl -s "$APP/vulnerable/shop?sid=vikram-chose-this-id-123"
```
→ `{"shop":"☕ ChaiCart (vulnerable)","signedInAs":null,"cart":[],"session":"443088c0"}`

📩 **② He sends Rahul the link.** Rahul clicks it, and the server sets Vikram's id as Rahul's cookie (no `HttpOnly` either):

```bash
curl -s -i -A "$R" -c rahul.jar "$APP/vulnerable/shop?sid=vikram-chose-this-id-123"
```
→
```
Set-Cookie: sid=vikram-chose-this-id-123; Path=/
{"shop":"☕ ChaiCart (vulnerable)","signedInAs":null,"cart":[],"session":"443088c0"}
```

🛒 **③ Rahul shops and logs in.** Same `session` tag before and after login:

```bash
curl -s -A "$R" -b rahul.jar $APP/cart -H "$J" -d '{"item":"Masala chai x2"}'
curl -s -A "$R" -b rahul.jar $APP/vulnerable/login -H "$J" -d '{"email":"rahul@mail.com","password":"chai-and-code-42"}'
```
→ `{"cart":["Masala chai x2"],"session":"443088c0"}` then `{"message":"Logged in as rahul@mail.com","session":"443088c0"}`

😱 **④ Vikram uses the id he chose.** He never saw a password or stole anything:

```bash
curl -s -A "Vikram-PC" -b "sid=vikram-chose-this-id-123" $APP/vulnerable/me
```
→ `{"email":"rahul@mail.com","cart":["Masala chai x2"],"session":"443088c0"}`

#### Part B: the same attack on the safe routes ✅

```bash
rm -f rahul.jar
```

🚫 **⑤ The URL id is ignored.** The safe shop issues its own random id, with `HttpOnly`:

```bash
curl -s -i -A "$R" "$APP/shop?sid=vikram-chose-this-id-123"
```
→
```
Set-Cookie: sid=ULWzK47lHXdYiE_hs1RIYyZ8oGETdgbolH5QanzPD70; Path=/; HttpOnly; SameSite=Lax
{"shop":"☕ ChaiCart","signedInAs":null,"cart":[],"session":"a81008ae"}
```

😈 **⑥ So Vikram gets a real guest id** and plants that one in Rahul's browser (think: a subdomain setting the cookie, or a shared computer):

```bash
curl -s -c vikram.jar $APP/shop
VSID=$(grep sid vikram.jar | awk '{print $7}')
```
→ `{"shop":"☕ ChaiCart","signedInAs":null,"cart":[],"session":"82f26286"}`

🔄 **⑦ Rahul shops and logs in with the planted cookie.** The login **regenerates** the id and keeps the cart:

```bash
curl -s -A "$R" -b "sid=$VSID" $APP/cart -H "$J" -d '{"item":"Masala chai x2"}'
curl -s -A "$R" -b "sid=$VSID" -c rahul.jar $APP/login -H "$J" -d '{"email":"rahul@mail.com","password":"chai-and-code-42"}'
```
→ `{"cart":["Masala chai x2"],"session":"82f26286"}` then `{"message":"Logged in as rahul@mail.com","oldSession":"82f26286","session":"f69d5357"}`

✅ **⑧ Vikram's id is dead; Rahul's new one works:**

```bash
curl -s -b "sid=$VSID" $APP/me
curl -s -A "$R" -b rahul.jar $APP/me
```
→
```
{"error":"Not signed in"}
{"email":"rahul@mail.com","cart":["Masala chai x2"],"session":"f69d5357","idleExpiresAt":"2026-11-06T02:24:24.158Z","absoluteExpiresAt":"2026-11-06T13:54:24.021Z"}
```

#### Part C: session hijacking (Rahul's id leaks)

```bash
RSID=$(grep sid rahul.jar | awk '{print $7}')
```

🕵️ **⑨ Vikram replays the copied id from his own browser.** The vulnerable route doesn't care. The safe route sees a different browser, ends the session for **both** of them, and emails Rahul:

```bash
curl -s -A "Vikram-PC" -b "sid=$RSID" $APP/vulnerable/me
curl -s -A "Vikram-PC" -b "sid=$RSID" $APP/me
curl -s -A "$R" -b rahul.jar $APP/me
```
→
```
{"email":"rahul@mail.com","cart":["Masala chai x2"],"session":"f69d5357"}
{"error":"Not signed in"}
{"error":"Not signed in"}
```
Server terminal:
```
🚨 Session f69d5357 of rahul@mail.com used from a different browser ("Vikram-PC"): revoked
📧 To: rahul@mail.com  "We signed you out because your session was used from a new browser. If this wasn't you, change your password."
```

🎭 **⑩ A smarter Vikram copies the User-Agent too.** Rahul logs in again, the id leaks again, and this time `/me` lets Vikram in (browser binding is only a signal). But changing the password needs the **password**:

```bash
curl -s -A "$R" -c rahul.jar $APP/login -H "$J" -d '{"email":"rahul@mail.com","password":"chai-and-code-42"}'
RSID=$(grep sid rahul.jar | awk '{print $7}')
curl -s -A "$R" -b "sid=$RSID" $APP/me
curl -s -A "$R" -b "sid=$RSID" $APP/account/password -H "$J" -d '{"currentPassword":"guess-123","newPassword":"vikram-owns-this-now"}'
```
→
```
{"message":"Logged in as rahul@mail.com","oldSession":null,"session":"a6baa358"}
{"email":"rahul@mail.com","cart":[],"session":"a6baa358","idleExpiresAt":"2026-11-06T02:24:24.646Z","absoluteExpiresAt":"2026-11-06T13:54:24.509Z"}
{"error":"Confirm this change with your current password"}
```

🔐 **⑪ Rahul changes his password.** **Every** session of his ends (2: this one, plus the fixated one left over from Part A), and his browser gets a new id. Vikram's copy is dead:

```bash
curl -s -A "$R" -b rahul.jar -c rahul.jar $APP/account/password -H "$J" -d '{"currentPassword":"chai-and-code-42","newPassword":"new-chai-pass-2026"}'
curl -s -A "$R" -b "sid=$RSID" $APP/me
curl -s -A "$R" -b rahul.jar $APP/me
```
→
```
{"message":"Password changed","sessionsEnded":2,"session":"9ca51ce5"}
{"error":"Not signed in"}
{"email":"rahul@mail.com","cart":[],"session":"9ca51ce5","idleExpiresAt":"2026-11-06T02:24:25.087Z","absoluteExpiresAt":"2026-11-06T13:54:24.945Z"}
```

👋 **⑫ Logout deletes the session on the server** and clears the cookie:

```bash
curl -s -i -A "$R" -b rahul.jar -X POST $APP/logout
curl -s -A "$R" -b rahul.jar $APP/me
```
→
```
Set-Cookie: sid=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; SameSite=Lax
{"message":"Logged out"}
{"error":"Not signed in"}
```

The idle (30 min) and absolute (12 h) timeouts are in the code too; `/me` shows when each one runs out. To see them fire quickly, set `IDLE_TIMEOUT_MS` to `10 * 1000` in `server.js` and wait 10 seconds.

> **Windows PowerShell users:** the single quotes in `-d '...'`, `$(…)` and `VAR=value node ...` work in Git Bash. In PowerShell, use Git Bash or Postman, or set the port with `$env:PORT=3050; node server.js`. Restart the server to reset users and sessions (Rahul's password goes back to `chai-and-code-42`).
