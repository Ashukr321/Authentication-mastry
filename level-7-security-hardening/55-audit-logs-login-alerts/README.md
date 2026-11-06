# 55. Audit Logs & Login Alerts

## Notes

### What are audit logs and login alerts?

An **audit log** is a permanent, append-only record of **security events**: who logged in, who failed, who changed a password, who looked at whose data. A **login alert** is the email (or SMS / push) you get when something unusual happens on **your** account: "New sign-in from a new device in Russia".

Every topic before this one tried to **stop** attackers. This one is about **noticing** them, because some will get through (a leaked password, a phished OTP, a stolen cookie).

> **One-line answer:** Write a structured entry for every security event (**who, what, to whom, when, from where, did it work**, never the password or token), make the log **append-only and tamper-evident**, use it to **detect** patterns, and **alert the account owner** about new devices, new countries and repeated failures with a one-click **"This wasn't me"** that revokes everything.

---

### Why it matters

| Without them… | What happens |
|---|---|
| No record of logins | After a breach you can't answer "which accounts? since when? from where?" |
| No alerts | The attacker uses Rahul's account for **weeks**; Rahul finds out from his bank statement |
| Passwords or tokens in logs | The log itself becomes the leak (anyone with log access can log in as anyone) |
| Logs the app can edit | An insider deletes the one line that shows what they did |
| Admins read logs freely | Nobody knows who looked at customer data |
| No user-visible activity page | Users can't spot "I never logged in from Chrome on Linux" themselves |

IBM's yearly breach report keeps finding the same thing: breaches take **months** to discover on average. Audit logs and alerts shorten that. Compliance rules (PCI DSS, SOC 2, ISO 27001, RBI guidelines for Indian banks) **require** security logging.

---

### Real-life example: the building's security guard 🏢

Priya's office building in Bengaluru has a guard with a register at the gate.

1. Everyone who enters writes **name, flat, time, purpose** → an **audit entry**
2. The guard never writes down **your door key's shape** → never log the password or token
3. The register is a **bound book with numbered pages**. Tearing a page out is obvious → **append-only, hash chain**
4. The guard calls Rahul: "Someone with your key just came in through the back gate at 2 a.m., was it you?" → **login alert**
5. Rahul says "No!" → the society **changes his lock and cancels all copies of his key** → **"This wasn't me": new password + every session revoked**
6. The society secretary can read the register, but **signs the register when she does** → reading the audit log is audited too

---

### The big picture

#### 📊 Diagrams

Open **[diagrams.html](diagrams.html)** in your browser (just double-click the file) to see:

- **Flow diagram**: what happens on every login attempt: audit, count failures, compare device and country, alert
- **Data flow**: Vikram logs in with Rahul's leaked password, Rahul gets the alert and clicks "This wasn't me"
- **Hash chain**: why deleting one audit entry is detected

In short: `security event → audit(entry without secrets) → hash-chained, append-only log → detection (new device, new country, 5 failures) → alert email to the owner → "This wasn't me" → new password + all sessions revoked + all devices forgotten`

---

### Step 1: What goes into an audit entry

One entry from our demo (real output):

```json
{
  "id": 9,
  "at": "2026-11-06T01:53:58.120Z",
  "event": "login.failure",
  "outcome": "failure",
  "actor": null,
  "target": "rahul@mail.com",
  "ip": "::1",
  "userAgent": "python-requests/2.32",
  "country": "RU",
  "requestId": "af33266b-d437-4437-8b47-14206aa6b10a",
  "details": { "reason": "wrong_password" },
  "hash": "93162b23cb34"
}
```

| Field | Why |
|---|---|
| `at` | ISO time in **UTC**. Servers in different time zones must agree |
| `event` | A fixed dotted name (`login.success`, `password.changed`) you can **filter and count** |
| `outcome` | `success` / `failure` / `denied`. Failures are often the interesting part |
| `actor` vs `target` | **Who did it** and **whose account it was about**. An admin resetting Rahul's MFA: actor = admin, target = Rahul |
| `ip`, `userAgent`, `country` | Where it came from. Needed for alerts and investigations |
| `requestId` | The same id is in the `X-Request-Id` response header and app logs, so support can match a user's complaint to the exact entry |
| `details` | Extra facts (`reason`, `newDevice`), passed through a **redact** filter |

What to log as events:

| Category | Events |
|---|---|
| Authentication | login success / failure, logout, MFA success / failure, passkey added, lockout (topic 16) |
| Account changes | password changed / reset, email changed, MFA turned off, recovery codes used |
| Sessions | session revoked, "log out everywhere", refresh-token reuse detected (topic 23) |
| Authorization | access **denied** (403), role changed (Level 4) |
| Admin actions | admin viewed / changed a user, impersonation, **audit log viewed** |
| Alerts | alert sent, "this wasn't me" clicked |

What **never** goes in:

```js
const SECRET_FIELDS = /pass|token|secret|otp|code|cookie|authorization/i;
const redact = (details) => Object.fromEntries(Object.entries(details).filter(([key]) => !SECRET_FIELDS.test(key)));
```

| ✅ Do | ❌ Don't |
|---|---|
| Log **that** the password was wrong | Log **the** wrong password (it's often the real one with a typo, or another site's password) |
| Log a short **hash** of an unknown email | Log the raw text typed into the email box (people paste passwords there) |
| Log `device: "a1b2c3d4"` (a hash prefix) | Log the session cookie, JWT, API key, OTP or reset token |
| Use **structured JSON** | Build log lines with string concatenation (log injection, see Tricky parts) |
| Store **UTC** time | Store "06/11/26 7:23 PM" |

---

### Step 2: Write the entry at the place the event happens

```js
if (!user || !crypto.timingSafeEqual(hash, user.passwordHash)) {
  if (!user) audit(req, "login.failure", "failure", { reason: "unknown_user", attemptedHash: sha256(email).slice(0, 12) });
  else {
    audit(req, "login.failure", "failure", { target: user.email, reason: "wrong_password" });
    maybeAlertFailedLogins(req, user.email);
  }
  return res.status(401).json({ error: "Wrong email or password" }); // the CLIENT still gets one vague message (topic 51)
}
```

The **response** stays vague so attackers learn nothing (topic 51). The **audit log** is detailed, because only your team reads it.

Two things that trip people up:

- **`req.ip` behind a load balancer** is the balancer's IP. Set `app.set("trust proxy", 1)` (the number of proxies you really have). Set it to `true` blindly and an attacker can fake any IP with `X-Forwarded-For`.
- **Generate your own request id.** Never use one the client sent; it would let the client write into your audit trail.

---

### Step 3: Make the log append-only and tamper-evident

An audit log is only useful if an attacker (or a dishonest insider) **can't quietly edit it**.

1. **In code**: the app has a function that **adds** entries and nothing that edits or deletes them.
2. **In the database**: the app's DB user gets `INSERT` and `SELECT` on the audit table, **no `UPDATE` / `DELETE`**.
3. **Ship it away**: copy entries to separate storage the app can't change (a SIEM like Splunk / Elastic / Datadog, S3 with Object Lock, a different cloud account).
4. **Hash chain**: each entry stores the hash of the previous one.

```js
const chainHash = (prevHash, entry) => sha256(prevHash + JSON.stringify(entry));
// entry #12 stores prevHash = hash of #11. Delete #11 and #12 no longer matches #10.
```

In our demo, a fake "insider" route deletes entry #11 (Vikram's successful login) behind the app's back, and verification catches it:

```
{"ok":false,"brokenAt":12,"problem":"the entry before this one is missing or was changed"}
```

A hash chain alone has a hole: someone who can rewrite **everything** can recompute every hash. So also copy the latest hash (`head`) somewhere the app can't write (a daily email, another system), or sign entries with a key the app server doesn't have.

**Who watches the watchers:** reading the audit log is itself an audited event (`audit.view`). It is full of personal data (emails, IPs, locations), so access is admins only, and a denied attempt is logged too.

---

### Step 4: Login alerts: tell the owner

The audit log helps **your team**. Alerts help **the user**, who is the only one who knows "that wasn't me".

**When to alert:**

| Trigger | How we detect it |
|---|---|
| **New device** | A random `did` cookie per browser (1 year, `HttpOnly`). Not in the user's known-devices list → new |
| **New country** | GeoIP lookup of the IP (in the demo: an `X-Demo-Country` header) not seen before for this user |
| **Many failed logins** | Count `login.failure` for this account in the last 15 min **from the audit log**. At 5, alert once per hour |
| **Account changes** | Password, email, phone or MFA changed: **always** alert (send the email-change alert to the **old** address) |

**When not to alert:** the very first login (nothing to compare with), and logins from known devices. Too many alerts and users stop reading them ("alert fatigue").

**What the email says:**

```
Subject: New sign-in to your ChaiPay account
Signed in from a new device and a new country (RU).
When: 2026-11-06T01:53:58.302Z  Device: python-requests/2.32  Location: RU (IP ::1)
If this was you, you can ignore this email.
Wasn't you? Secure your account: http://localhost:3055/security/not-me?token=M6FVaMJo…
(ChaiPay will never ask for your password or OTP by email or phone.)
```

| ✅ Do | ❌ Don't |
|---|---|
| Send to the **account owner** (the verified email / phone) | Send to an address the attacker can change just before logging in |
| Say **what, when, device, rough location** | Include balances, full addresses or other personal data |
| **One** clear action: "This wasn't me" | A "click here to log in" link: it trains users to fall for phishing |
| Say "we'll never ask for your password" | Ask them to reply with anything |
| Rate-limit the "failed logins" alert | Email on every single wrong password |

---

### Step 5: "This wasn't me": one click to kick the attacker out

```
GET  /security/not-me?token=…   → only shows a page with a form (changes nothing)
POST /security/not-me           → { token, newPassword }
```

**Why is GET harmless?** Email scanners (Outlook Safe Links, Gmail), antivirus and link previews **open links automatically**. If GET revoked sessions, a scanner would do it the moment the email arrived. Same rule as magic links (topic 42).

What the POST does, in one go:

1. Checks the token (random, stored as `sha256`, expires in 7 days, **single-use**: all of this user's links are used up)
2. Sets the **new password** (the attacker knows the old one)
3. **Revokes every session**, the attacker's included (`sessionsRevoked: 3`)
4. **Forgets every device**, so the next login from anywhere alerts again
5. Writes `password.changed` + `account.secured` to the audit log
6. Sends "Your password was changed" **without** any action link

From our run: Vikram's session gets `{"error":"Not signed in"}` right after, and the old password stops working.

In a bigger app also: revoke refresh tokens and API tokens (topics 23, 48), ask the user to review MFA and recovery settings (topic 45), and flag the account for your security team.

---

### Step 6: Show users their own activity

```
GET /me/activity →
{ "devices": [ { "label": "Chrome on Windows", "country": "IN", "thisDevice": false },
               { "label": "python-requests/2.32", "country": "RU", "thisDevice": true } ],
  "activity": [ { "event": "login.success", "country": "RU", "device": "python-requests/2.32", … }, … ] }
```

Google ("Security activity"), GitHub ("Security log") and every bank have this page. It's built **from the audit log**: same data, filtered to the user's own account and to events they understand. Combine it with the "log out this device" buttons from topic 26.

---

### 🤔 Tricky parts

**1. Log injection.** If you write `"login failed for " + email` as plain text, an email like `x\n2026-11-06 login.success admin` creates a fake second line. Writing **JSON** fixes it: `JSON.stringify` turns the newline into `\n`. Also **cap lengths** (a 5 MB `User-Agent` shouldn't become a 5 MB log line).

**2. Audit log ≠ debug log.** Debug logs are noisy, rotated after days and change with every deploy. The audit log has a **fixed format**, is **kept for a fixed period** (often 1 year or more, as your compliance rules say) and is **never** edited. Keep them separate.

**3. Logs are personal data.** IPs and emails are personal data under GDPR and India's DPDP Act. Keep them only as long as needed, restrict who can read them, and delete or anonymise after the retention period.

**4. IPs lie a little.** Mobile networks and VPNs change IP and "country" all the time. Use new **device** as the main signal and new **country** as a second one. Don't lock accounts just because the country changed.

**5. The device cookie is not proof.** An attacker can delete it (looks like a new device: alert, fine) or steal it along with the session (looks known). Device recognition only decides **whether to alert or ask for MFA** (topic 45); it never replaces a login.

**6. Alerts are a phishing template.** Attackers copy your alert emails. Keep links on your own domain, never ask for passwords, and teach users to open the app themselves instead of clicking when unsure.

**7. Failure in the logger.** If writing the audit entry fails, decide on purpose: for sensitive actions (admin changes, money transfers) **fail the action**; for logins, usually log the error and continue so an outage of the log store doesn't lock everyone out.

---

### Common beginner mistakes

1. **Logging the password, token or OTP.**
   Even "just in debug mode". Redact by field name and review log output in code review.

2. **Logging only failures.**
   The attacker's **successful** login with a stolen password is the most important line.

3. **No `actor` / `target` split.**
   "rahul@mail.com: password reset" doesn't say whether Rahul did it or an admin did.

4. **Audit log in the same table the app can `UPDATE` / `DELETE`.**
   Use insert-only permissions and ship a copy elsewhere.

5. **Wrong IP behind a proxy.**
   Every entry shows the load balancer's IP, or attackers fake theirs via `X-Forwarded-For`.

6. **Alerting on everything.**
   Users learn to ignore your emails. Alert on new device / new country / account changes / failure bursts.

7. **A "This wasn't me" link that acts on GET.**
   Email scanners click it. Show a page, act on POST.

8. **"This wasn't me" that only logs out one session.**
   Revoke everything and force a new password; the attacker knows the old one.

9. **Sending the email-change alert to the new address.**
   The attacker owns the new address. Alert the old one.

10. **Nobody ever reads the logs.**
    Set up automatic alerts on patterns (failure spikes, admin actions at 3 a.m.), not just storage.

---

### Interview questions

1. **What would you put in an authentication audit log entry?**
   Timestamp (UTC), event name, outcome, actor, target, IP, user agent, location, request id, and non-secret details like the failure reason. Never passwords, tokens, OTPs or session ids.

2. **How do you make audit logs tamper-proof?**
   Append-only in code, insert-only DB permissions, a copy shipped to separate write-once storage (SIEM, S3 Object Lock), and a hash chain or signatures so any edit or deletion breaks verification. Anchor the latest hash outside the system.

3. **How do you detect a suspicious login?**
   Compare against the user's history: new device (device cookie), new country / impossible travel (GeoIP), unusual time, many failures before success, a known bad IP. Then alert, require MFA (step-up, topic 45), or block.

4. **What should a new-sign-in email contain?**
   What happened, when, device and approximate location, "ignore if this was you", and one link to secure the account. No login link, no sensitive data, and a note that you never ask for the password.

5. **What does "This wasn't me" do?**
   Forces a new password, revokes all sessions and refresh / API tokens, forgets remembered devices, records it in the audit log and notifies the user. The link is single-use and only acts on POST.

6. **What is log injection and how do you prevent it?**
   User input containing newlines or control characters creates fake log lines or breaks log parsers. Write structured JSON (which escapes them) and cap field lengths.

7. **Why is an audit log different from application logs?**
   Different purpose (accountability vs debugging), fixed schema, longer retention, append-only, restricted access, and access to it is itself audited.

8. **How do you count failed logins for alerting?**
   Query recent `login.failure` events for the account (from the audit store or a counter), alert once above a threshold, and rate-limit the alert. For credential stuffing (topic 52) also look at failures **across** accounts from the same IP or ASN.

---

### Quick recap

- Audit **every** security event: who, what, to whom, when, from where, outcome. **No secrets**
- **Structured JSON**, UTC times, capped lengths: no log injection
- **Append-only**, insert-only DB user, shipped elsewhere, **hash chain**; reading it is audited
- **Alert the owner** on new device, new country, failure bursts and account changes; not on every login
- Alert email: facts + **one** "This wasn't me" link; GET shows a page, **POST acts**
- "This wasn't me" = new password + **revoke all sessions** + forget devices + audit + confirmation email
- Show users their **own activity** page from the same log
- Next: OWASP cheat sheets, the checklist for everything in Level 7 (topic 56)

## Code

A small **Express** app for **ChaiPay**, a wallet. Every security event goes through one `audit()` function into a **hash-chained, append-only** log. Logins compare the browser's device cookie and country with what Rahul used before and **email him** (printed in the terminal) on anything new, or after 5 wrong passwords. The email's **"This wasn't me"** link sets a new password and throws everyone out. Priya, an admin, can search and verify the log; a demo-only route plays an insider deleting an entry.

Test accounts: **rahul@mail.com** / **chai-and-code-42** (user), **priya@mail.com** / **admin-priya-77** (admin). Everything is in memory, so a restart resets it.

📄 **Full code: [server.js](server.js)**. Open it and read the comments, which follow the same steps as the notes above.

Install Express once (from this folder), then start the server:

```bash
npm install
```

```bash
node server.js
```

> Port 3000 busy? Run it on another port: `PORT=3055 node server.js` (Git Bash). The outputs below were recorded on port 3055.

### Try it (Git Bash)

```bash
APP=http://localhost:3055
```

We use `-A` to set a User-Agent (the "device" name) and `X-Demo-Country` to pretend to be somewhere else. Each cookie jar (`-c`/`-b`) is one browser.

💻 **① Rahul logs in from his laptop**, twice. The first login ever has nothing to compare with, the second is a known device: no alerts.

```bash
curl -s -c laptop.jar -b laptop.jar $APP/login -H "Content-Type: application/json" -A "Chrome on Windows" -d '{"email":"rahul@mail.com","password":"chai-and-code-42"}'
curl -s -c laptop.jar -b laptop.jar $APP/login -H "Content-Type: application/json" -A "Chrome on Windows" -d '{"email":"rahul@mail.com","password":"chai-and-code-42"}'
```
→ `{"message":"Logged in as rahul@mail.com"}` twice. Server terminal:
```
📝 audit #1 login.success success target=rahul@mail.com
📝 audit #2 login.success success target=rahul@mail.com
```

😈 **② Vikram guesses Rahul's password** from a script in Russia, 6 times:

```bash
for i in 1 2 3 4 5 6; do curl -s $APP/login -H "Content-Type: application/json" -A "python-requests/2.32" -H "X-Demo-Country: RU" -d '{"email":"rahul@mail.com","password":"password123"}'; echo; done
```
→ `{"error":"Wrong email or password"}` six times. On the 5th, Rahul gets an alert. The 6th is logged but **not** emailed again (one per hour):
```
📝 audit #7 login.failure failure target=rahul@mail.com
📧 To: rahul@mail.com
   Subject: Several failed sign-in attempts on your ChaiPay account
   5 wrong passwords in the last 15 minutes. Latest from IP ::1 (RU).
   Your account is safe as long as nobody knows your password. Turning on 2FA makes it safer.
   Wasn't you? Secure your account: http://localhost:3055/security/not-me?token=TudYZnFgXDb4QfLVYr9RpZx_0AOuax1cR3KMekQ2UlA
   (ChaiPay will never ask for your password or OTP by email or phone.)
📝 audit #8 alert.sent success target=rahul@mail.com
📝 audit #9 login.failure failure target=rahul@mail.com
```

🙈 **③ Someone types a password into the email box.** The client gets the same vague error; the log keeps only a short hash, never the text:

```bash
curl -s -i $APP/login -H "Content-Type: application/json" -d '{"email":"chai-and-code-42","password":"x"}' | grep -i "x-request-id\|error"
```
→
```
X-Request-Id: 83848568-2d90-41fc-b641-7a18c759d1c9
{"error":"Wrong email or password"}
```

🔓 **④ Vikram has Rahul's real password** (leaked from another site, topic 52). Login works, and Rahul is told at once:

```bash
curl -s -c vikram.jar -b vikram.jar $APP/login -H "Content-Type: application/json" -A "python-requests/2.32" -H "X-Demo-Country: RU" -d '{"email":"rahul@mail.com","password":"chai-and-code-42"}'
```
→ `{"message":"Logged in as rahul@mail.com"}`, and:
```
📝 audit #11 login.success success target=rahul@mail.com
📧 To: rahul@mail.com
   Subject: New sign-in to your ChaiPay account
   Signed in from a new device and a new country (RU).
   When: 2026-11-06T01:53:58.302Z  Device: python-requests/2.32  Location: RU (IP ::1)
   If this was you, you can ignore this email.
   Wasn't you? Secure your account: http://localhost:3055/security/not-me?token=M6FVaMJoZxeHm2yAUsc82jhZjbkdwQtO5Q_ALtmfxzg
   (ChaiPay will never ask for your password or OTP by email or phone.)
📝 audit #12 alert.sent success target=rahul@mail.com
```

📋 **⑤ The activity page** (what Rahul would see; here Vikram's session reads it):

```bash
curl -s -b vikram.jar $APP/me/activity
```
→ (shortened)
```json
{"email":"rahul@mail.com",
 "devices":[{"label":"Chrome on Windows","country":"IN","firstSeen":"2026-11-06T01:53:57.464Z","lastSeen":"2026-11-06T01:53:57.566Z","thisDevice":false},
            {"label":"python-requests/2.32","country":"RU","firstSeen":"2026-11-06T01:53:58.302Z","lastSeen":"2026-11-06T01:53:58.302Z","thisDevice":true}],
 "activity":[{"at":"2026-11-06T01:53:58.303Z","event":"alert.sent","outcome":"success","ip":"::1","country":"RU","device":"python-requests/2.32"},
             {"at":"2026-11-06T01:53:58.302Z","event":"login.success","outcome":"success","ip":"::1","country":"RU","device":"python-requests/2.32"},
             {"at":"2026-11-06T01:53:58.120Z","event":"login.failure","outcome":"failure","ip":"::1","country":"RU","device":"python-requests/2.32"}, …]}
```

🚫 **⑥ Rahul isn't an admin**, so the audit log is off-limits. The attempt is logged:

```bash
curl -s -b laptop.jar $APP/admin/audit
```
→ `{"error":"Admins only"}` and `📝 audit #13 audit.view denied actor=rahul@mail.com`

🔎 **⑦ Priya (admin) searches the log.** Note the unknown-user entry has only `attemptedHash`, and the `requestId` matches the header from step ③:

```bash
curl -s -c priya.jar -b priya.jar $APP/login -H "Content-Type: application/json" -A "Firefox on Mac" -d '{"email":"priya@mail.com","password":"admin-priya-77"}'
curl -s -b priya.jar "$APP/admin/audit?event=login.failure&limit=2"
```
→
```json
{"count":2,"entries":[
 {"id":10,"at":"2026-11-06T01:53:58.213Z","event":"login.failure","outcome":"failure","actor":null,"target":null,"ip":"::1","userAgent":"curl/8.23.0","country":"IN","requestId":"83848568-2d90-41fc-b641-7a18c759d1c9","details":{"reason":"unknown_user","attemptedHash":"3e1ca6c85acd"},"hash":"5d553508a447"},
 {"id":9,"at":"2026-11-06T01:53:58.120Z","event":"login.failure","outcome":"failure","actor":null,"target":"rahul@mail.com","ip":"::1","userAgent":"python-requests/2.32","country":"RU","requestId":"af33266b-d437-4437-8b47-14206aa6b10a","details":{"reason":"wrong_password"},"hash":"93162b23cb34"}]}
```
Her search is audited too: `📝 audit #15 audit.view success actor=priya@mail.com`. Other filters: `?user=rahul@mail.com`, `?outcome=denied`.

🛑 **⑧ Rahul clicks "This wasn't me".** Copy the token from the **new sign-in** email in step ④:

```bash
TOKEN=PASTE_THE_TOKEN_FROM_THE_EMAIL
curl -s "$APP/security/not-me?token=$TOKEN" | head -3
```
→ only a page with a form (an email scanner opening this link changes nothing):
```html
<!doctype html><meta charset="utf-8"><title>Secure your account</title>
<h1>Secure your ChaiPay account</h1>
<p>We'll sign out <b>every</b> device, forget all remembered devices and set your new password.</p>
```

The form POSTs the token and a new password. A too-short password is refused without using up the link:

```bash
curl -s -X POST $APP/security/not-me -H "Content-Type: application/json" -d "{\"token\":\"$TOKEN\",\"newPassword\":\"short\"}"
curl -s -X POST $APP/security/not-me -H "Content-Type: application/json" -d "{\"token\":\"$TOKEN\",\"newPassword\":\"masala-dosa-2026!\"}"
curl -s -X POST $APP/security/not-me -H "Content-Type: application/json" -d "{\"token\":\"$TOKEN\",\"newPassword\":\"masala-dosa-2026!\"}"
```
→
```
{"error":"New password must be 12 to 128 characters"}
{"message":"Account secured","sessionsRevoked":3,"devicesForgotten":2}
{"error":"This link is invalid or has expired"}
```
Server terminal:
```
📝 audit #18 password.changed success target=rahul@mail.com
📝 audit #19 account.secured success target=rahul@mail.com
📧 To: rahul@mail.com
   Subject: Your ChaiPay password was changed
   All 3 sessions were signed out. If you didn't do this, contact support.
```

👋 **⑨ Vikram is out**, and the leaked password is useless:

```bash
curl -s -b vikram.jar $APP/me/activity
curl -s $APP/login -H "Content-Type: application/json" -d '{"email":"rahul@mail.com","password":"chai-and-code-42"}'
```
→ `{"error":"Not signed in"}` and `{"error":"Wrong email or password"}`

When Rahul logs in again with his new password, he gets one "new device" alert even on his own laptop. That's on purpose: all devices were forgotten, so **every** device has to be seen fresh again.

🔗 **⑩ Verify the hash chain, then play the insider.** Delete entry #11 (Vikram's successful login) behind the app's back:

```bash
curl -s -b priya.jar $APP/admin/audit/verify
curl -s $APP/demo/tamper -H "Content-Type: application/json" -d '{"id":11}'
curl -s -b priya.jar $APP/admin/audit/verify
```
→
```
{"ok":true,"entries":23,"head":"3ff3449098b003757cb585215622ad4f94f092d9aa154e6c569e0588d114deca"}
{"message":"Deleted audit entry #11 (login.success) without going through audit()"}
{"ok":false,"brokenAt":12,"problem":"the entry before this one is missing or was changed"}
```

> **Windows PowerShell users:** the single quotes in `-d '...'`, the `for` loop and `VAR=value node ...` work in Git Bash. In PowerShell, use Git Bash or Postman, or set the port with `$env:PORT=3055; node server.js`. Restart the server to clear the log and the devices.
