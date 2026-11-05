# 14. Change Password

## Notes

### What is "change password"?

Rahul is **logged in** and wants a new password, maybe because he used the same one on another site, or he thinks someone saw him type it. He opens **Settings → Security → Change password**.

It looks like a simple "update one column" endpoint, but it isn't. The request comes from a **logged-in session**, and sessions can be **stolen** (an XSS bug, a shared computer, an open laptop in a café). If changing the password only needs the session, then whoever has the session can **lock the real owner out**.

> **One-line answer:** ask for the **current password** again, check the new one with the signup rules, save the new **hash**, **log out every other device**, give this device a **new session ID**, and send a "your password was changed" email.

How it differs from topic 13:

| | Forgot / reset password (13) | Change password (14) |
|---|---|---|
| Who uses it | Someone who **can't** log in | Someone who **is** logged in |
| How they prove it's them | A link sent to their **email** | Their **current password** |
| Other devices | Log out **all** of them | Log out all **others**, keep this one |

---

### Why does it matter?

| If you get it wrong… | What happens |
|---|---|
| No "current password" check | Priya steals Rahul's session cookie, changes the password, and **Rahul is locked out of his own account** |
| No limit on wrong current passwords | A stolen session becomes a free password-guessing machine |
| Other devices stay logged in | Whoever knew the old password **stays inside** |
| Same session ID kept | If the old ID was copied, the copy still works |
| No notice email | If an attacker does change it, the owner never finds out |
| New password not validated | Users switch to `password1`, or to the same password again |

---

### Real-life example: changing your ATM PIN 🏧

Rahul wants a new ATM PIN for his ₹ savings account.

1. He's already at the ATM with his card → he's **logged in** (has a session)
2. The machine still asks for his **old PIN** first → **re-authentication**: holding the card isn't enough, someone could have picked it up
3. Three wrong old PINs → the card is **blocked** → a **limit on wrong tries**
4. The new PIN can't be `0000` or `1234`, and can't be the old one → **validate the new password**
5. The bank sends an SMS: "Your PIN was changed" → the **notice email**
6. The old PIN stops working **everywhere** at once → **other devices logged out**

---

### The flow, step by step

#### 📊 Diagrams

Open **[diagrams.html](diagrams.html)** in your browser (just double-click the file) to see:

- **Flow diagram**: every check the server does on `POST /change-password`
- **Data flow**: Rahul changes his password on the laptop, and Priya's stolen cookie and the phone get logged out
- **Stolen session**: why asking for the current password stops an attacker

In short: `logged in → POST { currentPassword, newPassword } → too many wrong tries? → check current password → check new password → save new hash → log out other devices → new session ID here → notice email → 200`

#### What happens to each session? 🔍

| Session | Before | After the change |
|---|---|---|
| This laptop (the one that changed it) | `sid=3016…` | Still logged in, but with a **new** `sid=d698…` |
| A copy of the laptop's old cookie | Works | **Dead**: the old ID was deleted |
| Rahul's phone | Logged in | **Logged out**: must log in with the new password |
| Old password | Works | **Rejected** at login |

---

### Step 1: Only for logged-in users, only by POST

```js
app.post("/change-password", requireAuth, async (req, res) => { ... });
```

- `requireAuth` (topic 09): no session → `401`.
- **POST** with a `SameSite=Lax` cookie and an **Origin check** (topic 11), so another site can't submit it for the user (CSRF). The current-password check also blocks CSRF on its own, because the attacker's page doesn't know the password.

---

### Step 2: Ask for the current password (re-authentication)

```js
if (!(await verifyPassword(currentPassword, user.passwordHash))) {
  return res.status(403).json({ error: "Current password is incorrect" });
}
```

This is the most important step. Having a session proves "someone logged in as Rahul **at some point**". Typing the current password proves "Rahul is here **right now**".

| ✅ Do | ❌ Don't |
|---|---|
| Ask for the current password every time | Trust the session alone |
| Reply `403` for a wrong current password | Reply `401`: the frontend will think the user was logged out |
| Use the same slow hash check as login (topic 07) | Compare strings with `===` |

💡 Apps with MFA (Level 6) ask for the **second factor** here too. Apps with only social login (Google, Level 5) have no password to ask for, so they re-check the login with Google, or send a code by email.

---

### Step 3: Limit wrong current passwords

A stolen session + no limit = the attacker can try passwords one after another without ever hitting the login page's lockout (topic 16).

```js
if (user.wrongCurrentCount >= 5) user.changeLockedUntil = Date.now() + 15 * 60 * 1000;
```

Our demo allows **5 wrong tries**, then answers `429 Too Many Requests` for 15 minutes. Real apps often also **log the session out** or send a "suspicious activity" email at that point.

---

### Step 4: Check the new password

Use the **same rules as signup** (topic 06), plus two more:

| Rule | Why |
|---|---|
| 8–128 characters | Long enough to be strong, short enough that hashing can't be abused |
| Not a common / leaked password | Block `password1`, `12345678` (or check Have I Been Pwned) |
| Not the same as the email | Easy to guess |
| **Not the same as the current password** | Otherwise "change" changes nothing |

❌ Don't add "must contain a symbol and an uppercase letter" rules, or force a change every 90 days. NIST says those make passwords **weaker** (people pick `Password1!` and then `Password2!`).

Check the new password **after** the current one. Otherwise an attacker learns things about the account without knowing the password.

---

### Step 5: Save the new hash

```js
user.passwordHash = await hashPassword(newPassword); // a new salt every time (topic 04)
user.passwordChangedAt = new Date().toISOString();
```

`passwordChangedAt` is useful later: JWT apps (Level 3) reject any token issued **before** it, and you can show "Password last changed 3 days ago" on the security page.

---

### Step 6: Log out every OTHER device

```js
for (const [key, s] of sessions) if (s.userId === user.id && key !== req.sessionKey) sessions.delete(key);
```

People change passwords **because** they think someone else knows the old one. If that someone is already logged in, changing the password without logging them out does **nothing**.

Many apps let the user choose ("Log out of other devices? ✅"). Making it the default is the safe choice.

Also delete any open **password reset links** (topic 13) and **remember-me** tokens (topic 15): they were created for the old password.

---

### Step 7: New session ID for this device

```js
sessions.delete(req.sessionKey);
startSession(res, user, device); // new random ID, new Set-Cookie
```

The user stays logged in on this device, but the **old ID** is gone. If it had been copied, the copy is now useless. Rule of thumb: **whenever the user's security level changes** (login, password change, MFA turned on), **issue a new session ID**.

---

### Step 8: Send a "your password was changed" email

```
Subject: Your password was changed
Changed at 2026-11-04 17:42. If this wasn't you, reset your password: myapp.com/forgot-password
```

If it **was** an attacker, this email is how the owner finds out, and the link to topic 13's reset flow is how they get back in. Never put the new password in the email.

---

### 🤔 Tricky parts

**1. Why ask for the current password if the user is already logged in?**
A session is a "ticket" that can be stolen or left behind. The password is something only the owner knows. High-risk actions (change password, change email, delete account, add a payout bank account) should all ask again. This is called **step-up authentication** or **sudo mode**: GitHub, for example, asks for your password again before sensitive settings.

**2. Changing the email is just as dangerous.**
An attacker who changes the email can then use "forgot password" to take the account. Change email = current password + verify the **new** email + notify the **old** email (topic 12).

**3. The order of the steps matters.**
Lockout check → current password → new password rules → save → log out others → rotate session → email. Checking the current password **last** would let a session thief probe the password rules, and saving before logging others out leaves a gap.

---

### Common beginner mistakes

1. **Not asking for the current password.**
   A stolen session = a stolen account.

2. **Unlimited wrong current-password tries.**
   A stolen session becomes a password-guessing tool. Limit and lock.

3. **Returning `401` for a wrong current password.**
   Many frontends treat `401` as "logged out" and redirect to login. Use `403` or `400`.

4. **Different rules than signup.**
   Reuse the same validation function, so the rules never drift apart.

5. **Allowing the same password again.**
   Check the new password against the current hash.

6. **Leaving other devices logged in.**
   The attacker who knew the old password stays inside.

7. **Keeping the same session ID.**
   Issue a new one after a password change.

8. **No notice email.**
   The owner never learns about an attacker's change.

9. **Logging the request body.**
   Both passwords end up in plain text in your logs.

10. **Putting it on a GET or without CSRF protection.**
    POST + SameSite + Origin check (+ the current password).

---

### Interview questions

1. **Why require the current password when the user is already logged in?**
   To prove the owner is present right now. A session can be stolen or left open, and without this check whoever has it can lock the owner out.

2. **What should happen to other sessions after a password change?**
   Revoke them (all except the current one, which gets a new session ID). With JWTs, reject tokens issued before `passwordChangedAt` and revoke refresh tokens.

3. **Why rotate the current session ID?**
   The old ID may have been copied. Issuing a new one after any change in security level makes old copies useless (the same idea as preventing session fixation at login).

4. **How is change password different from reset password?**
   Change: logged in, proves identity with the current password, keeps this device. Reset: not logged in, proves identity through email, logs out every device.

5. **What status code for a wrong current password?**
   `403` (or `400`), not `401`, because the user is still authenticated. `401` usually makes the frontend log the user out.

6. **How do you stop a stolen session from brute-forcing the current password?**
   Count wrong attempts per user and lock changes for a while (`429`), maybe also end the session and email the user.

7. **What password rules should the new password follow?**
   The same as signup (NIST): length 8+ (allow 64+), block common/breached passwords, not equal to the old one or the email, no forced complexity, no forced expiry.

8. **What is step-up authentication?**
   Asking a logged-in user to prove themselves again (password, MFA) before a sensitive action, like changing the password or email, deleting the account, or adding a payment method.

---

### Quick recap

- Change password is for **logged-in** users: `requireAuth` + **POST** + Origin check
- Always ask for the **current password** (re-authentication / step-up)
- **Limit wrong tries** → `429` for a while
- New password: **same rules as signup**, not common, not the email, **not the same as before**
- Save a **new hash** and `passwordChangedAt`
- **Log out every other device**, delete reset links and remember-me tokens
- **New session ID** for this device
- Send a **"your password was changed"** email with a link to reset

## Code

A small **Express** API (plus Node's built-in `crypto` for hashing and session IDs): sign up, log in on a "laptop" and a "phone", then change the password on the laptop. Watch the phone and a stolen copy of the laptop's cookie get logged out, while the laptop stays in with a new session ID. Users and sessions are kept in memory, so they disappear when you restart.

📄 **Full code: [server.js](server.js)**. Open it and read the comments, which follow the same steps as the notes above.

Install Express once (from this folder), then start the server:

```bash
npm install
```

```bash
node server.js
```

> Port 3000 busy? Run it on another port: `PORT=3014 node server.js` (Git Bash), then use that port in the commands below.

### Try it

`-c file.txt` saves the cookie a "device" gets, `-b file.txt` sends it back (like a browser), and `-A "..."` sets the device name.

✅ **Sign up, then log in on a laptop and a phone:**

```bash
curl -X POST http://localhost:3000/signup -H "Content-Type: application/json" -d '{"email":"rahul@mail.com","password":"old password 123"}'
```

```bash
curl -c laptop.txt -A "Laptop Chrome" -X POST http://localhost:3000/login -H "Content-Type: application/json" -d '{"email":"rahul@mail.com","password":"old password 123"}'
```

```bash
curl -c phone.txt -A "Phone Safari" -X POST http://localhost:3000/login -H "Content-Type: application/json" -d '{"email":"rahul@mail.com","password":"old password 123"}'
```

🕵️ **Pretend an attacker copied the laptop's cookie:**

```bash
cp laptop.txt stolen.txt
```

❌ **Not logged in:**

```bash
curl -i -X POST http://localhost:3000/change-password -H "Content-Type: application/json" -d '{"currentPassword":"x","newPassword":"y"}'
```
→ `401 Unauthorized` with `{"error":"Not logged in"}`

❌ **Wrong current password** (what a session thief would try):

```bash
curl -i -b laptop.txt -X POST http://localhost:3000/change-password -H "Content-Type: application/json" -d '{"currentPassword":"guess 1","newPassword":"new password 456"}'
```
→ `403 Forbidden` with `{"error":"Current password is incorrect"}`

❌ **A common password, or the same password again:**

```bash
curl -i -b laptop.txt -X POST http://localhost:3000/change-password -H "Content-Type: application/json" -d '{"currentPassword":"old password 123","newPassword":"password1"}'
```
→ `400 Bad Request` with `{"error":"This password is too common, please choose another"}`

```bash
curl -i -b laptop.txt -X POST http://localhost:3000/change-password -H "Content-Type: application/json" -d '{"currentPassword":"old password 123","newPassword":"old password 123"}'
```
→ `400 Bad Request` with `{"error":"The new password must be different from the current one"}`

🛡️ **A request from another site is blocked:**

```bash
curl -i -b laptop.txt -H "Origin: http://evil.com" -X POST http://localhost:3000/change-password -H "Content-Type: application/json" -d '{"currentPassword":"old password 123","newPassword":"new password 456"}'
```
→ `403 Forbidden` with `{"error":"Request from another site was blocked"}`

✅ **Change it:** `-c laptop.txt` saves the new session cookie.

```bash
curl -i -b laptop.txt -c laptop.txt -X POST http://localhost:3000/change-password -H "Content-Type: application/json" -d '{"currentPassword":"old password 123","newPassword":"new password 456"}'
```
→ `200 OK` with a **new** cookie and
```
Set-Cookie: sid=d698804d...1cb76; Max-Age=28800; Path=/; Expires=...; HttpOnly; SameSite=Lax
{"message":"Password changed","otherDevicesLoggedOut":1}
```
The terminal prints the "Your password was changed" email.

✅ **The laptop is still logged in** (with its new cookie):

```bash
curl -b laptop.txt http://localhost:3000/me
```
→ `{"id":"...","email":"rahul@mail.com","device":"Laptop Chrome"}`

🚪 **The stolen copy and the phone are logged out:**

```bash
curl -i -b stolen.txt http://localhost:3000/me
```

```bash
curl -i -b phone.txt http://localhost:3000/me
```
→ both `401 Unauthorized` with `{"error":"Not logged in"}`. `curl -b laptop.txt http://localhost:3000/sessions` now shows only `[{"device":"Laptop Chrome","current":true}]`.

❌ **The old password is dead, the new one works:**

```bash
curl -X POST http://localhost:3000/login -H "Content-Type: application/json" -d '{"email":"rahul@mail.com","password":"old password 123"}'
```
→ `{"error":"Invalid email or password"}`

```bash
curl -c phone.txt -A "Phone Safari" -X POST http://localhost:3000/login -H "Content-Type: application/json" -d '{"email":"rahul@mail.com","password":"new password 456"}'
```
→ `{"message":"Logged in","email":"rahul@mail.com","device":"Phone Safari"}`

🔒 **Too many wrong current passwords:** run this 6 times.

```bash
curl -s -o /dev/null -w "%{http_code} " -b phone.txt -X POST http://localhost:3000/change-password -H "Content-Type: application/json" -d '{"currentPassword":"guess","newPassword":"another password 789"}'
```
→ `403 403 403 403 403 429`. Now even the **right** current password gets `429` with `{"error":"Too many wrong attempts. Try again in 15 minutes, or use Forgot password."}`

> **Windows PowerShell users:** the single quotes in the `-d '...'` part and `PORT=3014 node ...` work in Git Bash. In PowerShell, use Git Bash, Postman, or set the variable with `$env:PORT=3014; node server.js`.
