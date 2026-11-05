# 17. Account Deletion / Deactivation

## Notes

### What are "deactivate" and "delete"?

Rahul wants to leave your app. There are two very different ways to leave:

- **Deactivate** = "take a break". The account is **switched off**: nobody can log in to it or see it, but **all the data stays**. Rahul can come back any time.
- **Delete** = "I'm leaving for good". The account and Rahul's **personal data are erased**. Usually after a short **grace period** (for example 30 days), so a mistake (or an attacker) can still be undone.

> **One-line answer:** deactivate switches the account off but keeps the data; delete marks it for deletion, logs out every device, waits a grace period, then a background job really erases the personal data, and both actions need the password again.

---

### Why does it matter?

"Delete my account" looks like a simple button, but it touches security, the law and every table in your database.

| If you get it wrong… | What happens |
|---|---|
| No password check before deleting | Someone with a stolen session cookie (or a laptop left open) wipes the account |
| Old sessions keep working | A deactivated user (or the attacker) is **still logged in** on another device |
| Deleted at once, no grace period | One mis-click or one attacker = data gone forever, support can't help |
| "Delete" only sets a flag, forever | You're still storing personal data the user asked you to erase (illegal under GDPR / India's DPDP Act) |
| Email freed at once | Someone else signs up with Rahul's email while he can still cancel |
| Hard delete breaks other tables | Orders, invoices and comments point to a user that doesn't exist → crashes |

---

### Real-life example: a gym membership 🏋️

Priya has a gym membership.

1. **Freeze the membership** (deactivate): she's travelling for 2 months. Her card stops working at the door, but her locker, history and plan are **kept**. When she comes back, she just shows her card again → **log in to reactivate**.
2. **Cancel the membership** (delete): the desk asks for her **ID again** (→ re-enter the password) and makes her **sign a form** (→ type `DELETE`).
3. They say: "Your membership ends in **30 days**. Change your mind before then and we'll undo it" (→ **grace period**).
4. Her card stops working **today** (→ **all sessions logged out**).
5. After 30 days, they **shred her form and photo** (→ **erase personal data**), but the accountant keeps the bill for ₹2,000 for tax reasons, with "former member" instead of her name (→ **anonymize what you must keep**).

---

### The flow, step by step

#### 📊 Diagrams

Open **[diagrams.html](diagrams.html)** in your browser (just double-click the file) to see:

- **Flow diagram**: every check the server does when Rahul presses "Delete my account"
- **Data flow**: deactivate → come back → delete → grace period → erased
- **Account states**: active, deactivated, pending deletion and erased, and how to move between them

In short: `logged in → re-enter password (+ type DELETE) → status = pending_deletion → log out every device → email → wait 30 days (log in = cancel) → purge job erases personal data → keep only anonymous records`

#### Deactivate vs delete at a glance 🔍

| | Deactivate | Delete |
|---|---|---|
| What the user means | "Take a break" | "Erase me" |
| Data | **Kept** | **Erased** after the grace period |
| Can log in? | No… logging in **turns it back on** | Only during the grace period, and that **cancels** the deletion |
| Profile visible to others? | No | No |
| Email address | Still taken | Taken during the grace period, **free** after erasing |
| How long | Until the user comes back (some apps auto-delete after years) | Grace period, usually 14–30 days |
| Password needed? | ✅ Yes | ✅ Yes, plus a typed confirmation |

---

### Step 1: Ask for the password again (re-authentication)

Being logged in is **not enough** to destroy an account.

```js
if (!(await passwordMatches(req.user, req.body.password))) {
  return res.status(403).json({ error: "Wrong password" });
}
```

Why? The session cookie may be **stolen** (XSS, a shared computer, a laptop left open in a café). With re-authentication, the thief needs the password too.

| ✅ Do | ❌ Don't |
|---|---|
| Ask for the current password (or an MFA code, Level 6) | Delete on a single click |
| Rate-limit password checks like login (topic 16) | Let attackers guess the password here forever |
| Accept only `POST` with a body | Delete on `GET /delete-account` (a link in an email or an `<img>` tag could trigger it, CSRF) |
| Social-login users (Level 5): re-login with Google / send an email code | Skip the check because "they have no password" |

---

### Step 2: Deactivate: switch it off, keep the data

`POST /account/deactivate { password }`

```js
user.status = "deactivated";
user.deactivatedAt = new Date().toISOString();
deleteSessionsOf(user.id);  // log out every device
sendEmail(user.email, "Your account was deactivated", "...");
```

- **Don't delete anything.** Just change one field: `status`.
- **Log out every device.** Otherwise the phone that's still logged in keeps using the "switched off" account.
- **Hide the user everywhere**: search, profile pages, friend lists. A real app adds `WHERE status = 'active'` to those queries.
- **Send a notice email**, so Rahul finds out if it wasn't him.

---

### Step 3: Coming back after a deactivation

The simplest pattern (used by Facebook and Instagram): **logging in with the right password reactivates the account.**

```js
if (user.status === "deactivated") {
  notice = "Welcome back! Your account is active again.";
}
user.status = "active";
```

💡 Check the password **first**, and only then say "your account was deactivated". If you show that message before the password check, anyone can type an email and learn that the account exists and is deactivated (account enumeration, topic 06).

---

### Step 4: Delete: soft delete first, with a grace period

`POST /account/delete { password, confirm: "DELETE" }`

```js
if (confirm !== "DELETE") return res.status(400).json({ ... });  // no accidental clicks
user.status = "pending_deletion";
user.deleteAfter = Date.now() + 30 * 24 * 60 * 60 * 1000;      // 30 days from now
deleteSessionsOf(user.id);
res.status(202).json({ message: "Your account will be permanently deleted in 30 days..." });
```

| Term | Meaning |
|---|---|
| **Soft delete** | Only mark the row (`status`, `deletedAt`), the data is still there |
| **Hard delete** | Really remove the data (`DELETE FROM users ...`) |
| **Grace period** | The time between them, when the user can still undo it |

Why not erase it right away?

- Rahul **mis-clicks** or changes his mind tomorrow.
- An **attacker** who knows the password deletes the account. The owner gets the email and can log in to cancel.

Why `202 Accepted`? The request is accepted, but the real work (erasing) happens **later**.

Why `POST /account/delete` and not `DELETE /account`? `DELETE` with a JSON body (the password) has no defined meaning in HTTP (RFC 9110), and some proxies drop it. Both are fine in interviews if you can say why.

---

### Step 5: Cancel during the grace period

Same as Step 3: logging in during the grace period **cancels the deletion** and sends an email. Some apps use a "Cancel deletion" link in the email instead.

Until the grace period ends, **keep the email address taken**. If someone else could sign up with it, Rahul couldn't come back, and the new person might get his password-reset emails.

---

### Step 6: The purge job: really erase it

A **background job** (cron, a queue worker) runs every few minutes or once a day:

```js
for (const user of users.values()) {
  if (user.status === "pending_deletion" && Date.now() >= user.deleteAfter) {
    sendEmail(user.email, "Your account has been deleted", "...");  // last email, while we still have the address
    deleteSessionsOf(user.id);
    users.delete(user.email);
    auditLog.push({ event: "account_erased", userId: user.id, at: new Date().toISOString() });
  }
}
```

A real app must clean up **every place** the user lives:

| Where | What to do |
|---|---|
| `users` table | Delete the row (or blank out email, name, phone, password hash) |
| Sessions, refresh tokens, remember-me tokens, reset tokens (topics 09, 13, 15) | Delete all of them |
| Profile photo, uploads (S3 / cloud storage) | Delete the files |
| Comments, posts | Delete them, or show "Deleted user" |
| Orders, invoices, payments | **Keep** (tax law), but **anonymize**: replace the name/email with "Deleted user" |
| Analytics, email-marketing lists, third-party tools | Send them a delete request too |
| Logs | Don't log personal data in the first place; logs expire on their own |
| Backups | Can't edit them; they get deleted when the backup expires (say so in your privacy policy) |

---

### Step 7: Deleted users and JWTs

With **sessions** (topic 09), deleting the session rows logs everyone out right away.

With **JWTs** (Level 3), a token can't be deleted. It stays valid until it expires. So:

- Keep access tokens **short** (5–15 min).
- **Delete the refresh tokens** of the user, so no new access tokens can be made.
- When refreshing (or on sensitive routes), **check that the user still exists and is `active`**.

---

### 🤔 Tricky parts

**1. Unique email + soft delete.**
If `email` is `UNIQUE` and soft-deleted rows stay in the table, nobody can sign up with that email again, even after the purge. Fix: really delete or blank the row in the purge job, or use a partial unique index (`UNIQUE (email) WHERE deleted_at IS NULL`).

**2. Every query must skip inactive users.**
Forget `WHERE status = 'active'` in one query, and a "deleted" user shows up in search. Many ORMs have a "soft delete" feature (Prisma middleware, Sequelize `paranoid`, TypeORM `@DeleteDateColumn`) that adds it for you.

**3. "The right to be forgotten" is the law.**
GDPR (Europe) and India's DPDP Act 2023 give users the right to have their personal data erased. Under GDPR you must act without undue delay (normally within **one month**). So the purge job is **not optional**: a soft-delete flag kept forever is not "deleting".

**4. The last owner of a team.**
If Rahul is the only admin of a workspace, deleting him leaves it with no owner. Ask him to transfer ownership first, or delete the workspace too.

**5. Admins disabling a user is different.**
"Banned" or "suspended" by an admin is another status (Level 7, roles). The user must **not** be able to undo it by logging in. Keep it separate from "deactivated by the user".

---

### Common beginner mistakes

1. **No password check before deleting.**
   A stolen session cookie is enough to destroy the account. Re-authenticate.

2. **Deleting on `GET` (a link).**
   Email scanners, link previews and CSRF can trigger it. Use `POST` (or `DELETE`) with a body.

3. **Not logging out other devices.**
   The account is "deactivated" but the phone is still logged in.

4. **Erasing right away, no grace period.**
   One mis-click, or one attacker, and the data is gone for good.

5. **Soft delete forever.**
   "Deleted" users' data stays in your database. That breaks the law and the user's trust.

6. **Forgetting the other tables and files.**
   Tokens, uploads, analytics and third-party tools still hold the user's data.

7. **Hard-deleting rows that other tables need.**
   Orders and invoices crash or vanish. Anonymize instead.

8. **Freeing the email during the grace period.**
   Someone else takes it, and Rahul can't come back.

9. **Saying "this account is deactivated" before checking the password.**
   Leaks who has an account. Check the password first.

10. **No email notice.**
    If an attacker deletes the account, the owner never finds out in time to cancel.

---

### Interview questions

1. **What's the difference between deactivating and deleting an account?**
   Deactivation switches the account off and hides it, but keeps all data, and the user can come back. Deletion erases the personal data, usually after a grace period.

2. **What is soft delete vs hard delete?**
   Soft delete marks a row as deleted (`deleted_at`, `status`) but keeps it. Hard delete really removes the data. Account deletion usually soft-deletes first, then a job hard-deletes after the grace period.

3. **Why ask for the password before deleting an account?**
   A logged-in session can be stolen or used by someone at an unlocked computer. Re-authentication makes sure it's really the owner doing something that can't be undone.

4. **Why have a grace period?**
   To undo mistakes and attacks: the owner gets an email and can log in to cancel. It also gives time to finish background clean-up.

5. **What happens to sessions and JWTs when an account is deactivated or deleted?**
   Delete all sessions and refresh tokens right away. Access JWTs can't be deleted, so keep them short-lived and check the user's status when refreshing.

6. **How do you delete a user without breaking orders and invoices?**
   Keep the records you legally need, but anonymize them: remove the name, email and address, or point them to a "deleted user" placeholder.

7. **What is the "right to be forgotten"?**
   A legal right (GDPR Article 17, India's DPDP Act) for users to have their personal data erased. You must really delete it, within a deadline, including in third-party tools.

8. **What about data in backups?**
   You usually can't edit backups. The data disappears when the backup expires. If a backup is restored, run the deletions again (keep a list of erased user ids).

9. **How do you keep the email unique when you soft-delete users?**
   Blank or delete the row when you purge, or use a partial unique index that ignores deleted rows.

---

### Quick recap

- **Deactivate** = switch off, keep the data. **Delete** = erase the personal data
- Both need the **password again** (plus typing `DELETE` for deletion), `POST` only
- Both **log out every device** and send an **email notice**
- Logging in with the right password **reactivates** / **cancels deletion**; say why only **after** the password check
- Delete = **soft delete now**, **hard delete after a grace period** (14–30 days) by a **background job**
- Keep the **email taken** during the grace period
- Erase **everywhere**: tokens, files, third-party tools; **anonymize** what the law makes you keep
- JWTs: short-lived, delete refresh tokens, check status on refresh
- It's the law (GDPR, DPDP): a soft-delete flag forever is **not** deleting

## Code

A small **Express** API (plus Node's built-in `crypto`): sign up, log in on a "laptop" and a "phone" (session cookies, as in topic 09), deactivate the account and watch the phone get logged out, log in again to reactivate it, then delete the account, cancel it, delete it again and watch the purge job erase it. Users and sessions are kept in memory, so they disappear when you restart.

📄 **Full code: [server.js](server.js)**. Open it and read the comments, which follow the same steps as the notes above.

Install Express once (from this folder), then start the server. `DELETION_GRACE_SECONDS=10` shortens the 30-day grace period to 10 seconds so you can watch the account get erased:

```bash
npm install
```

```bash
DELETION_GRACE_SECONDS=10 node server.js
```

> Port 3000 busy? Run it on another port: `PORT=3017 DELETION_GRACE_SECONDS=10 node server.js` (Git Bash), then use that port in the commands below.

### Try it

✅ **Sign up, then log in on two devices:** `-c laptop.txt` and `-c phone.txt` save each device's session cookie in a file, like two browsers would.

```bash
curl -i -X POST http://localhost:3000/signup -H "Content-Type: application/json" -d '{"email":"rahul@mail.com","password":"rahul password 123"}'
```
→ `201 Created` with `{"id":"...","email":"rahul@mail.com"}`

```bash
curl -c laptop.txt -X POST http://localhost:3000/login -H "Content-Type: application/json" -d '{"email":"rahul@mail.com","password":"rahul password 123"}'
```

```bash
curl -c phone.txt -X POST http://localhost:3000/login -H "Content-Type: application/json" -d '{"email":"rahul@mail.com","password":"rahul password 123"}'
```
→ both reply `{"message":"Logged in","email":"rahul@mail.com"}`

```bash
curl -b laptop.txt http://localhost:3000/me
```
→ `{"id":"...","email":"rahul@mail.com","status":"active"}`

❌ **Deactivate with the wrong password:** being logged in is not enough.

```bash
curl -i -b laptop.txt -X POST http://localhost:3000/account/deactivate -H "Content-Type: application/json" -d '{"password":"wrong password"}'
```
→ `403 Forbidden` with `{"error":"Wrong password"}`

✅ **Deactivate:**

```bash
curl -i -b laptop.txt -X POST http://localhost:3000/account/deactivate -H "Content-Type: application/json" -d '{"password":"rahul password 123"}'
```
→ `200 OK` with `{"message":"Account deactivated. Log in any time to reactivate it."}`, and the terminal prints:

```
📧 To: rahul@mail.com
   Subject: Your account was deactivated
   Log in any time to turn it back on. If this wasn't you, log in and change your password.
```

🚪 **The phone was logged out too:**

```bash
curl -i -b phone.txt http://localhost:3000/me
```
→ `401 Unauthorized` with `{"error":"Not logged in"}`

🛡️ **The email is still taken, and a wrong password says nothing about the account:**

```bash
curl -i -X POST http://localhost:3000/signup -H "Content-Type: application/json" -d '{"email":"rahul@mail.com","password":"someone else 123"}'
```
→ `409 Conflict` with `{"error":"Email already registered"}`

```bash
curl -i -X POST http://localhost:3000/login -H "Content-Type: application/json" -d '{"email":"rahul@mail.com","password":"wrong password"}'
```
→ `401 Unauthorized` with `{"error":"Invalid email or password"}` (no "this account is deactivated")

✅ **Come back: logging in reactivates it:**

```bash
curl -c laptop.txt -X POST http://localhost:3000/login -H "Content-Type: application/json" -d '{"email":"rahul@mail.com","password":"rahul password 123"}'
```
→ `{"message":"Logged in","email":"rahul@mail.com","notice":"Welcome back! Your account is active again."}`

❌ **Delete without typing the confirmation:**

```bash
curl -i -b laptop.txt -X POST http://localhost:3000/account/delete -H "Content-Type: application/json" -d '{"password":"rahul password 123"}'
```
→ `400 Bad Request` with `{"error":"Type \"DELETE\" in the confirm field to delete your account"}`

✅ **Delete the account:**

```bash
curl -i -b laptop.txt -X POST http://localhost:3000/account/delete -H "Content-Type: application/json" -d '{"password":"rahul password 123","confirm":"DELETE"}'
```
→ `202 Accepted` with `{"message":"Your account will be permanently deleted in 10 seconds. Log in before then to cancel.","deleteAfter":"2026-11-05T01:52:32.567Z"}`, and the laptop is logged out (`/me` → `401`).

↩️ **Change your mind (log in within 10 seconds):**

```bash
curl -c laptop.txt -X POST http://localhost:3000/login -H "Content-Type: application/json" -d '{"email":"rahul@mail.com","password":"rahul password 123"}'
```
→ `{"message":"Logged in","email":"rahul@mail.com","notice":"Your account deletion was cancelled."}`

🗑️ **Delete it again, and this time wait 10+ seconds:** run the delete command again, then watch the terminal:

```
📧 To: rahul@mail.com
   Subject: Your account has been deleted
   All your personal data has been erased. Goodbye!

🗑️  Erased account f73ea921-31ac-4d4f-b53f-8ed015b34406. Audit log now has 3 entries (ids only, no personal data).
```

❌ **The account is gone:**

```bash
curl -i -X POST http://localhost:3000/login -H "Content-Type: application/json" -d '{"email":"rahul@mail.com","password":"rahul password 123"}'
```
→ `401 Unauthorized` with `{"error":"Invalid email or password"}`

✅ **The email is free again:**

```bash
curl -i -X POST http://localhost:3000/signup -H "Content-Type: application/json" -d '{"email":"rahul@mail.com","password":"new rahul 12345"}'
```
→ `201 Created` with a **new** id

> **Windows PowerShell users:** the single quotes in the `-d '...'` part and `VAR=value node ...` work in Git Bash. In PowerShell, use Git Bash, Postman, or set the variable with `$env:DELETION_GRACE_SECONDS=10; node server.js`.
