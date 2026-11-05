# 26. Multi-Device Sessions

## Notes

### What are multi-device sessions?

Rahul is logged in on his laptop, his phone and his tablet at the same time. Each one is a separate **session**: its own refresh token, its own "last active" time, and it can be **logged out on its own**. The "Your devices" page in Google, Netflix or WhatsApp Web is built on this.

Topic 11 did this for **cookie sessions**. With **JWTs** there's a twist: access tokens are checked without the database, so the server needs a way to tie each access token to its device.

> **One-line answer:** every login creates a **session row** (device, IP, created, last used) that owns that device's refresh token, and every access token carries the session id as a **`sid` claim**. Logging out one device = delete its row (refresh dies) + put its `sid` on a short revoked list (access tokens die). Add a "Your devices" list, "log out other devices", a device limit and a new-device email.

---

### Why does it matter?

| Without per-device sessions | What goes wrong |
|---|---|
| One refresh token per user | Logging in on the phone logs out the laptop (or they share one token 😬) |
| No list of devices | Rahul can't see that someone in another city is logged in |
| Only "log out everywhere" | To kick out a stolen phone, he must log out of **every** device |
| Logout only deletes the refresh token | The kicked device keeps working for up to 15 minutes |
| No new-device alert | Nobody notices an attacker's login |
| No device limit | One paid account shared by 20 people (Netflix's problem) |

---

### Real-life example: a family OTT subscription 📺

Priya pays ₹649 a month for a streaming plan with **3 screens**.

1. Each place she logs in (laptop, phone, her parents' Smart TV) appears in **"Manage devices"** → **one session row per device**
2. Each screen shows "last watched 2 days ago, Pune" → **`lastUsedAt` + IP**
3. Her cousin logs in on a 4th device → the app **logs out the screen used least recently** → **device limit**
4. She gets an SMS: "New login on Smart TV" → **new-device alert**
5. She sees a device she doesn't know and taps **"Sign out"** on just that one → **revoke one session**, the others keep playing
6. She taps **"Sign out of all other devices"** → **revoke all except the current one**

---

### The flow, step by step

#### 📊 Diagrams

Open **[diagrams.html](diagrams.html)** in your browser (just double-click the file) to see:

- **Flow diagram**: what happens at login: new-device alert, device limit, new session row
- **Data flow**: three devices log in, the laptop sees "Your devices" and logs out the tablet remotely
- **How the pieces connect**: session row ↔ refresh token ↔ `sid` in the access token

In short: `login → session row { device, ip, lastUsedAt } + refresh token + access token { sid }`. `refresh → lastUsedAt = now`. `log out a device → delete its row + revoked[sid] for 15 min`. Every request: `verify JWT → sid not revoked`.

---

### Step 1: One session row per login

```js
const session = { id: crypto.randomUUID(), userId, refreshTokenHash: sha256(refreshToken),
                  device: "Chrome on Windows", ip: req.ip, createdAt: now, lastUsedAt: now, expiresAt: now + 30 days };
jwt.sign({ sub: user.id, email, sid: session.id }, SECRET, { expiresIn: 900 });
```

- The **session id** is a random public id. It's safe to show it in "Your devices" and to use it in URLs (`DELETE /sessions/:id`). It is **not** a secret.
- The **refresh token** is the secret. It's stored only as a hash and is **never** shown in the device list (topic 11's rule).
- The **`sid` claim** links every access token to its session, so one device can be revoked without touching the others.

| ✅ Do | ❌ Don't |
|---|---|
| A new session per login | One shared refresh token for all devices |
| Public `id` ≠ secret refresh token | Show the token (or its hash) in the device list |
| Store device, IP, created, last used | Store nothing and show "Unknown device" |
| A friendly device name (`ua-parser-js`) | Show the raw 200-character User-Agent |

---

### Step 2: "Last active" comes from refresh

```js
session.lastUsedAt = Date.now(); // in POST /auth/refresh
session.ip = req.ip;
```

Access tokens are checked **without** the database, so the server only "sees" a device when it refreshes. "Last active" is therefore accurate to about **one access token lifetime** (15 minutes). That's fine for a device list. If you need exact activity, write it in the background or sample it, rather than hitting the DB on every request.

---

### Step 3: "Your devices"

```http
GET /sessions
Authorization: Bearer eyJ...
```
```json
{ "devices": [
  { "id": "6e5d…", "device": "Chrome on Android tablet", "ip": "::1", "lastUsedAt": "…", "current": false },
  { "id": "2418…", "device": "Chrome on Windows (laptop)", "ip": "::1", "lastUsedAt": "…", "current": true }
]}
```

`current: true` is found by comparing each row with the `sid` in the caller's token, so the UI can show "This device" and hide its "Sign out" button (use normal logout for that).

Real apps also show an approximate **location** from the IP ("Pune, India"), using a GeoIP database.

---

### Step 4: Log out one device (or all others)

```js
function revokeSession(sessionId) {
  sessions.delete(sessionId);                                           // refresh token is gone
  revokedSessions.set(sessionId, Date.now() + ACCESS_TTL_SECONDS * 1000); // its access tokens die now
}
// every request, after jwt.verify:
if (revokedSessions.has(claims.sid)) return res.status(401).json({ code: "session_revoked" });
```

This is the topic 24 deny-list, but **per device** instead of per token: one entry kills every access token that device has, and it only needs to live for one access token lifetime.

| Endpoint | What it does |
|---|---|
| `DELETE /sessions/:id` | Log out one device. **Only if it's yours**: someone else's id gets the same `404` as a made-up one |
| `POST /sessions/revoke-others` | Log out every device except this one ("Not you? Sign out everywhere else") |
| `POST /auth/logout` | Log out this device |
| Password change / reset | Revoke all sessions (maybe except the current one), topic 24 |

---

### Step 5: New-device alert

```js
if (existing.length > 0 && !existing.some((s) => s.device === device)) {
  // 📧 "New sign-in on Safari on iPhone from 49.36.x.x. Not you? ..."
}
```

The email should say **what** (device), **where** (approximate location), **when**, and **what to do** ("Not you? Log it out and change your password"). It's one of the cheapest ways to catch an account takeover. Real apps compare more than the User-Agent (location, a long-lived device cookie), because User-Agents change with every browser update.

---

### Step 6: Device limit

```js
if (existing.length >= MAX_DEVICES) {
  const oldest = existing.reduce((a, b) => (a.lastUsedAt <= b.lastUsedAt ? a : b));
  revokeSession(oldest.id);
}
```

Two common choices:

| Strategy | Used by | Feels like |
|---|---|---|
| Log out the **least recently used** device | Many apps, this demo | Logging in always works |
| **Refuse** the new login: "Too many devices, log out one first" | Some streaming / banking apps | Stricter, more support tickets |

Pick **least recently used**, not **oldest created**: the laptop Rahul logged in on a month ago but uses daily should survive; the phone he hasn't opened in two weeks should go.

---

### 🤔 Tricky parts

**1. Same device, logged in twice.**
Logging in again on the same browser creates a second row. Fix: on login, revoke the session this browser already had (read its refresh cookie, like topic 15 did), or reuse it.

**2. Device names lie.**
A User-Agent is just a header; attackers can copy it. Use it for display, never for security decisions.

**3. Private browsing and cleared cookies.**
Each one looks like a new device and creates a new row. Expired rows get cleaned up after 30 days.

**4. Rotation + sessions (topic 23).**
With rotation, the session row keeps the **current** refresh token hash (and the used ones for reuse detection). A reuse alarm revokes **that session**, not every device.

**5. Showing IPs is a privacy question.**
Show an approximate city, not the full IP, to other people in a shared account. Store what your privacy policy allows.

**6. Is this just stateful sessions again?**
Partly. The session table is touched at **login, refresh and logout**, not on every request. Per request you only check a tiny revoked set. That's the JWT trade-off: a little state, much less often.

---

### Common beginner mistakes

1. **One refresh token per user instead of per device.**
   Logging in elsewhere breaks the first device, and you can't revoke one device.

2. **No `sid` in the access token.**
   You can delete the device's refresh token, but its access token keeps working until it expires.

3. **Showing the refresh token (or its hash) in "Your devices".**
   Show a separate public id.

4. **`DELETE /sessions/:id` without checking the owner.**
   Anyone could log out anyone. Check `session.userId === me`, and return `404` either way.

5. **Updating `lastUsedAt` with a DB write on every request.**
   Slow, and it throws away the JWT benefit. Update it on refresh.

6. **Kicking out the oldest-created device at the limit.**
   Use least recently used.

7. **No new-device alert.**
   Account takeovers go unnoticed.

8. **Trusting the User-Agent for security.**
   It's for display only.

9. **Forgetting to revoke sessions on password change/reset.**
   An attacker's device stays logged in.

---

### Interview questions

1. **How do you support login on multiple devices with JWTs?**
   Create a session row per login holding that device's refresh token (hashed), device info and timestamps. Put the session id in every access token as `sid`.

2. **How do you log out one specific device?**
   Delete its session row (its refresh token stops working) and add its `sid` to a revoked list for one access token lifetime, checked on each request.

3. **How do you build "Your devices"?**
   List the user's session rows: device name, approximate location, created and last used, and mark the one matching the caller's `sid` as "this device". Never show tokens.

4. **How do you keep "last active" up to date without a DB write per request?**
   Update it on refresh. It's accurate to one access token lifetime, which is good enough for a device list.

5. **How would you limit a user to 3 devices?**
   At login, count active sessions. If at the limit, revoke the least recently used one (or refuse the login with a clear message).

6. **How do you prevent one user from logging out another user's devices?**
   Check that the session belongs to the caller, and return the same `404` for "not yours" and "doesn't exist", so ids can't be probed.

7. **When should all sessions be revoked?**
   Password reset, password change (keep the current one), account compromise, account disabled or deleted.

8. **What goes into a new-device alert?**
   Device, approximate location, time, and a clear action ("Not you? Sign out that device and change your password").

---

### Quick recap

- **One session row per login**: device, IP, `createdAt`, `lastUsedAt`, hashed refresh token
- Access tokens carry **`sid`** → one device can be revoked on its own
- Revoke = **delete the row** + **`sid` on a revoked list** for one access token lifetime
- "Your devices" = list rows, mark `current`, **never show tokens**
- `lastUsedAt` is updated on **refresh**, not every request
- **Log out others**, **owner check** with `404`, **new-device alert**, **device limit (LRU)**
- Next: validating every claim properly (topic 27)

## Code

A small **Express** + **`jsonwebtoken`** API: every login creates a **session row** for that device, access tokens carry its **`sid`**, and you can list your devices, log one out remotely, log out all the others, and watch the device limit and new-device alerts in the terminal. Users and sessions are kept in memory, so they disappear when you restart.

📄 **Full code: [server.js](server.js)**. Open it and read the comments, which follow the same steps as the notes above.

Install the dependencies once (from this folder), then start the server:

```bash
npm install
```

```bash
node server.js
```

> Port 3000 busy? Run it on another port: `PORT=3026 node server.js` (Git Bash), then use that port in the commands below. `MAX_DEVICES=5 node server.js` changes the device limit (default 3).

### Try it

Each device has its own cookie file (`-c` / `-b`) and its own **User-Agent** (`-A`), which becomes its device name. Copy the `accessToken` from each login into `LAPTOP`, `PHONE`, `TABLET`, `TV` (Git Bash).

✅ **Sign up, then log in on three devices:**

```bash
curl -X POST http://localhost:3000/auth/signup -H "Content-Type: application/json" -d '{"email":"rahul@mail.com","password":"correct horse battery"}'
```

```bash
curl -c laptop.txt -A "Chrome on Windows (laptop)" -X POST http://localhost:3000/auth/login -H "Content-Type: application/json" -d '{"email":"rahul@mail.com","password":"correct horse battery"}'
```

```bash
curl -c phone.txt -A "Safari on iPhone" -X POST http://localhost:3000/auth/login -H "Content-Type: application/json" -d '{"email":"rahul@mail.com","password":"correct horse battery"}'
```

```bash
curl -c tablet.txt -A "Chrome on Android tablet" -X POST http://localhost:3000/auth/login -H "Content-Type: application/json" -d '{"email":"rahul@mail.com","password":"correct horse battery"}'
```

The terminal sends a new-device email for the phone and the tablet (not for the very first login):
```
📧 To: rahul@mail.com: "New sign-in on Safari on iPhone from ::1. Not you? Log it out from Your devices and change your password."
📧 To: rahul@mail.com: "New sign-in on Chrome on Android tablet from ::1. Not you? Log it out from Your devices and change your password."
```

✅ **Your devices** (from the laptop):

```bash
curl http://localhost:3000/sessions -H "Authorization: Bearer $LAPTOP"
```
→
```json
{"devices":[
  {"id":"6e5d13de-a566-404c-86c5-8c689b02347e","device":"Chrome on Android tablet","ip":"::1","createdAt":"2026-11-05T02:28:56.015Z","lastUsedAt":"2026-11-05T02:28:56.015Z","current":false},
  {"id":"68d0295d-8d74-4aa6-b48c-4b57fe73b4a5","device":"Safari on iPhone","ip":"::1","createdAt":"2026-11-05T02:28:54.504Z","lastUsedAt":"2026-11-05T02:28:54.504Z","current":false},
  {"id":"24181bb6-9389-4d92-83a4-59258a01e769","device":"Chrome on Windows (laptop)","ip":"::1","createdAt":"2026-11-05T02:28:53.971Z","lastUsedAt":"2026-11-05T02:28:53.971Z","current":true}
]}
```

✅ **The laptop refreshes**, which updates its `lastUsedAt`:

```bash
curl -b laptop.txt -X POST http://localhost:3000/auth/refresh
```

🔌 **A 4th device hits the limit of 3:**

```bash
curl -c tv.txt -A "Smart TV app" -X POST http://localhost:3000/auth/login -H "Content-Type: application/json" -d '{"email":"rahul@mail.com","password":"correct horse battery"}'
```
→ the terminal prints `🔌 Device limit (3) reached: logged out "Safari on iPhone"`. The **phone** goes, not the laptop: the laptop was created first but used more recently.

```bash
curl http://localhost:3000/me -H "Authorization: Bearer $PHONE"
```
→ `{"error":"This device was logged out","code":"session_revoked"}`, and `curl -b phone.txt -X POST http://localhost:3000/auth/refresh` → `{"error":"This device is logged out, please log in"}`

✅ **Log out the tablet from the laptop** (use the tablet's `id` from `/sessions`):

```bash
curl -X DELETE http://localhost:3000/sessions/6e5d13de-a566-404c-86c5-8c689b02347e -H "Authorization: Bearer $LAPTOP"
```
→ `{"message":"Logged out \"Chrome on Android tablet\""}`. The tablet's access token fails **right away** (`session_revoked`) and its refresh fails too.

❌ **Someone else's device, or a made-up id:** both give the same answer.

```bash
curl -X DELETE http://localhost:3000/sessions/not-a-real-id -H "Authorization: Bearer $LAPTOP"
```
→ `{"error":"Device not found"}`. Priya, logged in to her own account, trying to delete Rahul's laptop session id gets the same `{"error":"Device not found"}`.

✅ **Log out all other devices:**

```bash
curl -X POST http://localhost:3000/sessions/revoke-others -H "Authorization: Bearer $LAPTOP"
```
→ `{"message":"Logged out 1 other device(s)"}` (the TV). `/sessions` now lists only the laptop, with `"current":true`.

✅ **Log out this device:**

```bash
curl -b laptop.txt -c laptop.txt -X POST http://localhost:3000/auth/logout -H "Authorization: Bearer $LAPTOP"
```
→ `{"message":"Logged out on this device"}`, and the laptop's access token now gets `session_revoked` too.

> **Windows PowerShell users:** the single quotes in the `-d '...'` part, `LAPTOP=...` / `$LAPTOP` and `VAR=value node ...` work in Git Bash. In PowerShell, use Git Bash, Postman, or `$env:PORT=3026; node server.js` and `$LAPTOP="eyJ..."`.
