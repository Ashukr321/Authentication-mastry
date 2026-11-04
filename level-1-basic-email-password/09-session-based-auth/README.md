# 09. Session-Based Auth

## Notes

### What is session-based auth?

In topic 07 (login) we gave the user a **session cookie** after a correct password. This topic explains what that session **really is** and how to manage it properly.

> A **session** is a small record **stored on the server** that says *"this visitor is Rahul, logged in since 10:30"*.
> The browser only gets a **random ID** (the session ID) that points to that record.

```
Browser cookie:   sessionId=k9X2fQ...            ← just a random "ticket number"
Server store:     k9X2fQ... → { userId: "u_1", createdAt: 10:30, lastSeenAt: 10:42 }
```

This fixes the problem from topic 02 (**HTTP is stateless**): the server **remembers you** by looking up your session ID on every request.

It also fixes the problems of Basic Auth (topic 08): the password is sent **only once**, and **logout actually works**, because the server can delete the session.

---

### Real-life example: a coat check 🧥

At a theatre's coat check:

1. You hand over your coat and get a **numbered token** (#42) → you log in and get a **session ID**
2. The **coat stays behind the counter**, not in your pocket → user data stays **on the server**
3. The token itself means nothing. It's just a number → the session ID contains **no user information**
4. To get your coat, you show the token, and staff look up #42 → every request, the server **looks up** the session
5. When you leave, the token is **taken back** and #42 is freed → **logout deletes the session**
6. If someone **steals your token**, they can take your coat 😱 → stolen session ID = **stolen login**. That's why we protect the cookie so carefully.

---

### The session lifecycle

A session goes through four stages:

| Stage | When | What the server does |
|---|---|---|
| 1. **Create** | Login succeeds | Make a random ID, save `{ userId, createdAt, lastSeenAt }`, send the ID in a cookie |
| 2. **Read** | Every request | Read the cookie, look up the session, find out who the user is |
| 3. **Refresh** | Every request | Update `lastSeenAt` (keeps an active user logged in) |
| 4. **Destroy** | Logout, or it expires | Delete the session from the store and clear the cookie |

#### 📊 Diagrams

Open **[diagrams.html](diagrams.html)** in your browser (just double-click the file) to see:

- **Flow diagram**: what the server checks on every request to a protected page (cookie → lookup → expired? → allowed)
- **Data flow**: the whole life of a session, from login to normal requests, logout, and a stolen cookie that stops working after logout
- **Scaling**: why an in-memory store breaks with two servers, and how a shared Redis store fixes it

In short: `login → create session + cookie → every request: look up session → logout: delete session → old cookie is now useless`

---

### Where are sessions stored? (the session store)

| Store | Good for | Problems |
|---|---|---|
| **Server memory** (a `Map`) | Learning and local development | Lost on restart. Doesn't work with **2+ servers**, because each one has its own memory |
| **Redis** ⭐ | Most real apps | One more service to run (but it's fast, and has built-in expiry) |
| **SQL database** (Postgres, MySQL) | Apps that don't want Redis | Slower, and you must delete old sessions yourself |

#### Why memory fails with multiple servers

Login happens on **Server A** and the session is saved in A's memory. The next request goes to **Server B**, which has never heard of you, so it answers "Please log in". 😕 (See diagram 3 in **[diagrams.html](diagrams.html#scale)**.)

👉 **Fix:** all servers share **one session store** (usually **Redis**). Another option is "sticky sessions", where the load balancer always sends a user to the same server, but that breaks if the server restarts.

---

### Rules for the session ID

The session ID is now **as valuable as the password**: anyone who has it **is** you, until the session ends.

| Rule | Why |
|---|---|
| **Long and random**: `crypto.randomBytes(32)` (256 bits) | Impossible to guess. OWASP asks for at least 64 bits of randomness, and 128+ is common. |
| **Never** `Math.random()`, a counter, the user ID, or the email | Those are predictable, so attackers can guess other users' sessions |
| **New ID on every login** | Prevents **session fixation** (topic 07) |
| **New ID when privileges change** (e.g. becoming admin, or after a password change) | Same reason: an old ID shouldn't gain new powers |
| Contains **no user data** | It's just a pointer. The real data stays on the server. |

#### The cookie that carries it

```
Set-Cookie: sessionId=k9X2fQ...; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=86400
```

| Flag | Protects against |
|---|---|
| `HttpOnly` | JavaScript (and XSS attacks) can't read the session ID |
| `Secure` | Never sent over plain HTTP |
| `SameSite=Lax` | Not sent on most cross-site requests, which helps against **CSRF** |
| `Max-Age` | The browser deletes it after this time |

*(Topic 10 covers every cookie flag in detail.)*

#### 💡 Pro tip: store a hash of the session ID

If your session table **leaks** (for example through SQL injection), the attacker gets **every live session ID** and can log in as everyone.

Fix: store `sha256(sessionId)` as the key instead of the raw ID. The browser sends the raw ID, and the server hashes it before looking it up. A leaked table then contains only hashes, which are useless for logging in. (A fast hash is fine here, because a 256-bit random ID can't be guessed.) The code for this topic does this.

---

### Session expiry: two timers ⏱️

A session should **not live forever**. Use **two** timeouts:

| Timeout | Meaning | Typical value |
|---|---|---|
| **Idle timeout** | Log out if the user does **nothing** for X minutes | 15–30 min (banking: ~5–15 min) |
| **Absolute timeout** | Log out after X hours **no matter what**, even if the user is active | 8–24 hours (or days, with "remember me") |

```
Logged in at 10:00   idle timeout = 30 min, absolute timeout = 8 hours

10:20  request  ✅  (idle timer resets to 10:50)
10:45  request  ✅  (idle timer resets to 11:15)
11:30  request  ❌  idle for 45 min → logged out
```

**Why both?**
- Idle only: an attacker with a stolen session could keep it alive **forever** by sending a request every few minutes.
- Absolute only: a user who walked away from a shared computer stays logged in for hours.

The idle timeout that resets on every request is also called a **sliding expiration**.

> The **cookie's** `Max-Age` is only a hint for the browser. **The server must check expiry itself**, because attackers can keep using an old cookie value.

---

### What to put inside a session

| ✅ Store | ❌ Don't store |
|---|---|
| `userId` | Passwords or password hashes |
| `createdAt`, `lastSeenAt` | Large objects (full user profiles, shopping history) |
| Small helpful info: IP, user agent (for a "your devices" page) | Anything you'd be upset to see leaked |
| Things like a CSRF token, or a flash message | |

Keep the session **small**. Load fresh user data (name, role) from the database when you need it, so that changes (like a removed admin role) apply **immediately**.

---

### Logout: the big advantage of sessions

```
Logout = delete the session on the server + clear the cookie in the browser
```

Once the session is deleted, the old session ID is **useless**, even if an attacker copied it earlier. That's something Basic Auth (topic 08) and JWTs (Level 3) can't easily do.

**"Log out of all devices"** is easy too: delete every session for that `userId`. Use it after a password change, or when the user reports a stolen phone.

*(Topic 11 covers logout in detail.)*

---

### The `requireAuth` middleware pattern

In real apps you don't repeat the session check in every route. You write it **once**:

```js
// Express-style middleware (pseudo-code)
async function requireAuth(req, res, next) {
  const session = await sessionStore.get(req.cookies.sessionId);
  if (!session || isExpired(session)) return res.status(401).json({ error: "Please log in" });
  session.lastSeenAt = Date.now();     // sliding (idle) expiry
  req.user = await db.users.findById(session.userId);
  next();
}

app.get("/me", requireAuth, (req, res) => res.json(req.user));
app.get("/orders", requireAuth, (req, res) => { /* ... */ });
```

In Express, the popular library is **`express-session`**, with a store like **`connect-redis`**. It handles the cookie, the store, and expiry for you. Now you know what it does inside.

---

### ⚠️ Sessions and CSRF

Cookies are sent **automatically** by the browser, even when the request comes from **another website**:

```
You're logged in to bank.com (session cookie saved).
You visit evil.com, which has a hidden form:
   <form action="https://bank.com/transfer" method="POST"> ... </form>
The browser sends your bank.com cookie with it. 😱 The bank thinks YOU sent it.
```

This is **CSRF (Cross-Site Request Forgery)**. Defenses:
- `SameSite=Lax` or `Strict` on the session cookie (a big help, and the default in modern browsers)
- **CSRF tokens** for forms (Level 7)
- Never change data with `GET` requests

---

### Sessions vs tokens (JWT): a preview

| | Sessions (this topic) | JWT (Level 3) |
|---|---|---|
| Where's the user data? | **Server** (session store) | **Inside the token** (client holds it) |
| What the browser holds | A meaningless random ID | A signed token anyone can read |
| Every request | A store lookup (fast with Redis) | Verify the signature, with no lookup |
| Logout / revoke | ✅ Instant: delete the session | ⚠️ Hard: the token is valid until it expires |
| Scaling to many servers | Needs a shared store (Redis) | Easy: any server can verify it |
| Best for | Websites with a backend you control | APIs, mobile apps, microservices |

Neither is "better". For a normal website, **sessions are simple, secure, and battle-tested**.

---

### Common beginner mistakes

1. **Using an in-memory store in production.**
   Users get logged out on every restart, and it breaks with more than one server. Use Redis or a database.

2. **Predictable session IDs** (`Math.random()`, counters, user IDs).
   Use `crypto.randomBytes(32)`.

3. **Not creating a new session ID at login** (session fixation).

4. **Relying only on the cookie's `Max-Age`.**
   The server must check the idle and absolute timeouts itself.

5. **No absolute timeout.**
   A stolen session can be kept alive forever.

6. **Logout only clears the cookie** and doesn't delete the server-side session.
   Anyone who copied the ID can still use it.

7. **Storing passwords or big objects in the session.**
   Keep it small: `userId` and timestamps.

8. **Missing `HttpOnly` / `Secure` / `SameSite`** on the session cookie.

9. **Never cleaning up expired sessions.**
   The store grows forever. Use Redis expiry (TTL) or a cleanup job.

10. **Changing data with `GET` requests.**
    Combined with cookies, this makes CSRF trivial.

---

### Interview questions

1. **What is session-based authentication?**
   After login, the server creates a session record (user ID, timestamps) in a store and gives the client a random session ID in a cookie. On each request, the server looks up the session by that ID to identify the user.

2. **Where should sessions be stored in production?**
   In a shared store like Redis (or a database), so that all app servers can see them and they survive restarts. Memory is only for development.

3. **What makes a good session ID?**
   Long (128+ bits) and cryptographically random, with no meaning. It's regenerated at login and on privilege changes.

4. **What's the difference between idle and absolute timeout?**
   Idle timeout ends a session after a period of inactivity, and resets on each request. Absolute timeout ends it after a fixed time, regardless of activity.

5. **How does logout work with sessions, and why is it better than with JWTs?**
   Delete the session from the store and clear the cookie. The old ID becomes useless immediately. A JWT stays valid until it expires, unless you build a blocklist.

6. **How do sessions work with multiple servers behind a load balancer?**
   Use a shared session store (Redis), or sticky sessions. A shared store is the standard approach.

7. **What is session fixation, and how do you prevent it?**
   An attacker plants a known session ID before the victim logs in. Prevent it by generating a new session ID on login.

8. **Why are session cookies vulnerable to CSRF, and how do you defend against it?**
   Browsers attach cookies automatically to cross-site requests. Defend with `SameSite` cookies, CSRF tokens, and never changing state on `GET`.

9. **Why might you store a hash of the session ID instead of the raw ID?**
   If the session table leaks, the attacker can't use the hashes to log in. The server hashes the incoming ID before looking it up.

---

### Quick recap

- **Session** = a record on the server. The browser only holds a **random session ID** in a cookie.
- Lifecycle: **create** (login) → **read + refresh** (each request) → **destroy** (logout or expiry)
- Store: memory for learning, **Redis** for real apps (shared by all servers)
- Session ID: **random 256 bits**, **new on login**, cookie with `HttpOnly; Secure; SameSite`
- Two timers: **idle** (sliding) + **absolute**, both checked **on the server**
- **Logout is real**: delete the session, and the old ID is dead. "Log out everywhere" is easy too.
- Watch out for **CSRF**, because cookies are sent automatically

## Code

A complete session system using only Node.js built-ins. It covers login, a protected `/me` route, a "my devices" list, logout, logout from all devices, and idle + absolute timeouts. It reuses the scrypt hashing and dummy hash from topics 04 and 07.

📄 **Full code: [server.js](server.js)**. Open it and read the comments, which follow the session lifecycle above (create → read → refresh → destroy).

> Demo user (made up for this example only): `rahul@mail.com` / `correct horse battery`

```bash
node server.js
```

### Try it

Run these in **Git Bash** (or use Postman). `-c file` saves the cookie, and `-b file` sends it, like a browser does. We use **two cookie files** to act as **two devices** (a laptop and a phone).

**1. Log in on the "laptop"**

```bash
curl -i -c laptop.txt -X POST http://localhost:3000/login -H "Content-Type: application/json" -d '{"email":"rahul@mail.com","password":"correct horse battery"}'
```
→ `200` with `Set-Cookie: sessionId=...; HttpOnly; SameSite=Lax; Path=/; Max-Age=28800`

**2. Use the session**

```bash
curl -b laptop.txt http://localhost:3000/me
```
→ `{"user":{"id":"u_1","email":"rahul@mail.com"},"session":{"createdAt":"...","idleExpiresInSeconds":1800,"absoluteExpiresInSeconds":28799}}`

**3. Log in on the "phone" too, and list your devices**

```bash
curl -s -c phone.txt -X POST http://localhost:3000/login -H "Content-Type: application/json" -d '{"email":"rahul@mail.com","password":"correct horse battery"}'
```

```bash
curl -b laptop.txt http://localhost:3000/sessions
```
→ `{"count":2,"sessions":[{"current":true,...},{"current":false,...}]}`. The server stores **two sessions** for one user.

**4. Copy the laptop's cookie (pretend an attacker stole it), then log out on the laptop**

```bash
cp laptop.txt stolen.txt
```

```bash
curl -i -b laptop.txt -X POST http://localhost:3000/logout
```
→ `204 No Content` with `Set-Cookie: sessionId=; ...; Max-Age=0` (the cookie is cleared)

**5. The stolen cookie is now useless**

```bash
curl -i -b stolen.txt http://localhost:3000/me
```
→ `401` with `{"error":"Please log in"}`. The session was deleted **on the server**, so the old ID points to nothing. 🎉

**6. Log out of all devices from the phone**

```bash
curl -s -b phone.txt -X POST http://localhost:3000/logout-all
```
→ `{"loggedOutSessions":1}`. Every session for this user is gone.

**7. Watch the idle timeout happen (10 seconds instead of 30 minutes)**

Stop the server, then start it with short timeouts:

```bash
IDLE_TIMEOUT_SECONDS=10 node server.js
```

Log in, call `/me` right away (✅ works), wait **more than 10 seconds** without any requests, and call `/me` again:

```bash
curl -i -b laptop.txt http://localhost:3000/me
```
→ `401` with `{"error":"Session expired, please log in again"}`

> **PowerShell users:** set the variable first with `$env:IDLE_TIMEOUT_SECONDS=10; node server.js`. You can also try `ABSOLUTE_TIMEOUT_SECONDS=30` to watch the absolute timeout end a session even while you keep using it.
