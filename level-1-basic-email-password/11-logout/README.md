# 11. Logout

## Notes

### What is logout, really?

Most beginners think logout means "delete the cookie". That's only **half** of it. The browser forgets the session ID, but if the **server** still remembers it, anyone who copied that ID (an XSS bug, a shared computer, malware) can keep using the account.

In topic 09 we saw that sessions make real logout possible. This topic is how to do it **properly**.

> **One-line answer:** logout = **delete the session on the server** (so the ID is dead everywhere) **+ clear the cookie in the browser**, done with a **POST**, and it should also let the user log out **other devices**.

---

### Why does it matter?

| If you get it wrong… | What happens |
|---|---|
| Only the cookie is deleted | A stolen copy of the session ID **still works** |
| Logout is a `GET` link | Any website can log your users out with `<img src="yoursite.com/logout">` |
| The cookie is cleared with a different `Path` | The browser keeps the old cookie, and the user is **still logged in** |
| Pages are cached | After logout, the **Back** button shows private pages |
| No "log out all devices" | Rahul loses his phone and can't kick it out of his account |
| Logout errors when there's no session | Double-clicks and expired sessions show scary errors |

---

### Real-life example: a hotel key card 🏨

Rahul stays at a hotel in Goa. He gets a **key card** for room 204.

1. Checking in → **login**: the front desk programs a card (session ID) and records it in their system (session store)
2. Every time he opens the door, the lock **asks the system** if the card is valid → every request **looks up the session**
3. Checking out → **logout**: the front desk **deactivates the card in the system**. Throwing the card in the bin isn't enough, because a copy would still open the door
4. Rahul left a second card in his bag at the restaurant → he asks the desk to **cancel all cards** for room 204 → **log out all devices**
5. "I'm checking out" is something Rahul **does at the desk**, not something that happens because a stranger shouted "204 checks out!" in the lobby → logout is a **POST**, protected from other sites

---

### The flow, step by step

#### 📊 Diagrams

Open **[diagrams.html](diagrams.html)** in your browser (just double-click the file) to see:

- **Flow diagram**: every step the server takes on `POST /logout`
- **Data flow**: Rahul logs in on a laptop and a phone, logs out the laptop (a stolen copy of the cookie dies too), then logs out the phone from the "my devices" list
- **Cookie only vs real logout**: why deleting just the cookie isn't enough

In short: `POST /logout → find the session → delete it on the server → clear the cookie (same name + path) → Clear-Site-Data → 200 "Logged out" (even if there was no session)`

#### Where does the session ID live after logout? 🔍

| Place | Before logout | After a **real** logout |
|---|---|---|
| Browser cookie | `sid=6ae3…0687` | Deleted (`Expires=1970`) |
| Server session store | `sha256(6ae3…)` → `{ userId, device }` | **Deleted** |
| A copy the attacker stole | Works ✅ | **Useless** ❌ (the server doesn't know it anymore) |
| localStorage / cached pages | May hold user data | Wiped by `Clear-Site-Data` and `Cache-Control: no-store` |

---

### Step 1: Logout must be a POST

```js
app.post("/logout", ...);                                                  // ✅
app.get("/logout", (req, res) => res.status(405).set("Allow", "POST")...); // ❌ refuse GET
```

| ❌ `GET /logout` | ✅ `POST /logout` |
|---|---|
| `<img src="yoursite.com/logout">` on **any** site logs your users out (**logout CSRF**) | Other sites can't send it with your cookie (`SameSite=Lax`, topic 10) |
| Browsers and link previews **prefetch** links, and logging out by accident | Never prefetched |
| Breaks the HTTP rule: GET must not change anything | Correct: it changes server state |

Logout CSRF sounds harmless ("so what, I'm logged out"), but attackers use it to log you out and then trick you into logging in to **their** account, so you type your card details into the attacker's account.

As **defense in depth**, our demo also refuses any POST whose `Origin` header is another site:

```js
if (origin && origin !== BASE_URL) return res.status(403).json({ error: "Request from another site was blocked" });
```

---

### Step 2: Delete the session on the server

```js
if (req.sessionKey) sessions.delete(req.sessionKey);
```

This is the step that **actually logs you out**. Once it's gone, the session ID is just a random string. That's the big advantage of sessions over JWTs: with a JWT (Level 3) the token keeps working until it expires, unless you build a deny-list.

---

### Step 3: Clear the cookie with the SAME options

```js
res.clearCookie("sid", { httpOnly: true, sameSite: "lax", path: "/", secure: isProduction });
```

`clearCookie` sends `Set-Cookie: sid=; Expires=Thu, 01 Jan 1970…`, a cookie that's already expired, so the browser deletes it.

⚠️ The browser identifies a cookie by **name + domain + path**. If you set it with `Path=/` and clear it with `Path=/api`, the browser thinks it's a **different** cookie and keeps the old one. Keep the options in **one constant** and use it for both `res.cookie` and `res.clearCookie`.

---

### Step 4 (bonus): `Clear-Site-Data`

```js
res.set("Clear-Site-Data", '"cookies", "storage"');
```

This header asks the browser to wipe **everything** this site stored: cookies, `localStorage`, `sessionStorage`, IndexedDB. Useful if your frontend keeps user data (a cart, a draft, cached profile) in storage, so the next person on a shared computer doesn't see it.

| Value | Clears |
|---|---|
| `"cookies"` | All cookies of this site |
| `"storage"` | localStorage, sessionStorage, IndexedDB, service worker caches |
| `"cache"` | The HTTP cache (can be slow: use with care) |

It only works over HTTPS (and on `localhost`). Treat it as an extra, not a replacement for steps 2 and 3.

Also send `Cache-Control: no-store` on private pages, so the **Back** button after logout can't show them from the browser cache.

---

### Step 5: Logging out twice is not an error

The user double-clicks "Log out", or their session already expired, or they're on two tabs. Logout should **always** answer `200 "Logged out"`, whether there was a session or not. The goal is "you are logged out", and that's true.

(This is called **idempotent**: doing it twice has the same result as doing it once.)

---

### Step 6: Log out other devices

Gmail, Netflix and Instagram all show "**Where you're logged in**". It's easy with sessions:

| Action | Endpoint | What the server does |
|---|---|---|
| See my devices | `GET /sessions` | List my sessions (device, time, "this device") |
| Log out one device | `DELETE /sessions/:id` | Delete that session, **only if it's mine** |
| Log out everywhere | `POST /logout-all` | Delete **every** session with my `userId` |

Two rules:
- Show a **separate public id** for each session in the list, **never** the session ID itself (that's the secret in the cookie).
- Check that the session **belongs to the logged-in user** before deleting it. Otherwise anyone could log anyone out by guessing ids (an **IDOR** bug, Level 4).

When to log out everywhere automatically: after a **password reset** (topic 13), a **password change** (topic 14, usually keep the current device), or when the account is disabled (topic 17).

---

### Step 7: The frontend's part

The server did the important work. The frontend should:

1. Call `POST /logout` (with `credentials: "include"` if the API is on another origin)
2. Clear any user data kept in memory (React state, Redux, query caches)
3. Redirect to the login or home page with `location.replace("/login")`, so **Back** doesn't return to the private page
4. If you have several tabs open, tell them too (a `BroadcastChannel` or a `storage` event), so they don't keep showing private data

---

### 🤔 Tricky parts

**1. "Log out" with JWTs.**
A JWT is checked by its signature, not looked up, so deleting it in the browser doesn't kill a stolen copy. Fixes (Level 3): short-lived access tokens + **revoking the refresh token**, or a deny-list of token ids until they expire.

**2. Session fixation.**
If the same session ID survives from "logged out" to "logged in", an attacker who planted an ID before login now shares the session. Always create a **new** session ID on login (our demo deletes any old session first).

**3. Automatic logout.**
Not every logout is a button: **idle timeout** and **absolute timeout** (topic 09) log users out too. Banking apps show a "You'll be logged out in 60 s" warning.

**4. "Remember me".**
A long-lived remember-me cookie (topic 15) must be deleted **and revoked** on logout too, or the user is logged straight back in.

---

### Common beginner mistakes

1. **Only deleting the cookie.**
   A stolen copy still works. Delete the session on the server.

2. **Logout as a GET link.**
   Any site can log your users out with an image tag, and browsers may prefetch it. Use POST.

3. **Clearing the cookie with different options.**
   A different `Path` or `Domain` creates a second cookie and leaves the real one. Reuse the same options.

4. **Returning an error when there's no session.**
   Logout should always succeed.

5. **Showing the real session ID in "my devices".**
   That's a working login. Show a separate public id.

6. **Not checking ownership in `DELETE /sessions/:id`.**
   Anyone could log out anyone. Check `session.userId === me`.

7. **Caching private pages.**
   The Back button shows them after logout. Send `Cache-Control: no-store`.

8. **Not logging out other devices after a password reset.**
   The attacker stays logged in (topic 13).

9. **Keeping user data in localStorage after logout.**
   The next person on a shared computer sees it. Clear it, or send `Clear-Site-Data`.

10. **Reusing the same session ID after logging in again.**
    Session fixation. Always issue a new one.

---

### Interview questions

1. **What does a proper logout do?**
   Deletes the session on the server, clears the cookie in the browser with the same name, path and domain, and returns success even if there was no session.

2. **Why isn't deleting the cookie enough?**
   Anyone who copied the session ID can still use it, because the server still knows it. Deleting the server session makes every copy useless.

3. **Why should logout be POST and not GET?**
   GET can be triggered by other sites (`<img>`), prefetched by browsers, and must not change state. POST with `SameSite` cookies and an Origin check is protected from CSRF.

4. **How do you implement "log out of all devices"?**
   Delete every session row with that `userId`. With JWTs, revoke the refresh tokens, or reject tokens issued before a stored `tokensValidAfter` time.

5. **How does logout work with JWTs?**
   The token can't be deleted from the server, because nothing is stored. Use short-lived access tokens + revoke the refresh token, or keep a deny-list of token ids (`jti`) until they expire.

6. **What does `Clear-Site-Data` do?**
   It tells the browser to delete the site's cookies, storage and/or cache. Useful on logout so no user data stays behind on shared computers.

7. **Why does the Back button sometimes show a private page after logout, and how do you stop it?**
   The page came from the browser cache. Send `Cache-Control: no-store` on private pages, and redirect with `location.replace`.

8. **What's logout CSRF, and why does it matter?**
   Another site logs the user out without asking. It's a building block for login CSRF, where the user is then logged into the attacker's account.

---

### Quick recap

- Logout = **delete the server session** + **clear the cookie**
- **POST only**: refuse GET with `405`, check `Origin`, rely on `SameSite`
- Clear the cookie with the **same name + path + domain** (one shared options object)
- Extras: **`Clear-Site-Data`**, **`Cache-Control: no-store`**, `location.replace` on the frontend
- Logging out twice is fine: **always `200`**
- **My devices** list with public ids → log out **one** device (check it's yours) or **all** devices
- Log out everywhere after a **password reset**, and always issue a **new** session ID on login

## Code

A small **Express** API (plus Node's built-in `crypto` for session IDs and hashing): sign up, log in on a "laptop" and a "phone", see your devices, log out properly, and watch a stolen copy of the cookie stop working. Users and sessions are kept in memory, so they disappear when you restart.

📄 **Full code: [server.js](server.js)**. Open it and read the comments, which follow the same steps as the notes above.

Install Express once (from this folder), then start the server:

```bash
npm install
```

```bash
node server.js
```

> Port 3000 busy? Run it on another port: `PORT=3011 node server.js` (Git Bash), then use that port in the commands below.

### Try it

In these commands, `-c file.txt` saves the cookie a "device" gets, `-b file.txt` sends it back (like a browser), and `-A "..."` sets the device name.

✅ **Sign up, then log in on a laptop and a phone:**

```bash
curl -X POST http://localhost:3000/signup -H "Content-Type: application/json" -d '{"email":"rahul@mail.com","password":"correct horse battery"}'
```

```bash
curl -i -c laptop.txt -A "Laptop Chrome" -X POST http://localhost:3000/login -H "Content-Type: application/json" -d '{"email":"rahul@mail.com","password":"correct horse battery"}'
```
→ `200 OK` with `Set-Cookie: sid=6ae362af...0687; Max-Age=28800; Path=/; Expires=...; HttpOnly; SameSite=Lax`

```bash
curl -c phone.txt -A "Phone Safari" -X POST http://localhost:3000/login -H "Content-Type: application/json" -d '{"email":"rahul@mail.com","password":"correct horse battery"}'
```

✅ **See where you're logged in:**

```bash
curl -b laptop.txt http://localhost:3000/sessions
```
→ `[{"id":"c22d9998-...","device":"Laptop Chrome","createdAt":"...","current":true},{"id":"d27e33f2-...","device":"Phone Safari","createdAt":"...","current":false}]`

🕵️ **Pretend an attacker copied the laptop's cookie:**

```bash
cp laptop.txt stolen.txt
```

❌ **Logout with GET is refused:**

```bash
curl -i -b laptop.txt http://localhost:3000/logout
```
→ `405 Method Not Allowed`, `Allow: POST`, `{"error":"Use POST /logout"}`

🛡️ **A logout request from another site is blocked:**

```bash
curl -i -b laptop.txt -H "Origin: http://evil.com" -X POST http://localhost:3000/logout
```
→ `403 Forbidden` with `{"error":"Request from another site was blocked"}`

✅ **Log out the laptop:**

```bash
curl -i -b laptop.txt -c laptop.txt -X POST http://localhost:3000/logout
```
→ `200 OK` with
```
Set-Cookie: sid=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; SameSite=Lax
Clear-Site-Data: "cookies", "storage"
{"message":"Logged out"}
```

🚪 **The stolen copy is dead too**, because the server deleted the session:

```bash
curl -i -b stolen.txt http://localhost:3000/me
```
→ `401 Unauthorized` with `{"error":"Not logged in"}`

✅ **Logging out again is fine:**

```bash
curl -i -b stolen.txt -X POST http://localhost:3000/logout
```
→ `200 OK` with `{"message":"Logged out"}`

📱 **The phone is still logged in** (logout only ends this device):

```bash
curl -b phone.txt http://localhost:3000/me
```
→ `{"id":"...","email":"rahul@mail.com","device":"Phone Safari"}`

✅ **Log out the phone from the laptop:** log the laptop in again, list the sessions, copy the phone's `id`, then delete it.

```bash
curl -c laptop.txt -A "Laptop Chrome" -X POST http://localhost:3000/login -H "Content-Type: application/json" -d '{"email":"rahul@mail.com","password":"correct horse battery"}'
```

```bash
curl -b laptop.txt -X DELETE http://localhost:3000/sessions/PASTE_PHONE_ID_HERE
```
→ `{"message":"Logged out: Phone Safari"}`. Now `curl -i -b phone.txt http://localhost:3000/me` → `401`.

✅ **Log out of all devices:** log the phone in again, then:

```bash
curl -b phone.txt -X POST http://localhost:3000/logout-all
```
→ `{"message":"Logged out of 2 device(s)"}`. Both `laptop.txt` and `phone.txt` now get `401` on `/me`.

> **Windows PowerShell users:** the single quotes in the `-d '...'` part and `PORT=3011 node ...` work in Git Bash. In PowerShell, use Git Bash, Postman, or set the variable with `$env:PORT=3011; node server.js`.
