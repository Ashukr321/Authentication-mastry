# 08. HTTP Basic Auth

## Notes

### What is HTTP Basic Auth?

**HTTP Basic Auth** is the **oldest and simplest** way to log in over HTTP. It's built into every browser, every HTTP library, and `curl`.

The idea fits in one line:

> **Send your username and password with *every single request*, inside the `Authorization` header.**

```
Authorization: Basic cmFodWw6Y29ycmVjdCBob3JzZSBiYXR0ZXJ5
```

There's **no login page**, **no session**, and **no cookie**. Remember from topic 02 that HTTP is **stateless**. Basic Auth doesn't fight that at all. It just proves who you are again on every request.

---

### Real-life example: a building with a guard at every door 🚪

Imagine an office where there's **no ID badge**. Instead, **every door** has a guard, and at every single door you must say your **name and secret password** out loud.

- ✅ Very simple, with nothing to carry
- ❌ You repeat your password **hundreds of times a day**
- ❌ If anyone overhears it **even once**, they can walk through every door as you
- ❌ There's no way to "hand back your badge" (no real logout)

Compare that with **login + session** (topic 07): you show your ID **once** at the front gate and get a **wristband**. After that, you only show the wristband.

---

### How the header is built

```
Step 1: Join username and password with a colon
        rahul  +  ":"  +  correct horse battery
        → "rahul:correct horse battery"

Step 2: Base64-encode it
        → "cmFodWw6Y29ycmVjdCBob3JzZSBiYXR0ZXJ5"

Step 3: Put it in the header with the word "Basic"
        → Authorization: Basic cmFodWw6Y29ycmVjdCBob3JzZSBiYXR0ZXJ5
```

In JavaScript:

```js
const header = "Basic " + Buffer.from("rahul:correct horse battery").toString("base64");
```

---

### ⚠️ Base64 is NOT encryption

You learned this in topic 03, but it matters most right here. **Anyone can decode it instantly:**

```bash
echo "cmFodWw6Y29ycmVjdCBob3JzZSBiYXR0ZXJ5" | base64 -d
```
→ `rahul:correct horse battery` 😱

Base64 is only there so that special characters can travel safely in a header. It gives **zero** security.

👉 **Basic Auth without HTTPS = sending your password as plain text.** HTTPS (topic 05) is **mandatory**, not optional.

---

### The challenge → response flow

#### 📊 Diagrams

Open **[diagrams.html](diagrams.html)** in your browser (just double-click the file) to see:

- **Flow diagram**: every check the server does on each request, and when it sends `401` or `200`
- **Data flow**: the browser popup, the header being sent, and the browser resending it automatically on every later request

In short: `request without header → 401 + WWW-Authenticate → browser popup → request with Authorization: Basic ... → 200 → browser resends the header on every request`

The two special headers:

| Header | Sent by | Meaning |
|---|---|---|
| `WWW-Authenticate: Basic realm="Admin area"` | **Server**, with a `401` | "You need to log in with Basic Auth. This protected area is called *Admin area*." |
| `Authorization: Basic <base64>` | **Client**, on every request | "Here are my username and password." |

**What's a realm?** Just a **name for the protected area**. The browser shows it in the popup, and it remembers credentials per realm. You can add `charset="UTF-8"` so non-English passwords work correctly:

```
WWW-Authenticate: Basic realm="Admin area", charset="UTF-8"
```

> ⚠️ If you return `401` **without** the `WWW-Authenticate` header, the browser **won't show the popup**. And `403` never shows it.

---

### What the server does on every request

```
1. Is there an "Authorization" header that starts with "Basic "?
      └── No → 401 + WWW-Authenticate
2. Base64-decode the rest            → "rahul:correct horse battery"
3. Split at the FIRST colon          → username = "rahul", password = "correct horse battery"
      └── no colon at all → 401
4. Find the user and verify the password hash (dummy hash if no user, as in topic 07)
      └── wrong → 401 + WWW-Authenticate
5. ✅ Allow the request
```

#### Why split at the FIRST colon?

The username **can't** contain a colon, but the **password can**:

```
"priya:pass:with:colons"
   │    └──────────────── password = "pass:with:colons"  ✅
   └── username = "priya"
```

If you do `value.split(":")`, you get `["priya", "pass", "with", "colons"]` and the password becomes just `"pass"`. ❌ Use `indexOf(":")` instead.

#### Same security rules as login (topic 07)

- **Hash the stored passwords** (argon2 / bcrypt / scrypt). Basic Auth doesn't change that.
- Use **constant-time comparison** (`crypto.timingSafeEqual` or the library's verify function), never `===`
- Use a **dummy hash** for unknown usernames, so response time doesn't reveal which usernames exist
- **Same `401` response** for "no such user" and "wrong password"

---

### 🐢 The hidden cost: hashing on every request

At login (topic 07), the slow password hash runs **once**. With Basic Auth, the password comes with **every request**, so the server must verify it **every time**:

```
1 page with 20 images/scripts = 20 requests × ~300 ms hashing each = 6 seconds of CPU 😬
```

This is why Basic Auth is usually used for:
- **Low-traffic** things (an admin page, a staging site)
- **Machine-to-machine** calls with a long, random API password. Here a fast compare (`timingSafeEqual` on a SHA-256 of the value) is acceptable, because a 32+ character random secret can't be guessed anyway. Slow hashing protects **human** passwords, which are weak.

---

### 🚪 The logout problem

Once the browser has your Basic Auth credentials, it **keeps sending them** until you **close the browser**. There's no standard "log out" button, because the server doesn't keep any session it could delete.

Tricks like "redirect to a URL with wrong credentials" work in some browsers but not others. **If you need logout, use sessions (topic 09) or tokens (Level 3).**

---

### When should you use Basic Auth?

| ✅ Good fit | ❌ Bad fit |
|---|---|
| Protecting a **staging / preview site** from the public | The login for your **real users** |
| Internal **admin tools** used by a few people | Apps that need **logout**, "remember me", or **MFA** |
| **Server-to-server** API calls with a random secret | Mobile apps and SPAs for customers |
| Package registries, CI tools, webhooks | Anything over **plain HTTP** |
| Quick testing with `curl -u` | High-traffic APIs that use human passwords |

Real-world examples: **Nginx `.htpasswd`** for protecting folders, private npm/Docker registries, and many APIs that accept `-u apiKey:` (Stripe's API, for example, accepts your secret key as the Basic Auth username).

---

### Basic Auth vs Session vs Bearer token

| | Basic Auth (this topic) | Session cookie (topic 09) | Bearer token / JWT (Level 3) |
|---|---|---|---|
| What's sent on each request | **Username + password** | Random session ID | Signed token |
| Header | `Authorization: Basic ...` | `Cookie: sessionId=...` | `Authorization: Bearer ...` |
| Server stores state? | ❌ No | ✅ Yes (session store) | ❌ No (usually) |
| Password sent how often? | **Every request** 😬 | Only once, at login | Only once, at login |
| Logout | ❌ Not really | ✅ Delete the session | ⚠️ Wait for it to expire, or keep a blocklist |
| Login page | Browser popup (ugly, can't style it) | Your own page | Your own page |
| Best for | Internal tools, scripts | Websites | APIs, mobile apps |

---

### Common beginner mistakes

1. **Thinking Base64 hides the password.**
   It's encoding, not encryption. Anyone can decode it.

2. **Using Basic Auth over plain HTTP.**
   The password is visible to everyone on the network. HTTPS only.

3. **Splitting on every colon** (`split(":")`).
   Passwords with colons break. Split at the **first** colon only.

4. **Forgetting the `WWW-Authenticate` header on 401.**
   The browser won't show the login popup.

5. **Returning `403` for missing or wrong credentials.**
   It's `401`: "I don't know who you are." (Topic 02)

6. **Comparing with `===`** or storing plain passwords for Basic Auth users.
   Same rules as login: hash + constant-time compare.

7. **Logging request headers.**
   `Authorization: Basic ...` in your logs is the same as logging the plain password. Remove or mask it.

8. **Putting credentials in the URL** (`https://rahul:secret@site.com`).
   URLs end up in history and logs, and modern browsers block or warn about this.

9. **Using it as the login system for a public app.**
   No logout, no MFA, ugly popup, and the password is sent on every request. Use sessions or tokens.

10. **No rate limiting.**
    Every request is a password guess. Attackers can try thousands per minute (topic 16).

---

### Interview questions

1. **How does HTTP Basic Auth work?**
   The client sends `Authorization: Basic base64(username:password)` with every request. If it's missing or wrong, the server returns `401` with a `WWW-Authenticate: Basic realm="..."` header.

2. **Is Basic Auth secure?**
   Only over HTTPS. Base64 is just encoding, so without TLS the password is effectively plain text. Even with HTTPS, it sends the password on every request and has no logout or MFA.

3. **What is the `WWW-Authenticate` header for?**
   The server sends it with a 401 to tell the client which authentication scheme to use (and the realm). Browsers use it to show their login popup.

4. **What's a realm?**
   A name for a protected area. Browsers show it in the popup and cache credentials per realm.

5. **Why is logout hard with Basic Auth?**
   The browser caches the credentials and resends them automatically, and there's no server-side session to destroy.

6. **Basic Auth vs Bearer token?**
   Basic sends the actual username and password every time. Bearer sends a token that was issued after login, which can expire, be limited in scope, and be revoked without changing the password.

7. **When would you still use Basic Auth today?**
   For staging sites, internal tools, server-to-server calls with random API secrets, private registries, and quick scripts. Always over HTTPS.

8. **How should the server parse the header?**
   Check the `Basic ` prefix, Base64-decode it, and split at the **first** colon (the password may contain colons). Then verify the password with a constant-time compare.

---

### Quick recap

- Basic Auth = `Authorization: Basic base64(username:password)` on **every request**
- **Base64 ≠ encryption**, so **HTTPS is mandatory**
- Missing or wrong credentials → **401** + `WWW-Authenticate: Basic realm="..."`, and the browser shows a popup
- Split at the **first colon**. Hash + constant-time compare + dummy hash, just like login.
- Downsides: **password sent every request**, hashing on every request, **no real logout**, no MFA, ugly popup
- Great for **internal tools, staging sites, and server-to-server** calls, not for your users' login

## Code

A small server with a public page and a protected `/admin` area, using only Node.js built-ins. It reuses the scrypt hashing and dummy-hash trick from topics 04 and 07.

📄 **Full code: [server.js](server.js)**. Open it and read the comments, which follow the same steps as "What the server does on every request" above.

> Demo users (made up for this example only): `rahul` / `correct horse battery`, and `priya` / `pass:with:colons` (a password with colons, to show why we split at the first one).

```bash
node server.js
```

### Try it

**1. Public page: no login needed**

```bash
curl -i http://localhost:3000/
```
→ `200` with `This page is public.`

**2. Protected page without credentials: the server sends a challenge**

```bash
curl -i http://localhost:3000/admin
```
→ `401 Unauthorized` with `WWW-Authenticate: Basic realm="Admin area", charset="UTF-8"`

**3. Log in with `-u` (curl builds the header for you)**

```bash
curl -i -u "rahul:correct horse battery" http://localhost:3000/admin
```
→ `200` with `Welcome to the admin area, rahul!`

**4. See the actual header curl sent**

```bash
curl -v -u "rahul:correct horse battery" http://localhost:3000/admin 2>&1 | grep -i "authorization"
```
→ `> Authorization: Basic cmFodWw6Y29ycmVjdCBob3JzZSBiYXR0ZXJ5`

**5. Decode it. This is why HTTPS is required!**

```bash
echo "cmFodWw6Y29ycmVjdCBob3JzZSBiYXR0ZXJ5" | base64 -d
```
→ `rahul:correct horse battery`

**6. Send the header yourself, without `-u`**

```bash
curl -i -H "Authorization: Basic cmFodWw6Y29ycmVjdCBob3JzZSBiYXR0ZXJ5" http://localhost:3000/admin
```
→ `200`. It's exactly the same as `-u`.

**7. A password with colons (split at the FIRST colon)**

```bash
curl -i -u "priya:pass:with:colons" http://localhost:3000/admin
```
→ `200` with `Welcome to the admin area, priya!`

**8. Wrong password vs unknown user: same answer, about the same time**

```bash
curl -s -w "  [%{http_code}] (%{time_total}s)\n" -u "rahul:wrong password" http://localhost:3000/admin
```

```bash
curl -s -w "  [%{http_code}] (%{time_total}s)\n" -u "nobody:wrong password" http://localhost:3000/admin
```
→ Both return `401` with `Invalid username or password`, in about the same time.

**9. Try it in a browser**

Open `http://localhost:3000/admin`. You'll see the browser's built-in login popup. Log in, refresh a few times (no popup, because the browser resends the header), and then try to "log out"... you can't, until you close the browser. That's the logout problem.
