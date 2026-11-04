# 02. HTTP Basics: Stateless, Headers, Cookies, 401 vs 403

## Notes

### Why learn this before auth?

Every login, session, and token you'll build later rides on top of **HTTP**. If you understand these four ideas, the rest of auth becomes much easier:

1. HTTP is **stateless**: the server forgets you after every request
2. **Headers** carry extra information, like "here's my login token"
3. **Cookies** are how a browser "reminds" the server who you are
4. **Status codes** tell the client what happened (200 OK, 401, 403, ...)

---

### 1. What is HTTP? (request and response)

HTTP is just a **conversation** between a client (browser, mobile app, Postman) and a server.

The client **asks** (request) → the server **answers** (response). That's it.

```
Client (browser)                         Server
     │                                      │
     │  ── Request: "GET /profile" ──────►  │
     │                                      │
     │  ◄── Response: "200 OK + your data"  │
     │                                      │
```

A **request** has:

| Part | Example | Meaning |
|---|---|---|
| Method | `GET`, `POST`, `PUT`, `DELETE` | What you want to do |
| URL / path | `/profile` | Which thing you want |
| Headers | `Authorization: Bearer abc123` | Extra info about the request |
| Body (optional) | `{ "email": "a@b.com" }` | Data you're sending |

A **response** has:

| Part | Example | Meaning |
|---|---|---|
| Status code | `200`, `401`, `404` | Did it work? |
| Headers | `Set-Cookie: sessionId=xyz` | Extra info about the response |
| Body | `{ "name": "Rahul" }` | The actual data |

---

### 2. Stateless: the server has no memory

**Stateless** means: **each request is completely independent.** The server does **not** remember anything about your previous request.

#### Real-life example: a forgetful shopkeeper

Imagine a shopkeeper with zero memory:

> **You:** "Hi, I'm Rahul, I have an account here."
> **Shopkeeper:** "OK, welcome Rahul!"
> *(5 seconds later)*
> **You:** "Can I see my order history?"
> **Shopkeeper:** "Who are you? I've never seen you before." 🤷

That's HTTP. You logged in on request #1, but on request #2 the server has **no idea** it's you.

#### So how does login work at all?

You have to **prove who you are on every single request**. Since the server can't remember you, **you carry the proof with you**:

> **You:** "Can I see my order history? *Here's the token you gave me earlier.*"
> **Shopkeeper:** *(checks token)* "Ah, Rahul! Here you go."

That "token" is usually sent in one of two ways:
- a **cookie** (the browser sends it automatically), or
- an **`Authorization` header** (your code adds it to each request)

👉 **This is the whole reason sessions, cookies, and JWTs exist.** They are tricks to make a forgetful (stateless) protocol remember who you are.

#### Why is HTTP stateless? Isn't that annoying?

It's actually a good design:
- **Simple**: the server doesn't have to track millions of open conversations
- **Scalable**: any server in a group can handle any request, because no server is "holding" your conversation

---

### 3. Headers: notes stuck on the envelope

Think of an HTTP request as a **letter in an envelope**:
- The **body** is the letter inside
- The **headers** are notes written on the **outside of the envelope**: who it's from, what's inside, how to handle it

Headers are simple `Name: value` pairs:

```
GET /profile HTTP/1.1
Host: api.example.com
Authorization: Bearer eyJhbGciOi...
Content-Type: application/json
Cookie: sessionId=abc123
```

#### Headers you'll see a lot in auth

| Header | Sent by | What it does |
|---|---|---|
| `Authorization` | Client | Carries login proof, e.g. `Bearer <token>` or `Basic <base64>` |
| `Cookie` | Client (browser, automatically) | Sends back cookies the server set earlier |
| `Set-Cookie` | Server | Tells the browser "save this cookie" |
| `WWW-Authenticate` | Server | Sent with a 401 to say *how* to log in (e.g. `Basic`, `Bearer`) |
| `Content-Type` | Both | Format of the body, e.g. `application/json` |
| `Origin` | Browser | Which website sent the request (important for CORS and CSRF later) |

---

### 4. Cookies: the server's "sticky note" on your browser

A **cookie** is a small piece of text that the **server asks the browser to store**. After that, the browser **automatically sends it back** on every request to that same website.

#### Real-life example: a cinema wristband

1. You buy a ticket at the counter (**login**).
2. They put a **wristband** on you (**server sets a cookie**).
3. Every time you walk back into the hall, the staff just look at the wristband (**browser sends the cookie**). You don't buy a new ticket each time.

#### How it works step by step

```
Browser                                       Server
   │                                             │
   │ ── POST /login  (email + password) ──────►  │  checks password ✅
   │                                             │
   │ ◄── 200 OK                                  │
   │     Set-Cookie: sessionId=abc123            │  "Browser, please save this"
   │                                             │
   │   (browser saves sessionId=abc123)          │
   │                                             │
   │ ── GET /profile                             │
   │    Cookie: sessionId=abc123 ─────────────►  │  "abc123 = Rahul" ✅
   │                                             │
   │ ◄── 200 OK  { name: "Rahul" }               │
```

Key points:
- The **server** creates the cookie using the `Set-Cookie` header.
- The **browser** stores it and sends it back using the `Cookie` header, **automatically**. Your frontend code doesn't have to do anything.
- Cookies belong to a **domain**. A cookie from `bank.com` is never sent to `evil.com`.

#### Cookie safety flags (just a preview)

When setting a cookie, the server can add flags to make it safer:

```
Set-Cookie: sessionId=abc123; HttpOnly; Secure; SameSite=Lax; Max-Age=3600
```

| Flag | Simple meaning |
|---|---|
| `HttpOnly` | JavaScript can't read it, so it's safer from XSS attacks |
| `Secure` | Only sent over HTTPS |
| `SameSite` | Limits sending it from other websites, which helps against CSRF |
| `Max-Age` / `Expires` | When the cookie should be deleted |

*(Topic 10 covers each flag in detail.)*

#### Cookie vs Authorization header

| | Cookie | `Authorization` header |
|---|---|---|
| Who sends it? | Browser, **automatically** | **Your code** adds it manually |
| Best for | Websites (browsers) | Mobile apps, APIs, server-to-server |
| Main risk | CSRF (sent automatically, even when you didn't mean to) | Token theft if stored in `localStorage` (XSS) |

---

### 5. Status codes: the server's answer in one number

Every response starts with a **3-digit number** that says what happened. You only need to remember the **first digit**:

| Range | Meaning | Simple version |
|---|---|---|
| **2xx** | Success | "Done ✅" |
| **3xx** | Redirect | "Go look over there ➡️" |
| **4xx** | Client error | "**You** did something wrong ❌" |
| **5xx** | Server error | "**I** (the server) broke 💥" |

#### Codes you'll use in auth

| Code | Name | When to use it |
|---|---|---|
| `200` | OK | Login worked, here's the data |
| `201` | Created | Signup worked, new user created |
| `204` | No Content | Logout worked, nothing to send back |
| `302` | Found (redirect) | Send the user to `/login` or back to the app after login |
| `400` | Bad Request | Missing email, invalid JSON, password too short |
| `401` | Unauthorized | Not logged in, or wrong/expired token |
| `403` | Forbidden | Logged in, but not allowed |
| `404` | Not Found | The thing doesn't exist (or you're hiding that it exists) |
| `409` | Conflict | Signup with an email that's already registered |
| `429` | Too Many Requests | Too many login attempts, slow down (rate limiting) |
| `500` | Internal Server Error | Bug in your server code |

---

### 6. 401 vs 403: the most confused pair

Remember from topic 01: **authentication** = who are you, **authorization** = what can you do.

| | 401 Unauthorized | 403 Forbidden |
|---|---|---|
| Real meaning | "I **don't know** who you are" | "I **know** who you are, but **no**" |
| Related to | Authentication | Authorization |
| Common cause | No token, wrong password, expired token | Normal user trying an admin route |
| Will logging in help? | **Yes**, log in and try again | **No**, you're already logged in, you just don't have permission |

#### Real-life example: a nightclub

- You walk up with **no ID** → bouncer says "Show me your ID first." → **401**
- You show your ID, but you're on the **guest list for a different party** → "I know who you are, but you can't come in." → **403**

#### Quick decision guide

```
Did the request include valid login proof (token/cookie)?
        │
        ├── No / invalid / expired ──► 401
        │
        └── Yes ──► Is this user allowed to do this action?
                          │
                          ├── No  ──► 403
                          └── Yes ──► 200 ✅
```

#### Bonus: sometimes 404 is better than 403

If user A asks for `/orders/999` and that order belongs to user B, returning **403** tells A "this order exists, you just can't see it." Big apps like GitHub return **404** instead, so attackers can't even discover what exists.

---

### Common beginner mistakes

1. **Thinking the server "remembers" you after login.**
   It doesn't. HTTP is stateless. Every request must carry a cookie or token.

2. **Returning 200 with `{ "error": "not logged in" }`.**
   Use the correct status code (401). Frontends, browsers, and tools all depend on it.

3. **Using 403 when the user simply isn't logged in.**
   No valid login means **401**. Logged in but not allowed means **403**.

4. **Saying "wrong password" vs "user not found" separately.**
   That tells attackers which emails are registered. Use one message for both: `401 Invalid email or password`.

5. **Setting auth cookies without `HttpOnly` and `Secure`.**
   This makes stealing them much easier.

6. **Returning 500 for bad user input.**
   If the user sent bad data, that's **4xx** (their mistake), not **5xx** (your mistake).

---

### Interview questions

1. **What does "HTTP is stateless" mean?**
   Each request is independent. The server doesn't remember earlier requests, so the client must send its identity (cookie or token) every time.

2. **If HTTP is stateless, how do websites keep you logged in?**
   After login, the server gives the client a session ID (in a cookie) or a token (like a JWT). The client sends it with every request, and the server uses it to identify the user.

3. **What's the difference between `Set-Cookie` and `Cookie` headers?**
   `Set-Cookie` is sent by the **server** in a response to store a cookie. `Cookie` is sent by the **browser** in requests to return it.

4. **401 vs 403?**
   401: not authenticated (missing or invalid credentials), and logging in may fix it. 403: authenticated but not permitted, and logging in again won't help.

5. **Cookie vs Authorization header for sending tokens?**
   Cookies are sent automatically by browsers (convenient, but need CSRF protection). The Authorization header is added by code (common for APIs and mobile apps, and not vulnerable to CSRF).

6. **What's the difference between 4xx and 5xx?**
   4xx means the client made a mistake. 5xx means the server failed.

---

### Quick recap

- **HTTP** = request + response. Each request has a method, URL, headers, and body.
- **Stateless** = the server forgets you after every request, so **you must send proof every time**.
- **Headers** = extra info. In auth, the big ones are `Authorization`, `Cookie`, and `Set-Cookie`.
- **Cookies** = the server stores a small value in your browser, and the browser sends it back automatically.
- **Status codes**: 2xx ok, 3xx redirect, 4xx your fault, 5xx server's fault.
- **401** = "Who are you?" **403** = "I know you, and the answer is no."

## Code

A tiny server using plain Node.js (no libraries) that shows statelessness, cookies, and 401/403 together.

```js
// server.js
const http = require("http");

const sessions = {}; // sessionId -> user (the server's "memory" lives here, not in HTTP)

http.createServer((req, res) => {
  // Read the Cookie header: "sessionId=abc123" -> "abc123"
  const sessionId = (req.headers.cookie || "").match(/sessionId=(\w+)/)?.[1];
  const user = sessions[sessionId];

  if (req.url === "/login") {
    const id = Math.random().toString(36).slice(2);
    sessions[id] = { name: "Rahul", role: "user" };
    res.writeHead(200, { "Set-Cookie": `sessionId=${id}; HttpOnly; SameSite=Lax` });
    return res.end("Logged in. Cookie set!");
  }

  if (!user) {
    res.writeHead(401);
    return res.end("401: Who are you? Please log in.");
  }

  if (req.url === "/admin" && user.role !== "admin") {
    res.writeHead(403);
    return res.end(`403: I know you, ${user.name}, but admins only.`);
  }

  res.end(`200: Hello ${user.name}!`);
}).listen(3000, () => console.log("Running on http://localhost:3000"));
```

Try it (`-c` saves cookies to a file and `-b` sends them back, just like a browser):

```bash
node server.js
```

```bash
curl -i http://localhost:3000/profile
```
→ `401` because no cookie was sent, so the server doesn't know you.

```bash
curl -i -c cookies.txt http://localhost:3000/login
```
→ `200` and look for the `Set-Cookie` header in the response.

```bash
curl -b cookies.txt http://localhost:3000/profile
```
→ `200: Hello Rahul!` because the cookie proved who you are.

```bash
curl -b cookies.txt http://localhost:3000/admin
```
→ `403` because you're logged in, but not an admin.
