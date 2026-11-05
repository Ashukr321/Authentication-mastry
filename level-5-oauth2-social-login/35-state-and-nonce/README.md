# 35. state & nonce

## Notes

### What are `state` and `nonce`?

In the OAuth / OpenID Connect redirect dance (topics 33, 34), the browser leaves your app, visits the provider, and comes back to your `/callback` with a `code`. Your callback has to answer one question: **"is this the login *this browser* started?"** Two random values answer it:

- **`state`**: you send it to `/authorize`, the provider sends it back **in the callback URL**, and you check it matches what you stored in **this browser's session**. It stops someone pushing **their** login into **your** browser (login CSRF).
- **`nonce`**: you send it to `/authorize`, the provider puts it **inside the signed ID token**, and you check it matches what you stored. It stops someone pushing **your** code or ID token into **their** browser (code / token injection and replay).

> **One-line answer:** for every login, generate a fresh random `state` and `nonce`, store both in the user's session, send both to `/authorize`. On the callback: **`state` from the URL must match the session** (else stop: login CSRF), and after the token exchange **`nonce` inside the verified ID token must match the session** (else stop: injected/replayed login). Both are one-use, short-lived and unguessable.

---

### Why does it matter?

| Missing check | Attack | Result |
|---|---|---|
| **`state`** | Vikram starts "Log in with PhotoVault" as **himself**, stops at the callback URL, and gets Rahul to open it (link, hidden `<img>`, auto-submitting page) | Rahul's browser is logged in to PrintKaro **as Vikram**. Rahul uploads photos, saves his address and card: into **Vikram's** account (**login CSRF**) |
| **`state`** on "Connect your account" | Same trick on an account-linking flow | Rahul's PrintKaro account gets linked to **Vikram's** PhotoVault: Vikram can now log in as Rahul with it (topic 40) |
| **`nonce`** (and no PKCE) | Vikram gets hold of Rahul's **unused** callback URL (malicious extension, proxy log, `Referer`), then calls the callback **in his own browser**, with **his own** valid `state` | Vikram's browser is logged in **as Rahul** (**code injection**) |
| **`nonce`** in flows that return the ID token in the URL | Vikram replays an ID token captured earlier | Logged in as the token's owner |

Both demos below run for real.

---

### Real-life example: a bank token number 🏦

Rahul goes to an SBI branch, takes token **#47** from the machine, and the machine also prints a **secret word**, "**mango**", on his slip.

- When **#47** is called, the clerk checks the slip in **Rahul's hand** says #47. If Vikram walks up and shoves **his** slip **#52** into Rahul's hand, the clerk says "you didn't take this token". → **`state`**: the callback must belong to the login this browser started
- The passbook the clerk hands over has "**mango**" printed **inside, under the bank's seal**. If Vikram somehow grabs Rahul's call and walks up with his own slip, the passbook inside says "mango" but Vikram's slip says "pineapple". → **`nonce`**: the signed result must belong to the login this browser started
- Tokens are thrown away once used, and only valid today. → one use, short-lived

---

### The flow, step by step

#### 📊 Diagrams

Open **[diagrams.html](diagrams.html)** in your browser (just double-click the file) to see:

- **Flow diagram**: the callback's checks, in order, and which attack each one stops
- **Data flow: login CSRF**: Vikram's callback URL opened in Rahul's browser, with and without `state`
- **Data flow: code injection**: Rahul's code used in Vikram's browser, with and without `nonce`

In short: `/login → state + nonce saved in the session → /authorize?state=..&nonce=.. → callback?code=..&state=.. → state in session? (else 400) → POST /token → id_token → verify signature, iss, aud, exp → id_token.nonce == session nonce? (else 400) → logged in (new session id) → go to the saved returnTo`.

---

### Step 1: Create both, store them in the session, send them

```js
const state = randomToken(16); // unguessable
const nonce = randomToken(16);
session.pending.set(state, { nonce, returnTo: "/orders", expiresAt: Date.now() + 10 * 60 * 1000 });
res.redirect(`${AUTH_URL}/authorize?response_type=code&client_id=printkaro&redirect_uri=...&scope=openid&state=${state}&nonce=${nonce}`);
```

| ✅ Do | ❌ Don't |
|---|---|
| `crypto.randomBytes(16+)`, new for **every** login | A constant, a counter, `Date.now()`, the user id |
| Store in the **server-side session** of this browser (or a signed, HttpOnly cookie) | Store nowhere and "check" that it's non-empty |
| A `Map` keyed by `state`, so two tabs can log in at once | One slot that the second tab overwrites |
| Keep `returnTo` **with** the state on the server, local paths only | Put a raw return URL in `state` and redirect to it (open redirect) |

---

### Step 2: Check `state` first, on the callback

```js
const pending = session.pending.get(req.query.state);
session.pending.delete(req.query.state);   // one use
if (!pending || pending.expiresAt < Date.now()) return res.status(400)...   // login CSRF stops here
```

- Check it **before** using the code. No match = this browser never started this login.
- The provider doesn't check `state` at all; it just sends it back. **Only the client can check it.**
- `SameSite=Lax` cookies don't save you here: the callback is a normal top-level GET navigation, so the cookie **is** sent.

---

### Step 3: Check `nonce` inside the verified ID token

```js
const claims = jwt.verify(id_token, key, { algorithms: ["HS256"], issuer: AUTH_URL, audience: "printkaro" }); // topic 27
if (claims.nonce !== pending.nonce) return res.status(400)...   // injected / replayed login stops here
```

- The nonce is **inside the signature**: an attacker can't change it without breaking the token.
- **Always verify the token first** (algorithm, signature, `iss`, `aud`, `exp`), then compare the nonce.
- Why `state` doesn't catch this attack: the attacker calls the callback in **their own** browser, with **their own** valid `state`. Only the nonce (or PKCE) ties the **result** to the **request**.

---

### Step 4: Finish the login safely

- **New session id** after login (topic 50: session fixation).
- Redirect to the **stored** `returnTo`, never to a URL from the callback query.
- Expire unused pending logins (10 minutes here).

---

### `state` vs `nonce` vs PKCE

| | `state` | `nonce` | PKCE (topic 34) |
|---|---|---|---|
| Spec | OAuth 2.0 | OpenID Connect | OAuth (RFC 7636) |
| Comes back in | Callback **URL** | **ID token** (signed) | Not returned: proven at `/token` |
| Checked by | Client, at the callback | Client, after the token exchange | **Authorization server**, at `/token` |
| Stops | Login CSRF (their login in your browser) | Code / ID token injection and replay (your login in their browser) | Code interception and code injection |
| Needed when | Always | Always with OpenID Connect (required if the ID token comes from the front channel) | Always (OAuth 2.1) |

Modern advice (RFC 9700): use **PKCE** for every client, and keep using **`state`** for CSRF (or rely on PKCE's protection only if you are sure the server enforces it) and **`nonce`** for OpenID Connect. They're cheap, so use all three.

---

### 🤔 Tricky parts

**1. "Login CSRF" sounds harmless. It isn't.**
Being logged in as the **attacker** means everything you do next (save a card, upload ID documents, search history) lands in **their** account. With account linking (topic 40), it can give the attacker a permanent way into **your** account.

**2. `state` must be tied to the browser, not just "valid somewhere".**
A server that only checks "is this a state we issued?" across **all** users fails: Vikram's own state is valid. It must be **this session's** state.

**3. One use, short life.**
The demo deletes the state on first use, so opening the same callback URL twice fails, and expires unused ones after 10 minutes.

**4. Don't put data in `state` that you then trust.**
Some apps put `{"returnTo":"https://..."}` in `state`. If you do, it must be **signed** and **also** contain the random CSRF value, and `returnTo` must still be validated. Keeping it server-side is simpler.

**5. Nonce and refreshed ID tokens.**
ID tokens from a **refresh** don't have to carry the nonce. Check the nonce on the **login** response.

**6. Libraries do this for you, if you let them.**
Passport, Auth.js, `openid-client` generate and check `state`, `nonce` and PKCE automatically (topic 41). The bug is usually turning a check off ("state mismatch errors in dev, so I disabled it").

---

### Common beginner mistakes

1. **Not sending `state` at all**, or sending it but never checking it.
   Login CSRF.

2. **Using a fixed or guessable value** (`state=xyz`, a timestamp, the user id).
   Random, per login.

3. **Checking `state` against a global list** instead of this browser's session.
   The attacker's own state passes.

4. **Not deleting `state` after use.**
   Callback URLs can be replayed.

5. **Skipping the nonce because "we use the code flow".**
   Without PKCE, code injection works (demo, attack 2). With OpenID Connect, check it.

6. **Comparing the nonce before verifying the ID token's signature.**
   An unverified token's nonce means nothing.

7. **Putting a raw return URL in `state`** and redirecting to it.
   Open redirect. Store `returnTo` server-side, local paths only.

8. **Disabling the state check because "it fails in development".**
   Usually the session cookie isn't being kept (different domain, port, or `SameSite=Strict`). Fix the cookie.

---

### Interview questions

1. **What is the OAuth `state` parameter for?**
   A random, one-time value the client stores in the user's session and sends to `/authorize`; the provider returns it in the callback, and the client checks it matches. It prevents CSRF on the callback (login CSRF / forced account linking).

2. **What is login CSRF?**
   An attacker makes the victim's browser complete the attacker's login, so the victim ends up signed in to the attacker's account and their actions/data go there.

3. **What is the `nonce` in OpenID Connect?**
   A random value the client sends in the authorization request; the provider puts it in the ID token; the client checks it matches the session. It binds the ID token to this login request and prevents replay and injection.

4. **Why isn't `state` enough against code injection?**
   The attacker uses the stolen code in their own browser with their own valid state, so the state check passes. The nonce (or PKCE) ties the token to the original request.

5. **State vs nonce vs PKCE?**
   State: CSRF on the callback, checked by the client from the URL. Nonce: binds the ID token to the request, checked by the client inside the token. PKCE: binds the code to the client instance, checked by the authorization server at `/token`.

6. **Where should state and nonce be stored?**
   In the server-side session of the browser that started the login (or a signed, HttpOnly, short-lived cookie), keyed so multiple tabs work.

7. **Should state be reused?**
   No. New for every login, deleted after one use, short expiry.

8. **Can you put the return URL in state?**
   Only if it's signed and validated; simpler to keep it server-side next to the state and only allow local paths.

---

### Quick recap

- Fresh random **`state`** and **`nonce`** for **every** login, stored in **this browser's session**
- Callback: **`state`** from the URL must match → stops **login CSRF**
- After `/token`: **verify the ID token**, then **`nonce`** inside it must match → stops **code/token injection and replay**
- **One use**, **short expiry**, a `Map` keyed by state for multiple tabs
- Keep `returnTo` server-side, local paths only; new session id after login
- Use **PKCE** too (topic 34); libraries do all three, so don't switch them off
- Next: OpenID Connect and the ID token in detail (topic 36)

## Code

One **Express** file, two apps: **PrintKaro** (client, offers "Log in with PhotoVault") on port 3000 and **PhotoVault Accounts** (authorization server, issues codes and signed ID tokens with `jsonwebtoken`) on port 3001.

PrintKaro's callback runs in **three versions** so you can attack and compare:

| `?variant=` | Callback path | Checks `state` | Checks `nonce` |
|---|---|---|---|
| `safe` (default) | `/callback` | ✅ | ✅ |
| `naive` | `/buggy/naive/callback` | ❌ | ❌ |
| `no-nonce` | `/buggy/no-nonce/callback` | ✅ | ❌ |

Users at PhotoVault: `rahul` (the victim) and `vikram` (the attacker), both with password `chai1234`. PKCE is deliberately left out, so you can see what `state` and `nonce` do on their own.

📄 **Full code: [server.js](server.js)**. Open it and read the comments, which follow the same steps as the notes above.

Install the dependencies once (from this folder), then start the server:

```bash
npm install
```

```bash
node server.js
```

> Port 3000 busy? Run it on other ports: `PORT=3035 node server.js` (Git Bash) uses **3035** and **3036**. The outputs below were recorded that way, so they show those ports.

### Try it (Git Bash)

Each `*.jar` file is one browser's cookies: `r` = Rahul's browser, `v` = Vikram's browser.

```bash
C=http://localhost:3000; AS=http://localhost:3001
red() { curl -s -o /dev/null -w "%{redirect_url}" "$@"; }   # print where a redirect goes, without following it
curl -s -c r_as.jar $AS/login -H "Content-Type: application/json" -d '{"username":"rahul","password":"chai1234"}'
curl -s -c v_as.jar $AS/login -H "Content-Type: application/json" -d '{"username":"vikram","password":"chai1234"}'
```

✅ **A normal login** (Rahul, safe callback, wants to land on `/orders`):

```bash
L=$(red -c r.jar -b r.jar "$C/login?returnTo=/orders"); echo "$L"
CB=$(red -b r_as.jar "$L"); echo "$CB"
curl -s -c r.jar -b r.jar -o /dev/null -w "%{http_code} %{redirect_url}\n" "$CB"
curl -s -b r.jar $C/orders
```
→
```
http://localhost:3036/authorize?response_type=code&client_id=printkaro&redirect_uri=http%3A%2F%2Flocalhost%3A3035%2Fcallback&scope=openid&state=jDQzux0kyMxRt37aSqYkDw&nonce=CRa3y5EIGUq9f2dsAh4erg
http://localhost:3035/callback?code=rZOVO9lg5ZowezWiXlGVnHMItl59AEDG7PVEaJUHq1k&state=jDQzux0kyMxRt37aSqYkDw
303 http://localhost:3035/orders
{"user":"u_rahul","orders":[],"note":"returnTo brought you here after login"}
```

Open the same callback again → `400 {"error":"This login didn't start in this browser (state mismatch). Please start again."}` (one use).
`/login?returnTo=//evil.example` → `400 {"error":"returnTo must be a local path"}`.

#### 🕵️ Attack 1: login CSRF (stopped by `state`)

Vikram starts a login **as himself** and keeps the callback URL **without opening it**:

```bash
L=$(red -c v.jar -b v.jar "$C/login?variant=naive"); CBV=$(red -b v_as.jar "$L"); echo "$CBV"
```
→ `http://localhost:3035/buggy/naive/callback?code=XHEtyDQZY3q2tpI-PZBWE-teVG07BgKypeiMKu2rOjI&state=HnKSSYrhYYH9JCsiOYSzXA`

He sends it to Rahul ("see the photos I printed for you!"). Rahul's fresh browser (`r2.jar`) opens it:

```bash
curl -s -c r2.jar -b r2.jar -o /dev/null -w "%{http_code} %{redirect_url}\n" "$CBV"
curl -s -b r2.jar $C/me
```
→
```
303 http://localhost:3035/me
{"loggedInAs":"u_vikram","name":"Vikram (attacker)"}      ← Rahul is now inside VIKRAM's account
```

The same attack on the **safe** callback (`$C/login` without `variant`, then Rahul opens Vikram's `/callback?...` URL):

```
{"error":"This login didn't start in this browser (state mismatch). Please start again."} 400
{"loggedInAs":null}
```
Terminal: `🚨 PrintKaro: state check failed (unknown or expired state): login refused`

#### 🕵️ Attack 2: code injection (stopped by `nonce`)

Rahul starts a login; Vikram intercepts the callback **before Rahul's browser uses it** (a malicious extension, a proxy log):

```bash
L=$(red -c r4.jar -b r4.jar "$C/login?variant=no-nonce"); CBR=$(red -b r_as.jar "$L"); echo "$CBR"
CODE_R=$(echo "$CBR" | sed 's/.*code=\([^&]*\).*/\1/')
```
→ `http://localhost:3035/buggy/no-nonce/callback?code=dnkTsYR38hDnHov0q8iijTbUv4tVmKBD8Fzy7xXG_Tw&state=dqo45iaMj70GA5uG4eTksw`

Vikram starts **his own** login in **his** browser, just to get **his own valid state**, and plugs Rahul's code into it:

```bash
LV=$(red -c v2.jar -b v2.jar "$C/login?variant=no-nonce"); STATE_V=$(echo "$LV" | sed 's/.*state=\([^&]*\).*/\1/')
curl -s -c v2.jar -b v2.jar -o /dev/null -w "%{http_code} %{redirect_url}\n" "$C/buggy/no-nonce/callback?code=$CODE_R&state=$STATE_V"
curl -s -b v2.jar $C/me
```
→
```
303 http://localhost:3035/me
{"loggedInAs":"u_rahul","name":"Rahul Sharma"}      ← the state check passed, and Vikram is now logged in AS RAHUL
```

The same attack on the **safe** callback (both logins start at `$C/login`, inject into `$C/callback`):

```
{"error":"This sign-in was not started here (nonce mismatch). Please start again."} 400
{"loggedInAs":null}
```
Terminal: `🚨 PrintKaro: nonce mismatch: ID token for u_rahul belongs to a different login: refused`

📋 **The whole terminal log:**

```
📸 AS: code for u_rahul → /callback (nonce CRa3y5…)
✅ PrintKaro (/callback): browser is now logged in as u_rahul
🚨 PrintKaro: state check failed (unknown or expired state): login refused
📸 AS: code for u_vikram → /buggy/naive/callback (nonce WWFfUz…)
✅ PrintKaro (/buggy/naive/callback): browser is now logged in as u_vikram
📸 AS: code for u_vikram → /callback (nonce Rdzwig…)
🚨 PrintKaro: state check failed (unknown or expired state): login refused
📸 AS: code for u_rahul → /buggy/no-nonce/callback (nonce d-WZAV…)
✅ PrintKaro (/buggy/no-nonce/callback): browser is now logged in as u_rahul
📸 AS: code for u_rahul → /callback (nonce hUPYx7…)
🚨 PrintKaro: nonce mismatch: ID token for u_rahul belongs to a different login: refused
```

> **Windows PowerShell users:** the variables, `red()`, cookie jars and `PORT=... node ...` work in Git Bash. In PowerShell, use Git Bash, or `$env:PORT=3035; node server.js`.
