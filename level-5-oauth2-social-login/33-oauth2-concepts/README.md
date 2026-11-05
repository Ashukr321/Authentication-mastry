# 33. OAuth 2.0 Concepts

## Notes

### What is OAuth 2.0?

Rahul keeps his photos in **PhotoVault** (think Google Photos). He wants **PrintKaro**, a photo printing website, to print some of them. The old, terrible way: give PrintKaro his PhotoVault **password**. Now PrintKaro can read his photos, delete them, change his password, forever, and if PrintKaro gets hacked, so does Rahul.

**OAuth 2.0** is the standard way to say: *"PhotoVault, please let **this app** do **this one thing** with my account, for **a while**"*, without ever giving the app your password.

> **One-line answer:** OAuth 2.0 is an **authorization (delegation) framework**: the user approves, on the **authorization server's own page**, a **client app** getting **limited access (scopes)** to their data on a **resource server**. The client gets a short-lived **access token** instead of the password. The usual flow is the **authorization code flow**: browser redirect → login + consent → **code** back to the app → app's server swaps the code for a **token** → app calls the API with `Authorization: Bearer <token>`.

OAuth is about **access**, not **login**. "Log in with Google" is built **on top** of OAuth, using **OpenID Connect** (topic 36).

---

### Why does it matter?

| Sharing the password | With OAuth 2.0 |
|---|---|
| The app gets **full** access to everything | The app gets **only** the scopes the user approved (`photos.read`) |
| Works **forever** | Tokens expire (minutes); access can be **revoked** per app |
| Changing the password breaks every app | Password changes don't affect app access (and vice versa) |
| The app's database leak = your account | A leak exposes short-lived, limited tokens |
| You type your password on **someone else's** site (phishing-friendly) | You type it only on the **provider's** own page |
| No record of which app did what | The provider knows which **client** used which **token** |

This is how "Connect your Google Drive", "Sign in with GitHub", Razorpay/Stripe Connect, Slack apps and most third-party integrations work.

---

### Real-life example: hotel valet key 🚗

Rahul drives to a wedding at a Jaipur hotel.

- He gives the valet a **valet key**, not his house keys with the car key on the ring. → **access token**, not the password
- The valet key **starts the car and opens the door**, but **not the boot or the glovebox**. → **scopes**
- The valet key only works **today**. → **expiry**
- Rahul hands it over at the **hotel's own desk**, which checks his parking slip. → login and consent happen at the **authorization server**
- The desk gives the valet a **token slip**, and the valet swaps it at the **key cabinet** for the actual key. → **authorization code** exchanged for a **token**
- The valet company is **registered** with the hotel; random people can't claim to be valets. → **client registration** (`client_id`, `client_secret`, redirect URIs)

---

### The four roles

| Role | In the demo | In "Connect Google Photos" |
|---|---|---|
| **Resource owner**: the user who owns the data | Rahul | You |
| **Client**: the app that wants access | PrintKaro (port 3000) | The printing app |
| **Authorization server (AS)**: logs the user in, asks consent, issues tokens | PhotoVault Accounts (port 3001) | accounts.google.com |
| **Resource server (RS)**: the API holding the data, accepts tokens | PhotoVault API (port 3002) | photoslibrary.googleapis.com |

The AS and RS are often run by the **same company** (Google), but they're separate jobs.

---

### The vocabulary

| Term | Meaning |
|---|---|
| **`client_id`** | The app's public name at the AS (`printkaro`) |
| **`client_secret`** | The app's password at the AS. Only for apps with a **server** ("confidential clients") |
| **`redirect_uri`** | Where the AS sends the browser back. **Registered in advance**, matched **exactly** |
| **Scope** | One permission the app asks for (`photos.read`) |
| **Consent** | The "PrintKaro wants to: See your photos. Allow / Deny" screen |
| **Authorization code** | A one-time, 60-second ticket the browser carries back to the app |
| **Access token** | What the app sends to the API: `Authorization: Bearer ...`. Short-lived |
| **Refresh token** | Optional, long-lived, used to get new access tokens (topic 21) |
| **Front channel** | Messages through the **browser** (redirects, URLs): visible, can be tampered with |
| **Back channel** | Direct **server-to-server** calls (the token request): not visible to the browser |
| **Grant type** | Which way the app gets a token (`authorization_code`, `client_credentials`, …, topic 34) |

---

### The flow, step by step

#### 📊 Diagrams

Open **[diagrams.html](diagrams.html)** in your browser (just double-click the file) to see:

- **Flow diagram**: every check the authorization server and the API make
- **Data flow**: the full authorization code flow between the browser, PrintKaro, PhotoVault Accounts and the PhotoVault API, with real URLs
- **Roles**: who talks to whom, and over which channel (browser vs server-to-server)

In short: `PrintKaro → redirect browser to PhotoVault /authorize (client_id, redirect_uri, scope, state) → Rahul logs in at PhotoVault → consent: Allow → redirect back to /callback?code&state → PrintKaro's server POSTs the code + client secret to /token → access_token → GET /photos with Bearer token`.

---

### Step 1: Register the client (once, in advance)

```js
{ id: "printkaro", secretHash: sha256(CLIENT_SECRET), redirectUris: ["http://localhost:3000/callback"], allowedScopes: ["photos.read"] }
```

In Google Cloud Console, GitHub Developer Settings, etc. you create an "OAuth app" and get a `client_id` and `client_secret`, and you list the **exact** redirect URIs (topic 37).

---

### Step 2: Send the user's browser to the authorization server

```
GET http://localhost:3001/authorize?response_type=code&client_id=printkaro
    &redirect_uri=http://localhost:3000/callback&scope=photos.read&state=sdecQ1pM3lfFzbRFIWYg1Q
```

The AS checks, **before anything else**:

| Check | If wrong |
|---|---|
| `client_id` is known, `redirect_uri` is **exactly** one of its registered URIs | Show an error **on the AS**, **don't redirect** (else the code goes to an attacker) |
| `response_type=code` | Redirect back with `error=unsupported_response_type` |
| Every scope is allowed for this client | Redirect back with `error=invalid_scope` |

`state` is a random value the client stores and checks later, so nobody can push **their** code into **your** session (CSRF; details in topic 35). Real apps also add **PKCE** here (topic 34).

---

### Step 3: Login and consent, on the authorization server's page

- The user logs in **at PhotoVault** (port 3001). PrintKaro never sees the password.
- The consent screen shows **who** is asking (registered app name) and **what** (scope descriptions).
- The consent form carries only a random, one-time `consentId`; the request details stay on the AS. That stops a forged form from changing the scopes or the redirect.

| ✅ Do | ❌ Don't |
|---|---|
| Users type passwords only on the AS's domain | Build a "login with PhotoVault" form on your own site |
| Ask for the **smallest** scopes you need | Ask for "everything" up front |

---

### Step 4: The code comes back through the browser

```
303 Location: http://localhost:3000/callback?code=aIu08oyGqNOPYPdMafP_J0tjtqu5llLyoclWkpWFfvY&state=sdecQ1pM3lfFzbRFIWYg1Q
```

- The code travels through the **browser** (front channel): it can end up in history, logs, `Referer`. So it is **useless on its own**: valid for **60 seconds**, **once**, only for **this client** and **this redirect_uri**, and only with the **client secret**.
- The client first checks `state` matches what it stored. If not → stop.
- If the user clicked **Deny**: `?error=access_denied&state=...`. Handle it politely.

---

### Step 5: Swap the code for a token (server to server)

```bash
POST http://localhost:3001/token
Authorization: Basic base64(printkaro:printkaro-demo-secret)
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&code=aIu08o...&redirect_uri=http://localhost:3000/callback
```
```json
{"access_token":"ctawzC_UGj_Mbj7k2A0Q6JE7a8bwlJLbpA1H9VhASok","token_type":"Bearer","expires_in":600,"scope":"photos.read"}
```

The AS checks: client id + secret (`401 invalid_client`), grant type, code exists / belongs to this client / not expired / not used / same `redirect_uri` (`400 invalid_grant`). If a code is used **twice**, the AS revokes the token it already issued: someone stole it.

The token goes to PrintKaro's **server** and stays there (its session store). The browser only has PrintKaro's session cookie (topic 25).

---

### Step 6: Call the API with the token

```
GET http://localhost:3002/photos
Authorization: Bearer ctawzC_UGj_...
```

The resource server checks the token is valid (`401 invalid_token`) and has the right **scope** (`403 insufficient_scope`), then returns **only the token's user's** data. PrintKaro's token can read Rahul's photos; it can't delete them, and it can't see Sneha's.

---

### 🤔 Tricky parts

**1. OAuth is authorization, not authentication.**
An access token says "this app may read photos". It doesn't tell **the app** who the user is in a standard, verifiable way. Using "I got a token, so the user is logged in" for login leads to real bugs (token substitution). For login, use **OpenID Connect** and its **ID token** (topic 36).

**2. Why a code, and not the token directly?**
The old **implicit flow** put the token straight into the URL fragment. URLs leak (history, extensions, logs), and anyone with the token can use it. The code is worthless without the client secret (or PKCE verifier), and the token travels only on the back channel. Implicit is **deprecated** (OAuth 2.1).

**3. Exact redirect URI matching.**
Allowing "anything starting with `https://printkaro.in`" lets attackers use `https://printkaro.in.evil.com` or an open redirect on the client's site to steal codes. Register full URIs; compare strings exactly.

**4. Public clients (SPAs, mobile apps).**
They can't keep a `client_secret` (anyone can read the bundle). They use the authorization code flow with **PKCE** instead (topic 34).

**5. Tokens are bearer tokens.**
Whoever has the token can use it. Keep them short-lived, send them only over HTTPS, never log them, keep them on the server where possible.

**6. Scopes are the app's limits, not the user's.**
A token can never do more than the **user** can do. `photos.read` on Rahul's account only reads Rahul's photos (ownership, topic 31, still applies on the API).

**7. OAuth 2.0 is a framework, not one protocol.**
Specs that matter: RFC 6749 (core), RFC 6750 (Bearer), RFC 7636 (PKCE), RFC 9700 (security best practice), and the OAuth 2.1 draft that bundles the good parts.

---

### Common beginner mistakes

1. **Asking users for their password on your own site** ("password grant").
   That's the problem OAuth exists to solve. Use the redirect flow.

2. **Using OAuth access tokens as proof of login.**
   Use OpenID Connect ID tokens for login (topic 36).

3. **Loose redirect URI checks** (prefix, wildcard, regex).
   Exact match only.

4. **No `state` check** (and no PKCE).
   Login CSRF and code injection (topics 34, 35).

5. **Putting the `client_secret` in frontend or mobile code.**
   Public clients use PKCE; secrets live on servers.

6. **Exchanging the code in the browser** and storing tokens in `localStorage`.
   Exchange on the server; keep tokens server-side (topic 25).

7. **Asking for too many scopes.**
   Users decline, and a leak is worse. Ask for more later if needed ("incremental authorization").

8. **Not handling `error=access_denied`.**
   Users click Deny. Show a friendly page.

9. **Logging full URLs with `?code=`** or tokens.
   Redact them.

---

### Interview questions

1. **What is OAuth 2.0?**
   An authorization framework that lets a user grant a third-party app limited, revocable access to their resources on another service, without sharing their password.

2. **Name the four roles.**
   Resource owner (user), client (app), authorization server (issues tokens), resource server (API that accepts tokens).

3. **Explain the authorization code flow.**
   Client redirects the browser to `/authorize` with client_id, redirect_uri, scope, state → user logs in and consents → AS redirects back with a code and state → client checks state and POSTs the code with its credentials to `/token` → gets an access token → calls the API with `Authorization: Bearer`.

4. **Why exchange a code instead of returning the token directly?**
   The browser leg is exposed; the code is short-lived, single-use, bound to the client and redirect URI, and useless without client authentication (or PKCE). The token only travels server-to-server.

5. **OAuth vs OpenID Connect?**
   OAuth 2.0 = delegated authorization (access tokens). OIDC = an identity layer on top: adds the ID token and `/userinfo` so the client can authenticate the user.

6. **What is a scope?**
   A named permission the client requests and the user approves, such as `photos.read`. The resource server enforces it.

7. **Front channel vs back channel?**
   Front channel = through the user's browser via redirects (visible, tamperable). Back channel = direct server-to-server HTTPS (the token request).

8. **Why must redirect URIs match exactly?**
   Otherwise an attacker can get the authorization code sent to a URL they control.

9. **What's a confidential vs public client?**
   Confidential clients (server-side apps) can keep a client secret. Public clients (SPAs, mobile, desktop) can't, and use PKCE.

10. **What does the resource server check?**
    Token valid (signature or introspection, not expired, not revoked, right audience), required scope present, and that the data belongs to the token's user.

---

### Quick recap

- OAuth 2.0 = **delegated access** without sharing passwords
- Roles: **resource owner**, **client**, **authorization server**, **resource server**
- Register the client: `client_id`, `client_secret`, **exact** `redirect_uri`, allowed scopes
- **Authorization code flow**: redirect → login + consent at the AS → code → **server swaps code for token** → Bearer token to the API
- Codes: **60 s, one use**, bound to client + redirect URI; reuse → revoke
- Tokens: short-lived, scoped, kept on the **server**
- Errors: `invalid_client` (401), `invalid_grant`, `invalid_scope`, `access_denied`, `insufficient_scope` (403)
- OAuth is **not** login: that's OpenID Connect (topic 36)
- Next: the other grant types and **PKCE** (topic 34), `state` and `nonce` (topic 35)

## Code

One **Express** file that starts **three apps** on three ports, so you can watch every hop:

| Port | App | OAuth role |
|---|---|---|
| `3000` | 🖨️ **PrintKaro** | Client (a photo printing site) |
| `3001` | 📸 **PhotoVault Accounts** | Authorization server: login, consent, `/authorize`, `/token` |
| `3002` | 📸 **PhotoVault API** | Resource server: `GET /photos`, `DELETE /photos/:id` |

Users at PhotoVault: `rahul` (3 photos) and `sneha` (1 photo), password `chai1234`. PrintKaro is registered with `client_id=printkaro`, secret `printkaro-demo-secret`, redirect URI `http://localhost:3000/callback`, and may only ask for `photos.read`.

📄 **Full code: [server.js](server.js)**. Open it and read the comments, which follow the same steps as the notes above.

Install the dependencies once (from this folder), then start the server:

```bash
npm install
```

```bash
node server.js
```

> Port 3000 busy? Run it on other ports: `PORT=3033 node server.js` (Git Bash) uses **3033**, **3034** and **3035**. The outputs below were recorded that way, so they show those ports.

### Try it in the browser (the easy way)

Open **http://localhost:3000** → click **Import from 📸 PhotoVault** → you're now on PhotoVault's page (port **3001**: check the address bar) → sign in as `rahul` / `chai1234` → the consent screen says *"PrintKaro (photo printing) wants to: See your photos (photos.read)"* → **Allow** → you're back on PrintKaro with:

```
Photos imported from PhotoVault:
🖼️ Goa beach sunset (ph_1)
🖼️ Dadi's 80th birthday (ph_2)
🖼️ Diwali rangoli (ph_3)
```

Try **Deny** too: PrintKaro says *"No problem, we didn't import anything (access_denied)"*. The terminal logs each step:

```
✅ u_rahul allowed printkaro [photos.read] → code issued (valid 60 s, one use)
🎟️  access token issued to printkaro for u_rahul [photos.read]
🙅 u_rahul denied printkaro
```

### Try it with curl: every hop, by hand (Git Bash)

```bash
C=http://localhost:3000; AS=http://localhost:3001; API=http://localhost:3002
```

🧭 **1. PrintKaro sends the browser to PhotoVault** (`client.txt` plays PrintKaro's cookie in your browser):

```bash
AUTHZ=$(curl -s -c client.txt -o /dev/null -w "%{redirect_url}" $C/connect); echo "$AUTHZ"
```
→ `http://localhost:3034/authorize?response_type=code&client_id=printkaro&redirect_uri=http%3A%2F%2Flocalhost%3A3033%2Fcallback&scope=photos.read&state=sdecQ1pM3lfFzbRFIWYg1Q`

🔐 **2. Log in at PhotoVault** (`as.txt` plays PhotoVault's cookie):

```bash
curl -s -c as.txt -o /dev/null -w "%{http_code} %{redirect_url}\n" $AS/login --data-urlencode "username=rahul" --data-urlencode "password=chai1234" --data-urlencode "next=${AUTHZ#$AS}"
```
→ `303 http://localhost:3034/authorize?response_type=code&client_id=printkaro&...` (back to the authorize URL, now logged in)

✋ **3. The consent page, then Allow:**

```bash
CID=$(curl -s -b as.txt "$AUTHZ" | grep -o 'name="consentId" value="[^"]*"' | cut -d'"' -f4)
CB=$(curl -s -b as.txt -o /dev/null -w "%{redirect_url}" $AS/consent -d "consentId=$CID" -d "decision=allow"); echo "$CB"
```
→ `http://localhost:3033/callback?code=aIu08oyGqNOPYPdMafP_J0tjtqu5llLyoclWkpWFfvY&state=sdecQ1pM3lfFzbRFIWYg1Q`

🔁 **4. Back at PrintKaro:** it checks `state`, swaps the code for a token (server to server), and shows the photos:

```bash
curl -s -b client.txt -o /dev/null -w "%{http_code} %{redirect_url}\n" "$CB"
curl -s -b client.txt $C/photos | grep -o '<li>[^<]*'
```
→
```
303 http://localhost:3033/photos
<li>🖼️ Goa beach sunset
<li>🖼️ Dadi&#39;s 80th birthday
<li>🖼️ Diwali rangoli
```

Opening the same callback URL again → `That sign-in didn't start here (state mismatch)`: `state` is one-use.

🎟️ **5. Be the client's server yourself.** Get a fresh code (repeat steps 1 and 3; you're still logged in), then exchange it with the client secret:

```bash
CODE=$(echo "$CB" | sed 's/.*code=\([^&]*\).*/\1/')
curl -s $AS/token -u printkaro:printkaro-demo-secret -d grant_type=authorization_code -d code=$CODE --data-urlencode "redirect_uri=$C/callback"
```
→ `{"access_token":"ctawzC_UGj_Mbj7k2A0Q6JE7a8bwlJLbpA1H9VhASok","token_type":"Bearer","expires_in":600,"scope":"photos.read"}`. Copy it: `TOKEN=...`

📸 **6. Call the API:**

```bash
curl -s $API/photos -H "Authorization: Bearer $TOKEN"
curl -s -i -X DELETE $API/photos/ph_1 -H "Authorization: Bearer $TOKEN"
curl -s -i $API/photos
```
→
```
{"user":"u_rahul","client":"printkaro","photos":[{"id":"ph_1","owner":"u_rahul","title":"Goa beach sunset"},{"id":"ph_2",...},{"id":"ph_3",...}]}

HTTP/1.1 403 Forbidden
WWW-Authenticate: Bearer error="insufficient_scope", scope="photos.delete"
{"error":"insufficient_scope","needed":"photos.delete"}

HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer error="invalid_token"
{"error":"invalid_token"}
```

❌ **What the token endpoint refuses** (run these with a fresh, unused `$CODE`; the last two after the good exchange above):

```bash
curl -s -w " %{http_code}\n" $AS/token -u printkaro:wrong -d grant_type=authorization_code -d code=$CODE --data-urlencode "redirect_uri=$C/callback"
curl -s -w " %{http_code}\n" $AS/token -u printkaro:printkaro-demo-secret -d grant_type=authorization_code -d code=$CODE --data-urlencode "redirect_uri=http://evil.example/cb"
curl -s -w " %{http_code}\n" $AS/token -u printkaro:printkaro-demo-secret -d grant_type=password -d username=rahul -d password=chai1234
curl -s -w " %{http_code}\n" $AS/token -u printkaro:printkaro-demo-secret -d grant_type=authorization_code -d code=$CODE --data-urlencode "redirect_uri=$C/callback"
curl -s -w " %{http_code}\n" $API/photos -H "Authorization: Bearer $TOKEN"
```
→
```
{"error":"invalid_client","error_description":"Client authentication failed"} 401
{"error":"invalid_grant","error_description":"redirect_uri does not match"} 400
{"error":"unsupported_grant_type","error_description":"Only authorization_code is supported here"} 400
{"error":"invalid_grant","error_description":"Code already used"} 400       ← the code was replayed...
{"error":"invalid_token"} 401                                                ← ...so the token it issued is revoked
```
Terminal: `🚨 code reused by printkaro: the access token it issued is now revoked`

❌ **What the authorize endpoint refuses:**

```bash
curl -s -w " %{http_code}\n" "$AS/authorize?response_type=code&client_id=printkaro&redirect_uri=http%3A%2F%2Fevil.example%2Fcb&scope=photos.read&state=x"
curl -s -b as.txt -o /dev/null -w "%{redirect_url}\n" "$AS/authorize?response_type=code&client_id=printkaro&redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fcallback&scope=photos.read%20photos.delete&state=x"
```
→
```
... <p>Unknown app or redirect address. You were <b>not</b> redirected.</p> ... 400     ← an HTML error page, no redirect
http://localhost:3033/callback?error=invalid_scope&state=x        ← PrintKaro may not ask for photos.delete
```

> **Windows PowerShell users:** the variables, `$(...)`, `-c/-b` cookie jars and `PORT=... node ...` work in Git Bash. In PowerShell, use the browser walkthrough, Git Bash, or `$env:PORT=3033; node server.js`.
