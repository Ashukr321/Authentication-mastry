# 34. OAuth 2.0 Grant Types & PKCE

## Notes

### What is a grant type?

Topic 33 walked through **one** way an app gets an access token: the authorization code flow. But not every app is a website with a server. A **mobile app** can't hide a secret. A **nightly script** has no user at all. A **smart TV** has no keyboard. OAuth 2.0 has a different **grant type** (a way of getting a token) for each situation, and **PKCE** is the add-on that makes the code flow safe for apps that can't keep a secret.

> **One-line answer:** a **grant type** is how a client gets a token. Today you need four: **authorization code + PKCE** (any app acting for a user: web, SPA, mobile), **refresh token** (new access tokens without the user, rotated), **client credentials** (a server acting as itself, no user), and **device code** (TVs and CLIs: approve on your phone). **Implicit** and **password** grants are **removed** in OAuth 2.1. **PKCE** = the app makes a random `code_verifier`, sends only its SHA-256 hash (`code_challenge`) to `/authorize`, and must show the original verifier at `/token`, so a **stolen code is useless**.

---

### Why does it matter?

| Situation | Wrong choice | What goes wrong |
|---|---|---|
| Mobile app / SPA | Ship a `client_secret` in the app | Anyone unzips the APK or reads the JS bundle and has it |
| Mobile app without PKCE | Code flow, no secret, no PKCE | Another app registers the same custom URL scheme, receives the code, swaps it for a token |
| SPA | Implicit flow (token in the URL `#fragment`) | Token leaks via history, extensions, `Referer`, logs; can't be refreshed safely |
| Your own login form | Password grant | The app sees the password: phishing-friendly, no MFA, no consent, exactly what OAuth was meant to stop |
| Nightly job | Using a real user's token | Breaks when that person leaves; the job has the user's full rights |
| Smart TV | Typing email and password with a remote | Painful, and the TV app sees the password |

---

### Real-life example: getting things done at a housing society 🏢

Rahul lives in a Bengaluru housing society with a gate app.

- **Authorization code**: a delivery boy rings. Rahul approves on **his own app** at the gate screen, and the guard hands over a one-time pass. → the user approves on the provider's side
- **PKCE**: when Rahul books the delivery, he tears a slip in two, keeps one half (**verifier**) and leaves a photo of it (**challenge**) at the gate. The pass is only released to whoever brings the matching half. Someone who overhears the pass number gets nothing. → stolen code is useless
- **Refresh token**: the maid has a monthly pass; each month the guard swaps her old card for a new one and shreds the old. If the old card ever shows up again, both are cancelled. → rotation + reuse detection
- **Client credentials**: the society's water tanker company has its own contract badge; no resident needs to approve each visit. → app acts as itself
- **Device code**: Rahul's elderly father can't type on the gate tablet, so the tablet shows **"Code: PPSM-JNQW"** and Rahul approves it from his phone. → device flow

---

### Which grant should I use?

| Your app | Grant | Client type | Secret? | PKCE? | Refresh token? |
|---|---|---|---|---|---|
| Web app with a backend | **Authorization code** | Confidential | ✅ on the server | ✅ (OAuth 2.1: always) | ✅ |
| SPA (React) / mobile / desktop | **Authorization code** | Public | ❌ can't keep one | ✅ **required** | ✅ rotated |
| Backend job / microservice, no user | **Client credentials** | Confidential | ✅ (or a certificate, Level 8) | n/a | ❌ just ask again |
| TV, console, CLI, IoT | **Device code** | Public | ❌ | n/a | ✅ |
| ~~SPA~~ | ~~Implicit~~ | | | | **Removed in OAuth 2.1** |
| ~~Your own login form~~ | ~~Password (ROPC)~~ | | | | **Removed in OAuth 2.1** |

**Confidential** client: runs on a server you control, can keep a secret. **Public** client: runs on the user's device (browser, phone, TV); anything inside it can be read.

---

#### 📊 Diagrams

Open **[diagrams.html](diagrams.html)** in your browser (just double-click the file) to see:

- **Flow diagram**: picking a grant type, and the PKCE check at the token endpoint
- **Data flow: PKCE**: a malicious app steals the code and still can't get a token
- **Data flow: device code**: a TV, Rahul's phone and the server, including `authorization_pending` and `slow_down`

In short: `PKCE: verifier (random, kept) → challenge = BASE64URL(SHA256(verifier)) → /authorize?code_challenge=...&code_challenge_method=S256 → code → /token with code_verifier → server re-hashes and compares`.

---

### Step 1: Register each client for the grants it needs

```js
["printkaro-mobile",   { type: "public",       redirectUris: [...], grants: ["authorization_code", "refresh_token"] }],
["nightly-report-job", { type: "confidential", secretHash: ...,      grants: ["client_credentials"] }],
["photovault-tv",      { type: "public",                             grants: [DEVICE_GRANT, "refresh_token"] }],
```

A client using a grant it isn't registered for gets `unauthorized_client`. A mobile app can never get a `client_credentials` token, because it can't prove who it is.

---

### Step 2: PKCE, part 1: the challenge at `/authorize`

```bash
V=$(openssl rand -base64 48 | tr '+/' '-_' | tr -d '=\r\n')                                    # code_verifier: 64 random chars, KEEP IT
CH=$(printf %s "$V" | openssl dgst -sha256 -binary | base64 | tr '+/' '-_' | tr -d '=\r\n')   # code_challenge
```
```
GET /authorize?response_type=code&client_id=printkaro-mobile&redirect_uri=...&scope=photos.read&state=s1
    &code_challenge=KJPhqdJdWI3bcb-w7kUywp7_20cpJFwEqdq_QDoKbEk&code_challenge_method=S256
```

- **verifier**: 43–128 characters from `A-Z a-z 0-9 - . _ ~`, random (32+ random bytes), **new for every login**, kept in the app's memory.
- **challenge**: `BASE64URL(SHA256(verifier))`, no `=` padding. It's a **hash**, so seeing it doesn't reveal the verifier.
- The server stores the challenge **with the code**.
- Only accept **`S256`**. The `plain` method sends the verifier itself and protects nothing if the request is seen.

Check your hashing with the example from RFC 7636: verifier `dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk` → challenge `E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM` (the demo checks this on startup).

---

### Step 3: PKCE, part 2: the verifier at `/token`

```bash
POST /token
grant_type=authorization_code&client_id=printkaro-mobile&code=...&redirect_uri=...&code_verifier=VsAxi4Z_1T3D...
```
```js
if (base64url(sha256(code_verifier)) !== record.challenge) → 400 invalid_grant   // and burn the code
```

**Why it works:** the code travels through the browser / OS (front channel) and can be stolen: a malicious app on the same phone claiming the same `printkaro://callback` scheme, a log, a browser extension. The verifier **never** left the real app. Without it, the stolen code is worthless.

PKCE also stops **code injection** (an attacker pushing their own code into your session), so OAuth 2.1 requires it for **confidential** clients too, alongside the secret.

---

### Step 4: Refresh tokens: rotate on every use

```bash
POST /token  grant_type=refresh_token&client_id=printkaro-mobile&refresh_token=HbqVziC_...
→ {"access_token":"G-4mpk...","refresh_token":"4OUFrK...", ...}     # a NEW refresh token every time
```

- Short access tokens (10 minutes) + a refresh token = long sessions without long-lived bearer tokens.
- **Rotation**: each refresh returns a **new** refresh token and invalidates the old. If an **old** one comes back, someone copied it → revoke the **whole family** (topic 23). Required for public clients in OAuth 2.1 (or sender-constrained tokens, Level 8).

---

### Step 5: Client credentials: the app is the user

```bash
POST /token  (Basic nightly-report-job:secret)  grant_type=client_credentials&scope=reports.read
→ {"access_token":"QHszD...","token_type":"Bearer","expires_in":600,"scope":"reports.read"}
```

- No user, no browser, no consent. `sub` is the **client** itself.
- Confidential clients only. No refresh token: the job can just ask again.
- Use it for service-to-service calls, cron jobs, webhooks between your own systems. Give each service its own client and the smallest scopes.

---

### Step 6: Device code: approve on another screen

```
TV    → POST /device_authorization  client_id=photovault-tv&scope=photos.read
      ← device_code (secret, stays on TV), user_code "PPSM-JNQW", verification_uri, interval 5
TV shows: "On your phone, open localhost:3000/device and enter PPSM-JNQW"
TV    → POST /token grant_type=urn:ietf:params:oauth:grant-type:device_code ... every 5 s
      ← authorization_pending ... (slow_down if it polls too fast)
Phone → logs in, enters the code, Allow
TV    → POST /token ... ← access_token + refresh_token
```

- The user approves on a device with a proper browser (often via a QR code of `verification_uri_complete`).
- `user_code`: short, easy to type, no vowels (no accidental rude words), no `0/O`, `1/I`; expires in minutes; rate-limit guesses.
- **Phishing risk**: an attacker can start a device flow and send you the code ("Enter PPSM-JNQW to claim your prize"). The approval screen must say clearly **which device/app** is asking.

---

### The removed grants (and why)

| Grant | How it worked | Why it's gone |
|---|---|---|
| **Implicit** (`response_type=token`) | Token returned in the URL fragment, no code exchange | Token exposed in the browser; no client authentication; replaced by **code + PKCE** |
| **Password / ROPC** (`grant_type=password`) | App collects the username + password and sends them to `/token` | The app sees the password; no MFA, no consent; trains users to type passwords anywhere |

The demo refuses both with clear errors.

---

### 🤔 Tricky parts

**1. PKCE doesn't replace `state`.**
PKCE protects the **code**. `state` protects the **client's session** from login CSRF, and `nonce` protects ID tokens (topic 35). Use all of them.

**2. The verifier must be per login, random, and stored safely until the callback.**
A fixed verifier compiled into the app is no better than none. In SPAs keep it in `sessionStorage` (or memory); in mobile apps, in memory.

**3. Public clients still identify themselves.**
They send `client_id` (no secret). The server can't trust it fully, so it relies on PKCE, exact redirect URIs, and for mobile, claimed HTTPS links (App Links / Universal Links) instead of custom URL schemes.

**4. A wrong verifier should burn the code.**
If someone presents a code with the wrong verifier, the real app won't get it either. The demo burns it; the real app just starts again.

**5. Client credentials tokens are powerful.**
They often have broad access (no user to limit them). Keep scopes tight, rotate secrets, prefer private-key JWT or mTLS client authentication for important services (Level 8).

**6. BFF for SPAs.**
Many teams now run the code flow on a small backend ("Backend for Frontend") so tokens never reach the browser, and the SPA just has a session cookie (topic 25).

---

### Common beginner mistakes

1. **Putting a `client_secret` in a mobile app or SPA.**
   It's public the moment you ship. Public client + PKCE.

2. **Using `code_challenge_method=plain`.**
   Use S256 only.

3. **Reusing one verifier**, or making it from something guessable.
   `randomBytes(32)` per login.

4. **Forgetting the `\r` / padding / `+/` when computing the challenge.**
   Base64**url**, no `=`, no line endings. Test against the RFC example.

5. **Still using the implicit flow for SPAs.**
   Code + PKCE (or a BFF).

6. **Using the password grant "because it's our own app".**
   You lose MFA, SSO and phishing protection. Redirect to the login page.

7. **Refresh tokens without rotation in public clients.**
   A stolen refresh token works for months.

8. **Polling the device endpoint every second.**
   Respect `interval` and `slow_down`.

9. **Using a person's token for a background job.**
   Client credentials, with its own scopes.

---

### Interview questions

1. **What grant types does OAuth 2.0 define, and which should you use today?**
   Authorization code, implicit, resource owner password, client credentials, plus refresh token and device code (extension). Today: authorization code + PKCE for users, client credentials for machines, device code for input-constrained devices, refresh tokens with rotation. Implicit and password are removed in OAuth 2.1.

2. **What is PKCE and what attack does it stop?**
   Proof Key for Code Exchange: the client sends a hash of a random verifier at `/authorize` and the verifier at `/token`. It stops authorization code interception and code injection: a stolen code can't be redeemed without the verifier.

3. **Why S256 and not plain?**
   With plain, the challenge equals the verifier, so anyone who sees the authorization request can redeem the code.

4. **Confidential vs public client?**
   Confidential clients run on servers and can keep a secret; public clients run on user devices and can't. Public clients rely on PKCE.

5. **Why was the implicit flow removed?**
   It returned the access token in the URL, exposing it to the browser, history and extensions, with no way to authenticate the client or bind the token. Code + PKCE is safer and now works in browsers thanks to CORS.

6. **Why was the password grant removed?**
   The client sees the user's credentials, which defeats OAuth's purpose, blocks MFA/SSO and encourages phishing.

7. **When do you use client credentials?**
   Machine-to-machine calls with no user: the client authenticates as itself and gets a token for its own permissions.

8. **How does the device code flow work?**
   The device gets a device_code and a short user_code, shows the code and a URL, and polls `/token`. The user approves on another device; polling then returns tokens. `authorization_pending` and `slow_down` control the polling.

9. **What is refresh token rotation?**
   Every refresh returns a new refresh token and invalidates the old. Reuse of an old one indicates theft, so the whole token family is revoked.

10. **Does PKCE replace the client secret or `state`?**
    No. Confidential clients still authenticate; `state` still protects against CSRF on the client. PKCE adds code binding.

---

### Quick recap

- **Grant type** = how a client gets a token; pick by **who** the client is and **whether there's a user**
- **Auth code + PKCE**: every app acting for a user (web, SPA, mobile)
- **PKCE**: random verifier per login → `S256` challenge at `/authorize` → verifier at `/token`; stolen code = useless
- **Public clients**: no secret, PKCE required. **Confidential**: secret + PKCE
- **Refresh token**: rotate every use; reuse → revoke the family
- **Client credentials**: no user, confidential only, no refresh token
- **Device code**: user code on the TV, approve on the phone, poll with `interval`
- **Implicit** and **password** grants: **removed** (OAuth 2.1)
- Next: `state` and `nonce` (topic 35), then OpenID Connect (topic 36)

## Code

One **Express** authorization server (plus a tiny `/api/whoami` resource server) that supports every modern grant. Four registered clients:

| Client | Type | Grants | Secret |
|---|---|---|---|
| `printkaro-web` | confidential (web app with a backend) | authorization_code (+ PKCE), refresh_token | `web-demo-secret` |
| `printkaro-mobile` | public (mobile app / SPA) | authorization_code (+ PKCE), refresh_token | none |
| `nightly-report-job` | confidential (backend job) | client_credentials | `job-demo-secret` |
| `photovault-tv` | public (smart TV) | device_code, refresh_token | none |

The user is `rahul` / `chai1234`. `/demo/callback` plays the app's redirect URI: it just shows you the `code` and `state` it received.

Shortcuts so everything fits in curl: login is a JSON `POST /login` (topic 33 shows the real HTML login and consent pages), there's no consent screen, and the device approval page is a JSON `POST /device`.

📄 **Full code: [server.js](server.js)**. Open it and read the comments, which follow the same steps as the notes above.

Install the dependencies once (from this folder), then start the server:

```bash
npm install
```

```bash
node server.js
```

> Port 3000 busy? Run it on another port: `PORT=3034 node server.js` (Git Bash). The outputs below were recorded that way, so they show port 3034.

### Try it (Git Bash)

```bash
AS=http://localhost:3000; CB=http%3A%2F%2Flocalhost%3A3000%2Fdemo%2Fcallback
curl -s -c as.txt $AS/login -H "Content-Type: application/json" -d '{"username":"rahul","password":"chai1234"}'
```
→ `{"ok":true,"user":"u_rahul"}`

#### 1️⃣ Authorization code + PKCE (the mobile app, no secret)

Make a verifier and its challenge, like the app would:

```bash
V=$(openssl rand -base64 48 | tr '+/' '-_' | tr -d '=\r\n')
CH=$(printf %s "$V" | openssl dgst -sha256 -binary | base64 | tr '+/' '-_' | tr -d '=\r\n')
echo "${#V} ${#CH}"
```
→ `64 43` (on Windows, `\r` in the `tr -d` matters: openssl prints CRLF line endings)

❌ **The server refuses requests without proper PKCE, and the implicit flow:**

```bash
curl -s -b as.txt -o /dev/null -w "%{redirect_url}\n" "$AS/authorize?response_type=code&client_id=printkaro-mobile&redirect_uri=$CB&scope=photos.read&state=s1"
curl -s -b as.txt -o /dev/null -w "%{redirect_url}\n" "$AS/authorize?response_type=code&client_id=printkaro-mobile&redirect_uri=$CB&scope=photos.read&state=s1&code_challenge=$CH&code_challenge_method=plain"
curl -s -b as.txt -o /dev/null -w "%{redirect_url}\n" "$AS/authorize?response_type=token&client_id=printkaro-mobile&redirect_uri=$CB&scope=photos.read&state=s1"
```
→
```
http://localhost:3034/demo/callback?error=invalid_request&error_description=code_challenge+is+required+%28PKCE%29&state=s1
http://localhost:3034/demo/callback?error=invalid_request&error_description=code_challenge_method+must+be+S256&state=s1
http://localhost:3034/demo/callback?error=unsupported_response_type&error_description=Implicit+flow+is+not+supported.+Use+response_type%3Dcode+with+PKCE.&state=s1
```

✅ **Get a code** (the browser would follow this redirect to the app):

```bash
L=$(curl -s -b as.txt -o /dev/null -w "%{redirect_url}" "$AS/authorize?response_type=code&client_id=printkaro-mobile&redirect_uri=$CB&scope=photos.read&state=s1&code_challenge=$CH&code_challenge_method=S256"); curl -s "$L"; echo
CODE=$(echo "$L" | sed 's/.*code=\([^&]*\).*/\1/')
```
→ `{"note":"This is the app's redirect_uri. The app would now check state and POST the code to /token.","query":{"code":"_i9SAsa_s_iq1eE2NECDzToeJT5xrdGNwZ0u3umkKxs","state":"s1"}}`

🕵️ **Be the attacker who stole that code:** no verifier, then a guessed one, then (too late) the real one:

```bash
curl -s $AS/token -d grant_type=authorization_code -d client_id=printkaro-mobile -d code=$CODE --data-urlencode "redirect_uri=$AS/demo/callback"
curl -s $AS/token -d grant_type=authorization_code -d client_id=printkaro-mobile -d code=$CODE --data-urlencode "redirect_uri=$AS/demo/callback" -d code_verifier=AttackerGuessAttackerGuessAttackerGuess12345678
curl -s $AS/token -d grant_type=authorization_code -d client_id=printkaro-mobile -d code=$CODE --data-urlencode "redirect_uri=$AS/demo/callback" -d code_verifier=$V
```
→
```
{"error":"invalid_grant","error_description":"code_verifier is missing or malformed"}
{"error":"invalid_grant","error_description":"PKCE verification failed"}        ← terminal: 🚨 PKCE mismatch for printkaro-mobile: code burned
{"error":"invalid_grant","error_description":"Code already used"}                ← burned, even for the real app
```

✅ **The real app** (get a fresh code with the same `L=...` / `CODE=...` lines, then):

```bash
curl -s $AS/token -d grant_type=authorization_code -d client_id=printkaro-mobile -d code=$CODE --data-urlencode "redirect_uri=$AS/demo/callback" -d code_verifier=$V
```
→ `{"access_token":"mNrJDSqXsFllHR-nx2HRTZY3q3LmZV3fwkdW_hupvHw","token_type":"Bearer","expires_in":600,"scope":"photos.read","refresh_token":"HbqVziC_EPkN40orVjQ1h7vShzUqtsqYxWyvs4_dIB0"}`. Copy both: `AT=...`, `RT=...`

```bash
curl -s $AS/api/whoami -H "Authorization: Bearer $AT"
```
→ `{"sub":"u_rahul","client_id":"printkaro-mobile","scope":"photos.read","grant":"authorization_code","user":true}`

✅ **The web app uses PKCE *and* its secret.** Get a code with `client_id=printkaro-web`, then:

```bash
curl -s $AS/token -u printkaro-web:web-demo-secret -d grant_type=authorization_code -d code=$CODE --data-urlencode "redirect_uri=$AS/demo/callback" -d code_verifier=$V
```
→ `{"access_token":"qKywEv0YX48RSq32VEf2UiwHBTu7IsfI2HaT2050cUY",...,"refresh_token":"7BPYZImwZiwatQzMrUDCVyD7irXZwaPrg1fhcqPjCP8"}`. Without the secret: `401 {"error":"invalid_client",...}`. Redeemed by a different client: `{"error":"invalid_grant","error_description":"Unknown code"}`.

#### 2️⃣ Refresh token, rotated

```bash
curl -s $AS/token -d grant_type=refresh_token -d client_id=printkaro-mobile -d refresh_token=$RT
curl -s $AS/token -d grant_type=refresh_token -d client_id=printkaro-mobile -d refresh_token=$RT
curl -s $AS/api/whoami -H "Authorization: Bearer <the access_token from the first line>"
```
→
```
{"access_token":"G-4mpkFRBX1C2685PQ3XC4LV2XTP7clWOpcqHhcT40Y",...,"refresh_token":"4OUFrKZd8oBQLBldBcxS8R2WtgyrusREHSf4hzf4KXs"}   ← new pair
{"error":"invalid_grant","error_description":"Refresh token already used"}       ← terminal: 🚨 refresh token reuse: whole token family revoked
{"error":"invalid_token"}                                                        ← even the newest access token is dead
```

#### 3️⃣ Client credentials (no user)

```bash
curl -s $AS/token -u nightly-report-job:job-demo-secret -d grant_type=client_credentials -d scope=reports.read
```
→ `{"access_token":"QHszD_HK8OZRz4ZtiL2Tv7UnTJydoZY7euDwudJlb-0","token_type":"Bearer","expires_in":600,"scope":"reports.read"}` (no refresh token)

`/api/whoami` with it → `{"sub":"nightly-report-job","client_id":"nightly-report-job","scope":"reports.read","grant":"client_credentials","user":false}`

```bash
curl -s $AS/token -u nightly-report-job:job-demo-secret -d grant_type=client_credentials -d scope=photos.read
curl -s $AS/token -u nightly-report-job:nope -d grant_type=client_credentials
curl -s $AS/token -d grant_type=client_credentials -d client_id=printkaro-mobile
```
→
```
{"error":"invalid_scope"}
{"error":"invalid_client","error_description":"Client authentication failed"}
{"error":"unauthorized_client","error_description":"printkaro-mobile may not use client_credentials"}
```

#### 4️⃣ Device code (the TV)

The TV asks for a code:

```bash
curl -s $AS/device_authorization -d client_id=photovault-tv -d scope=photos.read
```
→ `{"device_code":"77_L-n6CKC9rju4njhTEXj0UBZCSoP1fNYPm6LN7jIQ","user_code":"PPSM-JNQW","verification_uri":"http://localhost:3034/device","verification_uri_complete":"http://localhost:3034/device?user_code=PPSMJNQW","expires_in":600,"interval":5}`. Copy: `DC=...`, `UC=...`

The TV polls, too eagerly:

```bash
poll() { curl -s $AS/token -d grant_type=urn:ietf:params:oauth:grant-type:device_code -d client_id=photovault-tv -d device_code=$DC; echo; }
poll; poll
```
→
```
{"error":"authorization_pending"}
{"error":"slow_down"}          ← polled within 5 s: the interval is now 10 s
```

Rahul approves on his phone (lower case and dashes are fine):

```bash
curl -s -b as.txt $AS/device -d user_code=ppsm-jnqw -d decision=allow
```
→ `{"message":"Done! Your TV is now connected."}` (a wrong code → `{"error":"Code not found or expired. Check the code on your TV."}`; not logged in → `401`)

After 10 seconds the TV polls again:

```bash
poll
```
→ `{"access_token":"VhwBGX0gnSORNWEqqRjLSQTPE0JMV7n71-mnH5fdFBc","token_type":"Bearer","expires_in":600,"scope":"photos.read","refresh_token":"YUiq8o3Os0Kvuwv1CUpjjZ9-JuSv6f9tP6hKWjzE1NI"}`

`/api/whoami` with it → `{"sub":"u_rahul","client_id":"photovault-tv","scope":"photos.read","grant":"device_code","user":true}`. Polling once more → `{"error":"invalid_grant","error_description":"Unknown device_code"}` (one use).

#### 🚫 The removed grants

```bash
curl -s $AS/token -d grant_type=password -d client_id=printkaro-mobile -d username=rahul -d password=chai1234
```
→ `{"error":"unsupported_grant_type","error_description":"The password grant is not supported. Use authorization_code with PKCE."}`

📋 **The terminal log:**

```
✅ code for printkaro-mobile (public), user u_rahul, PKCE challenge KJPhqdJd…
🚨 PKCE mismatch for printkaro-mobile: code burned
🎟️  authorization_code: token for u_rahul via printkaro-mobile [photos.read] + refresh token
🎟️  refresh_token: token for u_rahul via printkaro-mobile [photos.read] + refresh token
🚨 refresh token reuse for printkaro-mobile: whole token family revoked
🎟️  client_credentials: token for nightly-report-job via nightly-report-job [reports.read]
📺 photovault-tv asked for device login, user code PPSM-JNQW
📱 u_rahul approved photovault-tv
🎟️  device_code: token for u_rahul via photovault-tv [photos.read] + refresh token
```

> **Windows PowerShell users:** the variables, `$(...)`, `openssl` pipes and `PORT=... node ...` work in Git Bash (which ships with `openssl`). In PowerShell, use Git Bash, or `$env:PORT=3034; node server.js`.
