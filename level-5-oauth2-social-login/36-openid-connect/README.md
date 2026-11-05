# 36. OpenID Connect (OIDC)

## Notes

### What is OpenID Connect?

OAuth 2.0 (topics 33–35) answers **"may this app access my photos?"**. It hands the app an **access token** meant for an **API**. It never promises to tell the app **who the user is**. But "Log in with Google" needs exactly that: *"this is user #248289761001 at Google, they logged in just now, and this login is for **your** app"*.

**OpenID Connect (OIDC)** is a thin layer on top of OAuth 2.0 that adds that answer.

> **One-line answer:** OIDC = OAuth 2.0 + `scope=openid` + an **ID token**: a **signed JWT for the app** that says who logged in (`sub` at `iss`), for which app (`aud`), when (`auth_time`, `iat`, `exp`) and for which login request (`nonce`). It also standardises a **`/userinfo`** endpoint, **discovery** (`/.well-known/openid-configuration`) and a **JWKS** of public keys. The app verifies the ID token and identifies the user by **`iss` + `sub`**, never by email.

---

### Why does it matter?

| Login built on plain OAuth | What goes wrong |
|---|---|
| "I got an access token, so the user is logged in" | An access token issued to **another** app (a quiz app the user also uses) can be replayed to yours: you log the attacker in as the victim (**token substitution**) |
| Call some `/me` API with the token and trust the answer | No standard, no signature, no proof the token was meant for **your** app |
| Identify users by **email** | Emails change, get recycled, and some providers return **unverified** emails: account takeover (topic 40) |
| Hard-code every provider's URLs and keys | Breaks when the provider rotates keys or moves endpoints |
| Every provider does it differently | One standard: Google, Microsoft, Apple, Okta, Auth0, Keycloak all speak OIDC |

---

### Real-life example: Aadhaar e-KYC at a bank 🪪

Rahul opens an account with a new bank app.

- The bank doesn't ask for his Aadhaar password. It sends him to **UIDAI's own page** (the **OpenID provider**), where he confirms with an OTP. → login happens at the provider
- UIDAI returns a **digitally signed** e-KYC document → the **ID token** (signed JWT)
- The document says **who** (Aadhaar number, name), **issued by** UIDAI (`iss`), **for which bank** (`aud`), **when** (`iat`, `exp`), and carries the bank's **reference number** for this request (`nonce`)
- The bank checks the signature with **UIDAI's public certificate**, published for everyone → **JWKS**
- UIDAI publishes **where everything is** in one place → **discovery**
- The bank links Rahul's account to his **Aadhaar number**, not his mobile number, because mobile numbers change hands → **`sub`, not email**

---

### The vocabulary

| Term | Meaning |
|---|---|
| **OpenID Provider (OP)** | The authorization server that also logs users in and issues ID tokens (Google, Microsoft, PhotoVault in the demo) |
| **Relying Party (RP)** | The app that relies on the OP for login (PrintKaro) |
| **`scope=openid`** | Turns an OAuth request into an OIDC request. Without it, no ID token |
| **ID token** | Signed JWT **for the RP**: who logged in, for whom, when |
| **Access token** | Still there, still **for APIs** (like `/userinfo`). Don't use it as proof of login |
| **`sub`** | The user's **permanent, unique id at this OP**. Never reused, never changes |
| **`iss`** | The OP's identifier (an HTTPS URL). `sub` is only unique **within** an `iss` |
| **Standard scopes** | `profile` (name, picture, …), `email` (email, email_verified), `address`, `phone` |
| **Claims** | The fields: `sub`, `name`, `email`, `email_verified`, `auth_time`, `nonce`, … |
| **Discovery** | `GET {issuer}/.well-known/openid-configuration`: every endpoint and capability |
| **JWKS** | `jwks_uri`: the OP's public signing keys, each with a `kid` |

---

### The flow, step by step

#### 📊 Diagrams

Open **[diagrams.html](diagrams.html)** in your browser (just double-click the file) to see:

- **Flow diagram**: how the RP validates the ID token and finds the account
- **Data flow**: the whole OIDC login between the browser, PrintKaro and PhotoVault, with discovery, JWKS and userinfo
- **Anatomy**: ID token vs access token: what each is for and who checks it

In short: `discovery → /authorize?scope=openid profile email + state + nonce + PKCE → login at the OP → code → /token → access_token + id_token → verify id_token (JWKS key by kid, RS256, iss, aud, exp, nonce) → (optional) /userinfo, sub must match → find account by iss+sub → new session`.

---

### Step 1: Discovery: start from the issuer URL only

```bash
curl http://localhost:3001/.well-known/openid-configuration
```
```json
{"issuer":"http://localhost:3037","authorization_endpoint":"http://localhost:3037/authorize","token_endpoint":"http://localhost:3037/token",
 "userinfo_endpoint":"http://localhost:3037/userinfo","jwks_uri":"http://localhost:3037/jwks.json","id_token_signing_alg_values_supported":["RS256"], ...}
```

- The RP is configured with **one** value: the issuer (`https://accounts.google.com`). Everything else is discovered.
- Check `issuer` in the document **equals** the issuer you asked about.

---

### Step 2: JWKS: the keys that verify ID tokens

```json
{"keys":[{"kty":"RSA","n":"0Wg-2W2v...","e":"AQAB","kid":"pv-9b--Fct_","alg":"RS256","use":"sig"}]}
```

- The OP signs with its **private** key; anyone can verify with the **public** key (RS256, topic 18).
- Each ID token's header says which key: `{"alg":"RS256","kid":"pv-9b--Fct_"}`.
- **Cache** the keys. If a token has an **unknown `kid`**, the OP probably rotated keys: fetch the JWKS **once** more, from the **discovered `jwks_uri` only** (never a URL from the token header).

---

### Step 3: Ask for `openid` (plus state, nonce, PKCE)

```
GET /authorize?response_type=code&client_id=printkaro&redirect_uri=http://localhost:3000/callback
    &scope=openid profile email&state=kz1Thv...&nonce=8z395S...&code_challenge=UO2N4m...&code_challenge_method=S256
```

Everything from topics 33–35 still applies: exact redirect URI, `state` (login CSRF), `nonce` (injection/replay), PKCE (stolen codes).

---

### Step 4: The token response now includes an ID token

```json
{"access_token":"zqZyFC...","token_type":"Bearer","expires_in":600,"scope":"openid email","id_token":"eyJhbGciOiJSUzI1NiIs..."}
```

Decoded (header and payload):

```json
{"alg":"RS256","typ":"JWT","kid":"pv-9b--Fct_"}
{"sub":"248289761001","auth_time":1793857648,"nonce":"n-0S6_WzA2Mj","email":"rahul@example.com","email_verified":true,
 "iat":1793857650,"exp":1793857950,"aud":"printkaro","iss":"http://localhost:3037"}
```

---

### Step 5: Validate the ID token (every time)

```js
const { header } = jwt.decode(idToken, { complete: true });           // only to read kid
const key = await getSigningKey(header.kid);                           // from the cached JWKS
const claims = jwt.verify(idToken, key, { algorithms: ["RS256"], issuer: ISSUER, audience: CLIENT_ID, clockTolerance: 30 });
if (claims.nonce !== pending.nonce) throw ...;                          // topic 35
```

| Check | Why |
|---|---|
| Signature with the JWKS key for `kid`, **algorithm pinned** (`RS256`) | Forged tokens, `alg: none`, HS256-with-public-key (topic 27) |
| `iss` = the configured issuer | Tokens from another provider or tenant |
| `aud` contains **your** `client_id` (and `azp` = you if there are several audiences) | **Token substitution**: an ID token made for another app |
| `exp`, `iat` (small clock tolerance) | Old tokens |
| `nonce` = the one in your session | Injection and replay (topic 35) |
| `auth_time` (if you asked for `max_age`) | "Log in again if it's been more than an hour" |

If the ID token came straight from the `/token` endpoint over HTTPS (the code flow), the spec lets you skip the signature check. **Do it anyway**: it's one library call.

---

### Step 6: Find the account by `iss` + `sub`

```js
const key = `${claims.iss}|${claims.sub}`;      // UNIQUE index in your users table
let account = accounts.get(key) ?? createAccount(claims);
```

- **`sub`** never changes and is never reused. **Emails** do both.
- `sub` is unique **per issuer**: Google's `123` and Microsoft's `123` are different people. Always store both.
- Name, email, picture: a **copy** you refresh on each login, not the identity.
- Only trust `email` for anything important if **`email_verified` is `true`** (and the provider is authoritative for that domain). Linking accounts by email is topic 40.

---

### Step 7 (optional): `/userinfo`

```bash
curl http://localhost:3001/userinfo -H "Authorization: Bearer <access_token>"
→ {"sub":"248289761001","email":"rahul@example.com","email_verified":true}
```

- An OAuth-protected API that returns claims for the granted scopes. Use it when the ID token is kept small, or to refresh profile data.
- Its **`sub` must equal** the ID token's `sub`. If not, ignore the response.
- It takes the **access token**. Sending the ID token gets `401`: they're different things.

---

### ID token vs access token

| | ID token | Access token |
|---|---|---|
| For | **The app (RP)** | **An API** (resource server) |
| Says | "This user logged in, for you, now" | "The bearer may do these scopes" |
| Format | Always a **JWT** | Anything (opaque here, often a JWT) |
| `aud` | Your `client_id` | The API |
| The app should | Verify it, then read the claims | Send it to the API, **not** read or trust it |
| Send it to APIs? | ❌ No | ✅ Yes |

---

### 🤔 Tricky parts

**1. Don't use OAuth alone for login.**
The classic bug: an app does "Log in with X" by accepting any valid **access token** and calling `/me`. An attacker who runs another app the victim used can replay the victim's token to yours. OIDC's `aud` check (ID token **for you**) closes this.

**2. Don't send the ID token to your APIs.**
Its `aud` is the client, not the API. APIs take access tokens (topic 20) or your own session.

**3. ID tokens don't log the user out.**
After login, use **your own session** (topics 09, 25). The ID token is a one-time proof, not a session. Logging out of the OP is "RP-initiated logout" / single logout (Level 8).

**4. `email` is not an identity.**
Some providers allow unverified emails or let users change them. `email_verified: false` (Sneha in the demo) must not be used to match or merge accounts.

**5. Key rotation.**
Cache JWKS, refetch on an unknown `kid`, and don't refetch on every request (rate-limit refetches).

**6. `prompt` and `max_age`.**
`prompt=login` forces the user to log in again (before a payment). `prompt=consent` shows consent again. `max_age=300` + checking `auth_time` makes sure the login is recent.

**7. Use a certified library.**
`openid-client` (Node), Auth.js, Passport strategies, Spring Security: they do discovery, JWKS, state, nonce, PKCE and all checks (topic 41). Writing it by hand, like this demo, is for learning.

---

### Common beginner mistakes

1. **Treating an access token as proof of login.**
   Use the ID token, verified, with `aud` = your client.

2. **`jwt.decode` instead of `jwt.verify`.**
   Decode trusts nothing. Verify with the JWKS key.

3. **Not checking `aud` / `iss`.**
   Token substitution and cross-provider confusion.

4. **Matching users by email.**
   Use `iss` + `sub`. Email is a profile field.

5. **Trusting `email` when `email_verified` is false.**
   Account takeover via account linking (topic 40).

6. **Hard-coding the provider's public key.**
   Breaks at the first key rotation. Use JWKS + `kid`.

7. **Fetching keys from a URL in the token header** (`jku`, `x5u`).
   The attacker controls it. Only the discovered `jwks_uri`.

8. **Sending ID tokens to backend APIs.**
   APIs need access tokens.

9. **Forgetting `nonce`** because "we use the code flow".
   Check it (topic 35).

---

### Interview questions

1. **OAuth 2.0 vs OpenID Connect?**
   OAuth 2.0 is delegated authorization (access tokens for APIs). OIDC is an identity layer on top: `scope=openid` adds an ID token (a signed JWT about the authentication), `/userinfo`, discovery and JWKS.

2. **What is an ID token? Name its key claims.**
   A JWT issued to the client describing the authentication event: `iss`, `sub`, `aud`, `exp`, `iat`, `auth_time`, `nonce`, optionally `azp`, `amr`, `acr`, plus profile claims.

3. **How do you validate an ID token?**
   Get the key by `kid` from the issuer's JWKS; verify the signature with a pinned algorithm; check `iss`, `aud` (and `azp`), `exp`/`iat` with small skew, `nonce`, and `auth_time` if `max_age` was used.

4. **Why identify users by `sub` and not email?**
   `sub` is stable and unique per issuer; emails change, can be reassigned, and may be unverified.

5. **ID token vs access token?**
   The ID token is for the client (proof of authentication, `aud` = client_id). The access token is for APIs (authorization). Don't send ID tokens to APIs; don't use access tokens as login proof.

6. **What is discovery?**
   `/.well-known/openid-configuration`: a JSON document listing the issuer's endpoints, JWKS URI and supported features, so clients configure themselves from the issuer URL.

7. **What is JWKS and why `kid`?**
   A JSON Web Key Set of the provider's public keys. `kid` in the token header tells the client which key to use, allowing key rotation without breaking clients.

8. **What is the userinfo endpoint?**
   An OAuth-protected endpoint returning claims about the user for the granted scopes. Its `sub` must match the ID token's `sub`.

9. **What does `scope=openid` do?**
   Marks the request as OIDC so the provider returns an ID token. `profile`, `email`, `address`, `phone` request standard claims.

10. **What is token substitution?**
    Using a token issued for one client to log in to another. The ID token's `aud` check prevents it.

---

### Quick recap

- OIDC = OAuth 2.0 + **`openid` scope** + **ID token** + userinfo + discovery + JWKS
- **ID token**: signed JWT **for the app**: `iss`, `sub`, `aud`, `exp`, `iat`, `auth_time`, `nonce`
- Start from the **issuer URL**: discovery gives endpoints, **JWKS** gives keys (pick by `kid`, refetch on unknown)
- Validate: **RS256 pinned**, signature, **`iss`**, **`aud`**, `exp`, **`nonce`**
- Identify users by **`iss` + `sub`**, never by email; respect `email_verified`
- `/userinfo` takes the **access token**; its `sub` must match
- ID token → the app; access token → APIs; your own **session** after login
- Next: doing all this with **Google** (topic 37)

## Code

One **Express** file, two apps, using `jsonwebtoken`:

| Port | App | Role |
|---|---|---|
| `3000` | 🖨️ **PrintKaro** | **Relying party**: "Log in with PhotoVault" |
| `3001` | 📸 **PhotoVault** | **OpenID provider**: discovery, JWKS, `/authorize`, `/token` (ID token, RS256), `/userinfo` |

PrintKaro is configured with only the issuer URL, client id and secret. It discovers the endpoints, fetches the JWKS, sends `state` + `nonce` + PKCE, verifies the ID token, checks `/userinfo`'s `sub`, and keeps accounts keyed by `iss|sub`.

Users at PhotoVault (password `chai1234`): `rahul` (`sub` 248289761001, email verified) and `sneha` (`sub` 248289761002, email **not** verified).

📄 **Full code: [server.js](server.js)**. Open it and read the comments, which follow the same steps as the notes above.

Install the dependencies once (from this folder), then start the server:

```bash
npm install
```

```bash
node server.js
```

> Port 3000 busy? Run it on other ports: `PORT=3036 node server.js` (Git Bash) uses **3036** and **3037**. The outputs below were recorded that way, so they show those ports.

### Try it (Git Bash)

```bash
RP=http://localhost:3000; OP=http://localhost:3001
red() { curl -s -o /dev/null -w "%{redirect_url}" "$@"; }
```

🔎 **Discovery and keys** (what PrintKaro reads on startup):

```bash
curl -s $OP/.well-known/openid-configuration
curl -s $OP/jwks.json
```
→
```
{"issuer":"http://localhost:3037","authorization_endpoint":"http://localhost:3037/authorize","token_endpoint":"http://localhost:3037/token","userinfo_endpoint":"http://localhost:3037/userinfo","jwks_uri":"http://localhost:3037/jwks.json","response_types_supported":["code"],"subject_types_supported":["public"],"id_token_signing_alg_values_supported":["RS256"],"scopes_supported":["openid","profile","email"],"claims_supported":["sub","name","given_name","email","email_verified"],"code_challenge_methods_supported":["S256"],"token_endpoint_auth_methods_supported":["client_secret_basic"]}
{"keys":[{"kty":"RSA","n":"0Wg-2W2vNgW4uRus83Qn_S8TzgVnYa1Oz...","e":"AQAB","kid":"pv-9b--Fct_","alg":"RS256","use":"sig"}]}
```

#### 1️⃣ Log in to PrintKaro with PhotoVault

Log in at PhotoVault first (shortcut: a JSON login; topic 33 has the HTML pages):

```bash
curl -s -c r_op.jar $OP/login -H "Content-Type: application/json" -d '{"username":"rahul","password":"chai1234"}'
```

Then the normal "Log in with PhotoVault" button, hop by hop (`r1.jar` = Rahul's browser at PrintKaro):

```bash
L=$(red -c r1.jar -b r1.jar "$RP/login"); echo "$L"
CB=$(red -b r_op.jar "$L"); echo "$CB"
curl -s -c r1.jar -b r1.jar -o /dev/null -w "%{http_code} %{redirect_url}\n" "$CB"
curl -s -b r1.jar $RP/me
```
→
```
http://localhost:3037/authorize?response_type=code&client_id=printkaro&redirect_uri=http%3A%2F%2Flocalhost%3A3036%2Fcallback&scope=openid+profile+email&state=kz1ThvALxlhcLGMIq6eihg&nonce=8z395SB0DqNqq_DNn36vKg&code_challenge=UO2N4mRHm6WyIBgVVa0nLUyvtvux5c_A5Yy25KoICtE&code_challenge_method=S256
http://localhost:3036/callback?code=NKJS2ZbhylswLJtJ1tifiebNWtFhQb8QbRJwoRLPxJE&state=kz1ThvALxlhcLGMIq6eihg
303 http://localhost:3036/me
```
```json
{"account":{"id":"acct_-5UyaA","iss":"http://localhost:3037","sub":"248289761001","createdAt":"2026-11-05T05:47:29.464Z","name":"Rahul Sharma","email":"rahul@example.com","emailVerified":true},
 "idTokenClaims":{"sub":"248289761001","auth_time":1793857648,"nonce":"8z395SB0DqNqq_DNn36vKg","name":"Rahul Sharma","given_name":"Rahul","email":"rahul@example.com","email_verified":true,"iat":1793857649,"exp":1793857949,"aud":"printkaro","iss":"http://localhost:3037"},
 "userinfo":{"sub":"248289761001","name":"Rahul Sharma","given_name":"Rahul","email":"rahul@example.com","email_verified":true}}
```

✅ **Rahul logs in again** from another browser (`r2.jar`, same three lines): same account, `"id":"acct_-5UyaA"`. Terminal: `👋 RP: returning user acct_-5UyaA (iss http://localhost:3037, sub 248289761001)`

✅ **Sneha logs in** (`s_op.jar`, `s1.jar`): a different account, `{"id":"acct_lWVODw",...,"sub":"248289761002",...,"emailVerified":false}`

❌ **Not logged in:** `curl -s $RP/me` → `401 {"error":"Not logged in. Open /login"}`

#### 2️⃣ Be the relying party yourself: see the raw ID token

Make PKCE values (topic 34), get a code (scope `openid email` this time), and exchange it with the client secret:

```bash
V=$(openssl rand -base64 48 | tr '+/' '-_' | tr -d '=\r\n'); CH=$(printf %s "$V" | openssl dgst -sha256 -binary | base64 | tr '+/' '-_' | tr -d '=\r\n')
CB=$(red -b r_op.jar "$OP/authorize?response_type=code&client_id=printkaro&redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fcallback&scope=openid%20email&state=s1&nonce=n-0S6_WzA2Mj&code_challenge=$CH&code_challenge_method=S256")
CODE=$(echo "$CB" | sed 's/.*code=\([^&]*\).*/\1/')
curl -s $OP/token -u printkaro:printkaro-demo-secret -d grant_type=authorization_code -d code=$CODE --data-urlencode "redirect_uri=$RP/callback" -d code_verifier=$V
```
→ `{"access_token":"zqZyFCuPkT7b55zstTQYKUtE85NdQ5t6zcW0HtYLe5A","token_type":"Bearer","expires_in":600,"scope":"openid email","id_token":"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InB2LTliLS1GY3RfIn0.eyJzdWIiOiIy..."}`. Copy: `IDT=...`, `AT=...`

**Decode it** (just to look; this checks nothing):

```bash
node -e "for (const part of process.argv[1].split('.').slice(0, 2)) console.log(Buffer.from(part, 'base64url').toString())" "$IDT"
```
→
```
{"alg":"RS256","typ":"JWT","kid":"pv-9b--Fct_"}
{"sub":"248289761001","auth_time":1793857648,"nonce":"n-0S6_WzA2Mj","email":"rahul@example.com","email_verified":true,"iat":1793857650,"exp":1793857950,"aud":"printkaro","iss":"http://localhost:3037"}
```
`profile` wasn't requested this time, so there's no `name`. Paste `$IDT` into [jwt.io](https://jwt.io) with the JWKS key to see the signature check.

**`/userinfo`** takes the **access** token, not the ID token:

```bash
curl -s $OP/userinfo -H "Authorization: Bearer $AT"
curl -s $OP/userinfo -H "Authorization: Bearer $IDT"
```
→
```
{"sub":"248289761001","email":"rahul@example.com","email_verified":true}
{"error":"invalid_token"} 401
```

❌ **No `openid` in the scope = not an OIDC request:**

```bash
red -b r_op.jar "$OP/authorize?response_type=code&client_id=printkaro&redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fcallback&scope=email&state=s1&code_challenge=$CH&code_challenge_method=S256"
```
→ `http://localhost:3036/callback?error=invalid_scope&error_description=scope+must+include+openid&state=s1`

📋 **The terminal log:**

```
📸 OP: rahul logged in to printkaro [openid,profile,email] → ID token (kid pv-9b--Fct_) + access token
🆕 RP: new account acct_-5UyaA for sub 248289761001
📸 OP: rahul logged in to printkaro [openid,profile,email] → ID token (kid pv-9b--Fct_) + access token
👋 RP: returning user acct_-5UyaA (iss http://localhost:3037, sub 248289761001)
📸 OP: sneha logged in to printkaro [openid,profile,email] → ID token (kid pv-9b--Fct_) + access token
🆕 RP: new account acct_lWVODw for sub 248289761002
```

> **Windows PowerShell users:** the variables, `red()`, cookie jars, `openssl` pipes and `PORT=... node ...` work in Git Bash. In PowerShell, use Git Bash, or `$env:PORT=3036; node server.js`.
