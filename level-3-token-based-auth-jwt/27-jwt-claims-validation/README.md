# 27. JWT Claims Validation

## Notes

### What is claims validation?

A JWT's signature only proves **"someone with the key made this, and nobody changed it"**. It doesn't prove the token is **for you**, **still valid**, **the right kind of token**, or **about a real user**. Those facts live in the **claims** (`iss`, `aud`, `exp`, `nbf`, `iat`, `sub`, …) and in the **header** (`alg`, `typ`), and your API has to check every one of them.

> **One-line answer:** before trusting a JWT, check: the **algorithm** is the one you expect (pinned, never `none`), the **signature**, **`iss`** = your auth server, **`aud`** = this API, **`exp`** / **`nbf`** / **`iat`** with a small clock tolerance, the token **type** (access, not refresh/ID), and that required claims like **`sub`** exist. Then return one generic `401` and log the real reason.

---

### Why does it matter?

Every missing check is a real attack:

| Check you skipped | What an attacker does |
|---|---|
| `alg` not pinned | Sends `alg: "none"` with no signature, or HS256 signed with your **public** key ("algorithm confusion") |
| Signature not verified (`jwt.decode` instead of `jwt.verify`) | Writes any payload they like: `"sub": "u_admin"` |
| `aud` | Uses a token made for the **reports API** on the **payments API** |
| `iss` | Uses a token from **staging** (or another tenant on the same identity provider) in **production** |
| `exp` | Uses a token from last year |
| `nbf` / `iat` in the future | Uses tokens minted with a wrong or forged clock |
| `typ` | Sends a **refresh token** or an **ID token** where an access token is expected |
| `sub` | Your code reads `undefined` as the user id |

---

### Real-life example: a train ticket on Indian Railways 🚆

The TTE checks Rahul's ticket on the Rajdhani from Delhi to Mumbai.

1. **Is it a real IRCTC ticket?** Hologram / QR checks out → **signature** (with the right algorithm, not a photocopy)
2. **Issued by IRCTC**, not a fake booking site → **`iss`**
3. **For this train**, not the Shatabdi → **`aud`**
4. **For today's journey**, not last month's → **`exp`**; and not next week's → **`nbf`**
5. A **ticket**, not a platform ticket → **`typ`** (right kind of token)
6. **Passenger name** is there and matches his ID → **`sub`**
7. The TTE's watch is a few minutes off from the station clock, so he allows **a little slack** → **clock tolerance**
8. If anything is wrong, he says "Invalid ticket", not "the third digit of your PNR is wrong" → **generic error, detailed log**

---

### The flow, step by step

#### 📊 Diagrams

Open **[diagrams.html](diagrams.html)** in your browser (just double-click the file) to see:

- **Flow diagram**: the checks in order, and which attack each one stops
- **Data flow**: a good token, then three attack tokens, against the same API
- **Anatomy**: which header fields and claims are checked by what

In short: `split → header.alg pinned (RS256) → signature → iss → aud → exp/nbf (± 30 s) → iat not in the future, not too old → header.typ = at+jwt → sub present → trust the payload`. Any failure → `401 Invalid access token` + log the reason.

---

### Step 1: Pin the algorithm

```js
jwt.verify(token, PUBLIC_KEY, { algorithms: ["RS256"] });
```

The header says which algorithm was used, and **the attacker writes the header**. So never let the token choose:

- **`alg: "none"`**: an unsigned token. Some old libraries accepted it as valid.
- **Algorithm confusion**: the API verifies RS256 with a **public** key. The attacker makes an **HS256** token and uses that same public key as the HMAC secret. A library that picks the algorithm from the header computes HMAC with the public key, and the signature matches! The public key is public, so anyone can do this.

Both are stopped by **one line**: an explicit allow-list with exactly the algorithm you use. (Modern `jsonwebtoken` versions also refuse an RSA key with HS256, but don't rely on library defaults.)

| ✅ Do | ❌ Don't |
|---|---|
| `algorithms: ["RS256"]` (or `["HS256"]`) | Leave `algorithms` out |
| `jwt.verify(...)` | `jwt.decode(...)` and trust the result: **decode does not verify** |
| One algorithm per key | Accept "whatever the header says" |

---

### Step 2: Who made it, and for whom? (`iss`, `aud`)

```js
jwt.verify(token, PUBLIC_KEY, { algorithms: ["RS256"], issuer: "https://auth.example.com", audience: "orders-api" });
```

- **`iss` (issuer)**: the auth server that created it. Staging and production, or two customers (tenants) on the same identity provider, may share keys or key formats. Without `iss`, a staging token works in production.
- **`aud` (audience)**: the API it was made for. One auth server makes tokens for many APIs. Without `aud`, a token for the low-risk reports API works on the payments API. Each API checks for **its own name**.

---

### Step 3: Is it valid **now**? (`exp`, `nbf`, `iat`)

```js
jwt.verify(token, PUBLIC_KEY, { ..., clockTolerance: 30, maxAge: "1h" });
if (payload.iat > now() + 30) throw new Error("iat is in the future");
```

| Claim | Meaning | Check |
|---|---|---|
| `exp` | Expires at (Unix seconds) | `now < exp` (+ tolerance). Library does it |
| `nbf` | Not valid before | `now >= nbf` (- tolerance). Library does it |
| `iat` | Issued at | Not in the future (you check), not older than `maxAge` (library, if you set it) |

- **Clock tolerance** (here 30 s): servers' clocks drift a little. Without it, a token can fail just because the API's clock is 2 seconds ahead. Keep it **small**; it's not a way to make tokens live longer. The demo shows a token that expired **10 s** ago being accepted, and one that expired **5 minutes** ago being rejected.
- **`maxAge`**: protects you from a misconfigured issuer that hands out tokens with `exp` a year away.
- Most libraries check `exp` only **if it exists**. Require it: a token without `exp` should be rejected (`jsonwebtoken` options like `maxAge` require `iat`; you can also check `typeof payload.exp === "number"`).

---

### Step 4: Is it the right **kind** of token? (`typ`)

```js
if (header.typ !== "at+jwt") throw new Error("not an access token");
```

The same auth server, often with the **same key**, signs **access tokens**, **refresh tokens** (if they're JWTs) and OpenID Connect **ID tokens** (Level 5). They all pass the signature check. RFC 9068 gives access tokens the header `typ: "at+jwt"` exactly so APIs can tell them apart. Other ways: a `token_use` claim, or different keys / audiences per token type.

An **ID token** says "this person logged in to the **web app**"; it's not permission to call your API. Don't accept it as an access token.

---

### Step 5: Required claims

```js
if (typeof payload.sub !== "string" || !payload.sub) throw new Error("sub is missing");
```

Check every claim your code **uses**, and its **type**:

- `sub`: the user id. A string, not empty
- `jti`: if you deny-list tokens (topic 24)
- `sid`, `ver`: if you revoke sessions/devices (topics 24, 26)
- `scope` / `roles`: if you authorize with them (Level 4). Check against an allow-list, never trust free text

After validation, **look things up by `sub`**, don't trust everything else in the payload: an email in a token can be stale.

---

### Step 6: Fail closed, with a boring error

```js
console.log(`❌ rejected token: ${err.message}`);          // the detail goes to YOUR logs
res.set("WWW-Authenticate", 'Bearer error="invalid_token"');
res.status(401).json({ error: "Invalid access token" });  // the client gets one generic message
```

- **Any** exception → `401`. Never "log it and continue".
- Don't tell attackers which check failed ("audience invalid" tells them the token is otherwise good). The demo adds a `debugReason` only when `NODE_ENV` isn't `production`, so you can see which check fired.
- Do the validation in **one shared function / middleware**, so no route forgets a check.

---

### 🤔 Tricky parts

**1. `jwt.decode` vs `jwt.verify`.**
`decode` just base64-decodes the payload. It's fine for reading `exp` in the frontend (topic 22) but **never** for trusting a token on the server.

**2. Key rotation and `kid`.**
Auth servers change keys over time. The header's `kid` (key id) says which public key to use from the auth server's **JWKS** URL (`/.well-known/jwks.json`). Fetch keys only from **your configured issuer's** URL, never from a URL inside the token (`jku`/`x5u` headers). Libraries like `jose` and `jwks-rsa` handle this (Level 5).

**3. `aud` can be an array.**
`"aud": ["orders-api", "reports-api"]` is valid; the check is "my name is in the list". Libraries handle it.

**4. Library defaults differ.**
Some check `exp` but not `aud` unless you pass it, and some allow any algorithm by default. Read your library's options; every check in this topic is one option you **pass**.

**5. Validate in every service.**
In microservices, each API validates the token itself (with its own `aud`). Don't trust "the gateway already checked" unless the network is locked down so nothing else can reach the service.

**6. HS256 secrets.**
With HS256, every service that verifies also holds the secret and can **create** tokens. Use a long random secret (at least 32 bytes), or switch to RS256/ES256 so APIs only hold the public key (topic 18).

---

### Common beginner mistakes

1. **Using `jwt.decode` on the server.**
   No signature check at all. Always `jwt.verify`.

2. **Not pinning `algorithms`.**
   Opens the door to `alg: none` and algorithm confusion.

3. **Skipping `aud` and `iss`.**
   Tokens from other APIs or other environments work on yours.

4. **No clock tolerance, or a huge one.**
   Random failures, or tokens that live much longer than intended. 30–60 s is plenty.

5. **Accepting refresh or ID tokens as access tokens.**
   Check `typ` (or `token_use`), or use different keys/audiences.

6. **Trusting claims you didn't validate.**
   `roles: ["admin"]` in a token you didn't fully verify is just text.

7. **Detailed error messages to the client.**
   Log the reason, return a generic `401`.

8. **Checking claims in each route by hand.**
   One middleware, used everywhere.

9. **Fetching the verification key from a URL in the token header.**
   The attacker controls that URL. Use your configured issuer's JWKS only.

---

### Interview questions

1. **What do you validate in a JWT?**
   Algorithm (pinned), signature, `iss`, `aud`, `exp`, `nbf`, `iat` (with small clock tolerance and a max age), the token type (`typ: at+jwt`), and the presence and type of claims the code uses, like `sub`.

2. **What is the `alg: none` attack?**
   A token with `alg: none` and no signature. A library that trusts the header treats it as valid, so anyone can forge tokens. Prevented by pinning allowed algorithms.

3. **What is algorithm confusion?**
   The server verifies RS256 with a public key. The attacker signs an HS256 token using that public key as the HMAC secret. If the library uses the header's algorithm, the HMAC check passes. Prevented by pinning `algorithms: ["RS256"]`.

4. **Why check `aud`?**
   One auth server issues tokens for many APIs. Without `aud`, a token for one API can be replayed against another.

5. **Why check `iss`?**
   To accept only tokens from your auth server and environment. A staging or other-tenant token must not work in production.

6. **What is clock skew tolerance?**
   A few seconds of leeway when checking `exp`/`nbf`/`iat`, because servers' clocks differ slightly. Keep it small (30–60 s).

7. **How do you stop a refresh token or ID token being used as an access token?**
   Check the header `typ` (`at+jwt` per RFC 9068) or a `token_use` claim, and/or use different audiences or keys per token type.

8. **`jwt.decode` vs `jwt.verify`?**
   `decode` only parses; `verify` checks the signature and claims. Never trust `decode` output on the server.

9. **What should the error response look like?**
   `401` with `WWW-Authenticate: Bearer error="invalid_token"` and a generic message. The specific reason goes to server logs.

---

### Quick recap

- Signature ≠ validity. Check the **header** and **every claim** you rely on
- **Pin `algorithms`**: blocks `alg: none` and HS256-with-the-public-key
- **`iss`** = your auth server, **`aud`** = this API
- **`exp`**, **`nbf`**, **`iat`** with a **small clock tolerance** (30 s) and a **max age**
- **`typ: at+jwt`**: access tokens only, not refresh or ID tokens
- **Required claims** (`sub`, …) present and the right type
- **`jwt.verify`, never `jwt.decode`**, in **one middleware**
- Generic **`401`** to the client, the real reason in the logs
- Level 3 done. Next: what the user is **allowed** to do (Level 4: authorization)

## Code

A small **Express** + **`jsonwebtoken`** API with one protected route, `GET /orders`, guarded by `verifyAccessToken()`: every check from the notes, in order. Tokens are signed with **RS256**. A dev-only **token lab** (`/lab/token/:case`) makes tokens with exactly **one** thing wrong, so you can watch each check reject the right one.

📄 **Full code: [server.js](server.js)**. Open it and read the comments, which follow the same steps as the notes above.

Install the dependencies once (from this folder), then start the server:

```bash
npm install
```

```bash
node server.js
```

> Port 3000 busy? Run it on another port: `PORT=3027 node server.js` (Git Bash), then use that port in the commands below.

### Try it

✅ **See the cases:**

```bash
curl http://localhost:3000/lab/cases
```
→ `{"valid":"Nothing. Should be accepted","expired-10s-ago":"exp was 10 s ago, inside the 30 s clock tolerance: accepted","expired":"exp was 5 minutes ago",...}`

✅ **Get a good token and call the API:**

```bash
curl http://localhost:3000/lab/token/valid
```
→ `{"case":"valid","whatIsWrong":"Nothing. Should be accepted","token":"eyJhbGciOiJSUzI1NiIsInR5cCI6ImF0K2p3dCJ9..."}`. Copy the token: `TOKEN=eyJ...`

```bash
curl http://localhost:3000/orders -H "Authorization: Bearer $TOKEN"
```
→ `{"user":"u_rahul","orders":[{"id":"ord_1","item":"Masala chai (500 g)","total":"₹240"}]}`

🧪 **Run every case at once** (Git Bash):

```bash
for c in valid expired-10s-ago expired not-yet-valid issued-in-future too-old wrong-audience wrong-issuer refresh-as-access missing-sub tampered alg-none hs256-with-public-key; do T=$(curl -s http://localhost:3000/lab/token/$c | grep -o '"token":"[^"]*' | cut -d'"' -f4); printf "%-22s → " $c; curl -s http://localhost:3000/orders -H "Authorization: Bearer $T"; echo; done
```
→
```
valid                  → {"user":"u_rahul","orders":[{"id":"ord_1","item":"Masala chai (500 g)","total":"₹240"}]}
expired-10s-ago        → {"user":"u_rahul","orders":[{"id":"ord_1","item":"Masala chai (500 g)","total":"₹240"}]}
expired                → {"error":"Invalid access token","debugReason":"jwt expired"}
not-yet-valid          → {"error":"Invalid access token","debugReason":"jwt not active"}
issued-in-future       → {"error":"Invalid access token","debugReason":"iat is missing or in the future"}
too-old                → {"error":"Invalid access token","debugReason":"maxAge exceeded"}
wrong-audience         → {"error":"Invalid access token","debugReason":"jwt audience invalid. expected: orders-api"}
wrong-issuer           → {"error":"Invalid access token","debugReason":"jwt issuer invalid. expected: https://auth.example.com"}
refresh-as-access      → {"error":"Invalid access token","debugReason":"wrong token type: typ is \"refresh+jwt\", expected \"at+jwt\""}
missing-sub            → {"error":"Invalid access token","debugReason":"sub (the user id) is missing"}
tampered               → {"error":"Invalid access token","debugReason":"invalid signature"}
alg-none               → {"error":"Invalid access token","debugReason":"jwt signature is required"}
hs256-with-public-key  → {"error":"Invalid access token","debugReason":"invalid algorithm"}
```

Each bad token fails at **exactly** the check that's meant to catch it. The terminal logs each one as `❌ rejected token: ...`. Note `expired-10s-ago` is accepted thanks to the 30-second clock tolerance.

🔍 **Look inside an attack token:** paste the `alg-none` or `hs256-with-public-key` token into [jwt.io](https://jwt.io): the header says `"alg":"none"` / `"alg":"HS256"` and the payload says `"sub":"u_admin"`. Only `algorithms: ["RS256"]` stands between that and an admin login.

✅ **Production mode hides the reason:**

```bash
NODE_ENV=production node server.js
```
Now a bad token gets only `{"error":"Invalid access token"}` (plus `WWW-Authenticate: Bearer error="invalid_token"`). The reason still appears in the terminal.

> **Windows PowerShell users:** the `for` loop, `TOKEN=...` / `$TOKEN` and `VAR=value node ...` work in Git Bash. In PowerShell, use Git Bash, Postman, or `$env:NODE_ENV="production"; node server.js`.
