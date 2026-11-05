# 18. JWT Structure, HS256 vs RS256/ES256

## Notes

### What is a JWT?

In Level 1 (topic 09), the server kept a **session** in its database and gave the browser a random id. Every request → look up the id in the database.

A **JWT** (JSON Web Token, say "jot") flips that around: the server writes the user's info **into the token itself** and **signs** it. On the next request, the server doesn't look anything up. It just checks the signature: "did I sign this, and has nobody changed it?"

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImhzLTEifQ.eyJuYW1lIjoiUmFodWwiLCJyb2xlIjoidXNlciIsInN1YiI6InVfMSJ9.bYXog8QLs4PALLbNAWVpv-IVGXx70T4hdJGH0KDpW74
└──────────────── header ─────────────────────────────┘ └─────────────── payload ──────────────────────────────────────┘ └──────── signature ────────────────────┘
```

> **One-line answer:** a JWT is `header.payload.signature`, three base64url parts; anyone can **read** the header and payload, but only the holder of the key can make a valid **signature**, so the server can trust the data without a database lookup.

---

### Why does it matter?

Almost every API, mobile app and microservice system uses JWTs. And most JWT bugs come from not knowing what's inside one.

| If you get it wrong… | What happens |
|---|---|
| You think the payload is secret | You put an email, a phone number or a password in it, and anyone with the token can read it |
| You decode instead of verify | Attacker edits `"role":"user"` → `"admin"` and you believe it |
| You trust the `alg` in the header | `"alg":"none"` or **algorithm confusion** → attacker makes their own valid tokens |
| HS256 secret is `"secret"` or `"myapp123"` | Cracked offline in minutes → attacker signs any token |
| You share the HS256 secret with 5 services | Any of those 5 can now **make** tokens for any user |

---

### Real-life example: a hostel gate pass 🎫

Rahul lives in a college hostel. To go out at night, he needs a **gate pass** from the warden.

1. The pass says: "Rahul, Room 204, may return by **9 pm**, valid today only" → the **payload**.
2. The top says "Signed with the warden's stamp" → the **header** (which algorithm, which key).
3. The warden **stamps** it → the **signature**.
4. The guard at the gate can **read** the pass, and so can anyone who picks it up. It's **not secret**.
5. If Rahul changes "9 pm" to "11 pm", the stamp no longer matches the text → the guard **rejects** it.

Now the two kinds of stamp:

- **HS256 (one shared rubber stamp):** the warden and every guard have a **copy of the same stamp**. Guards can check passes… but any guard could also **make** a pass. Fine if there's just one gate.
- **RS256 / ES256 (private pen + public sample):** only the warden has her **pen** (private key). Guards get a **photo of her signature** (public key) to compare against. They can **check** passes but can **never make** one. Perfect when there are many gates (many services).

---

### The flow, step by step

#### 📊 Diagrams

Open **[diagrams.html](diagrams.html)** in your browser (just double-click the file) to see:

- **Flow diagram**: every check the server does when it verifies a token
- **Data flow**: making a token, verifying it, a tampered token and an `alg: none` token
- **HS256 vs RS256/ES256**: who holds which key, and who can sign vs verify

In short: `header (alg, kid) + payload (claims) → base64url each → sign "header.payload" with the key → token. Verify: split → find key by kid → allow ONLY that key's alg → check signature → check exp, iss, aud → trust the payload`

---

### Step 1: Three parts, joined by dots

| Part | What it is | Example (decoded) |
|---|---|---|
| **Header** | Which algorithm and which key signed it | `{"alg":"HS256","typ":"JWT","kid":"hs-1"}` |
| **Payload** | The data ("claims") about the user | `{"sub":"u_1","name":"Rahul","role":"user","exp":1793844746}` |
| **Signature** | Proof that header + payload weren't changed | 32 random-looking bytes (HS256) |

Each part is **base64url**: normal base64, but `+` → `-`, `/` → `_`, and no `=` padding, so it's safe in URLs and headers.

```js
Buffer.from("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImhzLTEifQ", "base64url").toString();
// '{"alg":"HS256","typ":"JWT","kid":"hs-1"}'
```

⚠️ **base64url is encoding, not encryption.** Anyone can turn it back into text. Paste a token into jwt.io and you'll see everything.

---

### Step 2: The header

| Field | Meaning |
|---|---|
| `alg` | The signing algorithm: `HS256`, `RS256`, `ES256`… |
| `typ` | Usually `"JWT"` |
| `kid` | **Key ID**: which key signed it. Lets you have several keys and rotate them (topic 54) |

The header is written by **whoever made the token**. If an attacker made it, they wrote it. So it can **point to** a key, but must never **decide** how you verify.

---

### Step 3: The payload (claims)

**Registered claims** (standard names from RFC 7519, all optional, all short):

| Claim | Name | Example |
|---|---|---|
| `sub` | Subject: who it's about | `"u_1"` (the user id, not the email) |
| `iss` | Issuer: who made it | `"https://auth.myapp.com"` |
| `aud` | Audience: who it's for | `"demo-api"` |
| `exp` | Expires at (seconds since 1970) | `1793844746` |
| `iat` | Issued at | `1793843846` |
| `nbf` | Not valid before | `1793843846` |
| `jti` | Token id (unique) | `"9f1c…"`, used for revocation (topic 24) |

Plus **your own claims**: `name`, `role`, `tenantId`…

| ✅ Put in the payload | ❌ Never put in the payload |
|---|---|
| User id (`sub`), role, expiry | Passwords or password hashes |
| Things needed on every request | Email, phone, address, Aadhaar/PAN (anyone can read it) |
| Small values | Big objects: the token goes in **every** request header |

Claims are checked in detail in topic 27.

---

### Step 4: The signature

The signature is made over the **exact text** `base64url(header) + "." + base64url(payload)`. Change one character and the signature no longer matches.

**HS256 is just HMAC-SHA256.** Our [server.js](server.js) proves it by building the signature by hand and comparing:

```js
crypto.createHmac("sha256", secret).update(`${header}.${payload}`).digest("base64url");
// === the third part of the token jsonwebtoken made ✅
```

| Algorithm | How the signature is made | Key |
|---|---|---|
| **HS256** | HMAC with SHA-256 | **One shared secret** (at least 256 random bits) |
| **RS256** | RSA signature (PKCS#1 v1.5) with SHA-256 | **Private key** signs, **public key** verifies (RSA 2048+ bits) |
| **ES256** | ECDSA on the P-256 curve with SHA-256 | **Private key** signs, **public key** verifies (much smaller keys) |

---

### Step 5: HS256 vs RS256 vs ES256

| | HS256 | RS256 | ES256 |
|---|---|---|---|
| Type | Symmetric (one key) | Asymmetric (key pair) | Asymmetric (key pair) |
| Who can **sign** | Anyone with the secret | Only the private key holder | Only the private key holder |
| Who can **verify** | Anyone with the **same** secret | Anyone with the **public** key | Anyone with the **public** key |
| Signature size | 32 bytes | 256 bytes | 64 bytes |
| Token length in our demo | 263 chars | 562 chars | 306 chars |
| Can you publish the verify key? | ❌ Never (it can also sign) | ✅ Yes (JWKS) | ✅ Yes (JWKS) |
| Good for | One app that makes **and** checks its own tokens | Many services / third parties verifying; very widely supported | Same as RS256, with smaller tokens and keys |

**How to choose:**

- **One backend** that both issues and checks tokens → **HS256** is simple and fine, with a strong random secret.
- **Microservices**, mobile + many APIs, or **other companies** verify your tokens → **RS256 or ES256**. Only the auth server holds the private key; a hacked "orders" service can't make tokens.
- OAuth / OpenID Connect providers (Google, Auth0, Cognito, Level 5) sign with **RS256** (some also ES256), and publish their public keys at a **JWKS** URL.

---

### Step 6: Verify the right way

```js
const kid = parts.header?.kid;
if (typeof kid !== "string" || !Object.hasOwn(KEYS, kid)) throw new Error("unknown key id (kid)");
const key = KEYS[kid];
jwt.verify(token, key.verifyWith, {
  algorithms: [key.alg],   // ONLY the algorithm this key is for
  issuer: ISSUER,
  audience: AUDIENCE,      // exp is checked automatically
});
```

| ✅ Do | ❌ Don't |
|---|---|
| `jwt.verify()` with `algorithms: [...]` pinned | `jwt.decode()` and trust the result |
| Choose the algorithm from **your key**, not from the header | `jwt.verify(token, key)` with no `algorithms` |
| Check `exp`, `iss`, `aud` | Accept tokens made for another app (wrong `aud`) |
| Use a well-known library (`jsonwebtoken`, `jose`) | Write your own verify with `===` (not timing-safe, easy to get wrong) |

---

### Step 7: JWKS: publishing public keys

With RS256/ES256, the auth server publishes its **public** keys as JSON at a well-known URL:

```
GET /.well-known/jwks.json
{ "keys": [ { "kty": "RSA", "kid": "rs-1", "alg": "RS256", "n": "o_Vu…", "e": "AQAB" },
            { "kty": "EC",  "kid": "es-1", "alg": "ES256", "crv": "P-256", "x": "pCuA…", "y": "mCxO…" } ] }
```

Other services download it (and cache it), find the key by the token's `kid`, and verify. **Key rotation** (topic 54): add a new key with a new `kid`, start signing with it, and remove the old key once old tokens have expired.

---

### 🤔 Tricky parts

**1. `"alg": "none"`.**
The JWT standard allows unsigned tokens with `"alg":"none"` and an empty signature. An old library that trusted the header would accept `eyJhbGciOiJub25lIn0.eyJyb2xlIjoiYWRtaW4ifQ.` as valid. Fix: always pin `algorithms`.

**2. Algorithm confusion (RS256 → HS256).**
Your server verifies RS256 with the **public** key. The attacker downloads that public key (it's public!), makes a token with `"alg":"HS256"` and signs it with HMAC **using the public key as the secret**. A server that lets the header pick the algorithm runs HMAC with the public key, and it matches. Fix: one algorithm per key, pinned. Our demo's self-check runs this attack at every start. More in topic 53.

**3. Decode ≠ verify.**
`jwt.decode()` only base64-decodes. It's fine for a **frontend** to read `exp` or `name` for display, but the **backend** must always `verify`.

**4. Weak HS256 secrets can be cracked offline.**
An attacker with **one** token can try billions of secrets per second on their own GPU (no requests to your server). `"secret"`, `"jwt-key"`, or your app name fall in seconds. Use `crypto.randomBytes(32)`.

**5. Signed ≠ encrypted.**
A JWT (JWS) is **signed**: readable by all, changeable by none. If you really need hidden contents, there's **JWE** (encrypted JWT), but usually the answer is "don't put secrets in the token".

**6. ES256 signatures change every time.**
Sign the same payload twice with ES256 and you get two different signatures (ECDSA uses a random number). Both are valid. HS256 and RS256 give the same signature every time.

---

### Common beginner mistakes

1. **Thinking a JWT is encrypted.**
   It's only base64url. Anyone can read the payload.

2. **Putting personal or secret data in the payload.**
   Emails, phone numbers and password hashes leak to anyone who sees the token (logs, browser extensions).

3. **Using `jwt.decode()` on the backend instead of `jwt.verify()`.**
   Anyone can then make an "admin" token.

4. **Not pinning `algorithms`.**
   Opens the door to `alg: none` and algorithm confusion.

5. **A short, guessable HS256 secret, or one committed to Git.**
   Use 32 random bytes from a secrets manager or env var.

6. **Sharing the HS256 secret with every microservice.**
   Every service can now forge tokens. Use RS256/ES256 and share only the public key.

7. **No `exp`, or `exp` in days.**
   A stolen token works forever. Keep access tokens short (topic 20) and use refresh tokens (topic 21).

8. **Putting the whole user object in the token.**
   Big tokens slow down every request, and the data goes stale (role changes, topic 24).

9. **Not checking `aud` and `iss`.**
   A token made for another app (or by another issuer) is accepted by yours.

---

### Interview questions

1. **What are the three parts of a JWT?**
   Header (algorithm, type, key id), payload (claims), and signature, each base64url-encoded and joined by dots. The signature is over `header.payload`.

2. **Is a JWT encrypted? Can a user read it?**
   No. A normal JWT is signed, not encrypted. Anyone can decode the header and payload. JWE exists for encryption.

3. **What's the difference between HS256 and RS256?**
   HS256 uses one shared secret (HMAC) for both signing and verifying. RS256 uses an RSA key pair: the private key signs and the public key verifies, so verifiers can't create tokens.

4. **When would you pick RS256/ES256 over HS256?**
   When services other than the issuer need to verify tokens: microservices, third parties, OAuth/OIDC. They get only the public key, so a compromised service can't forge tokens.

5. **ES256 vs RS256?**
   Both are asymmetric. ES256 (ECDSA P-256) has much smaller keys and signatures (64 vs 256 bytes) for similar security. RS256 is older and supported everywhere.

6. **What is the `alg: none` attack?**
   An unsigned token with `"alg":"none"`. A library that trusts the header accepts it. Fix: pin the allowed algorithms.

7. **What is algorithm confusion?**
   The attacker switches `RS256` to `HS256` and signs with the public key as an HMAC secret. If the server lets the header choose the algorithm, it verifies with the public key as the HMAC secret and accepts it. Fix: pin algorithms per key.

8. **What is `kid` and JWKS?**
   `kid` names the key that signed the token. JWKS is a JSON list of public keys at a URL (often `/.well-known/jwks.json`), so verifiers can find the right key and keys can be rotated.

9. **Why is a JWT "stateless", and what's the downside?**
   The server trusts the signature instead of a database lookup. The downside: you can't easily cancel a token before it expires (topic 24).

10. **What's the difference between `jwt.decode` and `jwt.verify`?**
    Decode only reads the parts. Verify checks the signature, algorithm and claims. Only verified data can be trusted.

---

### Quick recap

- JWT = `base64url(header).base64url(payload).signature`
- **Readable by anyone, changeable by no one** without the key: no secrets in the payload
- Standard claims: `sub`, `iss`, `aud`, `exp`, `iat`, `nbf`, `jti`
- **HS256** = HMAC with one shared secret (signs **and** verifies), 256+ random bits
- **RS256 / ES256** = private key signs, public key verifies; publish public keys as **JWKS**
- ES256: smaller keys and signatures than RS256
- Always **verify**, never just decode; **pin `algorithms`** per key; check `exp`, `iss`, `aud`
- Watch out for **`alg: none`** and **algorithm confusion** (topic 53)

## Code

A small **Express** API using **`jsonwebtoken`** (the library this topic is about) and Node's built-in `crypto` for the keys. It makes tokens with HS256, RS256 and ES256, shows their parts, decodes them without checking, verifies them properly, and publishes the public keys as a JWKS. At every start it runs a **self-check**: it rebuilds the HS256 signature by hand with HMAC, and tries a tampered token, an `alg: none` token and an algorithm-confusion token (all must be rejected).

📄 **Full code: [server.js](server.js)**. Open it and read the comments, which follow the same steps as the notes above.

Install the packages once (from this folder), then start the server:

```bash
npm install
```

```bash
node server.js
```

You should see:

```
✅ Self-check passed: HS256 = HMAC by hand, tampering, alg:none and alg confusion are all rejected
JWT structure demo on http://localhost:3000
```

> Port 3000 busy? Run it on another port: `PORT=3018 node server.js` (Git Bash), then use that port in the commands below.

The keys are made fresh at every start, so your tokens and signatures will look different from the ones below (which come from a test run on port 3018), and old tokens stop working after a restart.

### Try it

✅ **Make an HS256 token:**

```bash
curl -X POST http://localhost:3000/tokens -H "Content-Type: application/json" -d '{"alg":"HS256"}'
```
→ `201 Created` with:

```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImhzLTEifQ.eyJuYW1lIjoiUmFodWwiLCJyb2xlIjoidXNlciIsImlhdCI6MTc5Mzg0Mzg0NiwiZXhwIjoxNzkzODQ0NzQ2LCJhdWQiOiJkZW1vLWFwaSIsImlzcyI6Imh0dHA6Ly9sb2NhbGhvc3Q6MzAxOCIsInN1YiI6InVfMSJ9.bYXog8QLs4PALLbNAWVpv-IVGXx70T4hdJGH0KDpW74",
  "header": { "alg": "HS256", "typ": "JWT", "kid": "hs-1" },
  "payload": { "name": "Rahul", "role": "user", "iat": 1793843846, "exp": 1793844746, "aud": "demo-api", "iss": "http://localhost:3018", "sub": "u_1" },
  "signature": "bYXog8QLs4PALLbNAWVpv-IVGXx70T4hdJGH0KDpW74",
  "signatureBytes": 32,
  "tokenLength": 263
}
```

✅ **Compare with RS256 and ES256:** same payload, different signatures.

```bash
curl -X POST http://localhost:3000/tokens -H "Content-Type: application/json" -d '{"alg":"RS256"}'
```
→ `"signatureBytes": 256, "tokenLength": 562`

```bash
curl -X POST http://localhost:3000/tokens -H "Content-Type: application/json" -d '{"alg":"ES256"}'
```
→ `"signatureBytes": 64, "tokenLength": 306`

❌ **An algorithm we don't allow:**

```bash
curl -i -X POST http://localhost:3000/tokens -H "Content-Type: application/json" -d '{"alg":"none"}'
```
→ `400 Bad Request` with `{"error":"alg must be HS256, RS256 or ES256"}`

Save a token in a shell variable for the next steps (Git Bash; `node -pe` pulls out the `token` field):

```bash
TOKEN=$(curl -s -X POST http://localhost:3000/tokens -H "Content-Type: application/json" -d '{"alg":"HS256"}' | node -pe 'JSON.parse(require("fs").readFileSync(0)).token')
```

👀 **Decode it: no key needed, anyone can read it:**

```bash
curl -X POST http://localhost:3000/decode -H "Content-Type: application/json" -d "{\"token\":\"$TOKEN\"}"
```
→ `{"header":{"alg":"HS256","typ":"JWT","kid":"hs-1"},"payload":{"name":"Rahul","role":"user",...,"sub":"u_1"},"warning":"Decoded only, NOT verified. Never trust this for auth."}`

✅ **Verify it:**

```bash
curl -X POST http://localhost:3000/verify -H "Content-Type: application/json" -d "{\"token\":\"$TOKEN\"}"
```
→ `{"valid":true,"payload":{"name":"Rahul","role":"user","iat":1793843846,"exp":1793844746,"aud":"demo-api","iss":"http://localhost:3018","sub":"u_1"}}`

❌ **Tamper with it: make yourself admin:** keep the header and signature, swap in a new payload.

```bash
PAYLOAD=$(printf '{"name":"Rahul","role":"admin","sub":"u_1"}' | base64 | tr '+/' '-_' | tr -d '=')
TAMPERED="$(echo $TOKEN | cut -d. -f1).$PAYLOAD.$(echo $TOKEN | cut -d. -f3)"
curl -i -X POST http://localhost:3000/verify -H "Content-Type: application/json" -d "{\"token\":\"$TAMPERED\"}"
```
→ `401 Unauthorized` with `{"valid":false,"error":"Invalid token","reason":"invalid signature"}`

❌ **The `alg: none` attack:** an unsigned token (note the empty third part after the last dot).

```bash
NONE="$(printf '{"alg":"none","typ":"JWT","kid":"hs-1"}' | base64 | tr '+/' '-_' | tr -d '=').$(echo $TOKEN | cut -d. -f2)."
curl -i -X POST http://localhost:3000/verify -H "Content-Type: application/json" -d "{\"token\":\"$NONE\"}"
```
→ `401 Unauthorized` with `{"valid":false,"error":"Invalid token","reason":"jwt signature is required"}`

❌ **Not a JWT at all:**

```bash
curl -i -X POST http://localhost:3000/verify -H "Content-Type: application/json" -d '{"token":"hello"}'
```
→ `401 Unauthorized` with `{"valid":false,"error":"Invalid token","reason":"jwt malformed"}`

🔑 **The public keys (JWKS):** only RS256 and ES256. The HS256 secret is never published.

```bash
curl http://localhost:3000/.well-known/jwks.json
```
→ `{"keys":[{"kty":"RSA","n":"o_VuTfn2…","e":"AQAB","kid":"rs-1","alg":"RS256","use":"sig"},{"kty":"EC","x":"pCuAxxEc…","y":"mCxOuB18…","crv":"P-256","kid":"es-1","alg":"ES256","use":"sig"}]}`

> **Windows PowerShell users:** the single quotes in `-d '...'`, `$(...)`, `base64`, `tr` and `cut` above work in Git Bash. In PowerShell, use Git Bash or Postman.
