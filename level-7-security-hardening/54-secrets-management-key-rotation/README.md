# 54. Secrets Management & Key Rotation

## Notes

### What is secrets management?

A **secret** is any value that lets someone act as your system: the JWT signing key, the database password, the key that encrypts PAN numbers, the Razorpay API key, the webhook signing secret, an admin token. **Secrets management** is how you keep them out of code, give them only to the processes that need them, and **replace them** (rotate) on a schedule or the moment one leaks.

Every topic so far relied on a secret staying secret: the JWT key (Level 3), the TOTP encryption key (topic 44), the CSRF and session keys (topics 10, 47). This topic is about **where those keys live and how you change them without logging everyone out or losing data**.

> **One-line answer:** keep secrets **out of code and Git**, load them from the **environment or a secrets manager / KMS**, **fail fast** if one is missing, **never log** them, and design every key to be **rotatable**: tokens carry a **`kid`**, encrypted rows carry a **key ID**, the old key stays **verify/decrypt-only** until its tokens expire or its rows are **re-encrypted**, and then it's retired.

---

### Why it matters

| Problem | What happens |
|---|---|
| **Secret in the code** (`const JWT_SECRET = "supersecret"`) | It's in Git history forever, on every laptop, in every fork. Bots scan public GitHub for keys within minutes of a push. |
| **Secret in logs** | `console.log(req.body)` prints passwords; an error log prints the `Authorization` header. Logs go to many more people and tools than your database. |
| **One key, never changed** | A key that leaked two years ago still works today. Nobody knows who has a copy (ex-employees, an old backup). |
| **Rotation that breaks everything** | Change the JWT key and every user is logged out; change the encryption key and old rows can't be decrypted. So nobody rotates. |
| **Emergency with no plan** | The key leaks on a Friday night, and the team discovers the app has no way to switch keys without a code change. |

Leaked credentials are one of the most common ways breaches start (Verizon DBIR, year after year). Uber (2016) lost 57 million records because AWS keys were committed to a private GitHub repo.

---

### Real-life example: the bank locker room 🏦

Rahul runs a small bank branch in Jaipur. The lockers open with keys.

1. Keys are **not taped under the counter** (in the code). They sit in the **key safe** in the manager's cabin → a **secrets manager / KMS**
2. Staff get only the keys their job needs, and every use is written in the register → **least privilege + audit log**
3. Each locker has a **number plate saying which key opens it** → the **key ID** stored next to encrypted data, the **`kid`** in a JWT header
4. Every year Rahul gets **new keys**. Old keys keep working while customers are moved over one by one, then the old keys are **destroyed** → **rotation** with an overlap period
5. If a key is **stolen**, he doesn't wait for the yearly change: the old lock is blocked **today**, and customers come back for a new key → **emergency rotation**: retire the key now, accept that its tokens stop working
6. He never destroys an old key while a locker still uses it, because then the locker can **never** be opened → never delete a data key that still has rows

---

### The big picture

#### 📊 Diagrams

Open **[diagrams.html](diagrams.html)** in your browser (just double-click the file) to see:

- **Flow diagram**: a signing-key rotation, from "new key" to "old key retired", plus the emergency path
- **Data flow**: rotating the data-encryption key and re-encrypting Rahul's PAN, with the real values from the demo
- **Key lifecycle**: the states a key goes through

In short: `secret in a vault → loaded at boot (fail fast) → used, never logged → new key added (old one verify/decrypt-only) → tokens expire / rows re-encrypted → old key retired`

| Kind of secret | Example | How it's rotated |
|---|---|---|
| **Signing key** (asymmetric) | JWT private key | New key + new `kid`; old public key stays in JWKS until old tokens expire |
| **Encryption key** | AES key for PAN / Aadhaar / TOTP secrets | New key for new writes; re-encrypt old rows; then retire |
| **Shared secret** | Admin token, webhook secret, HMAC key, API key you give to partners | Accept **two** values (old + new) for a while; switch callers; remove the old one |
| **Credential to someone else** | DB password, Razorpay / AWS key | Create the new one at the provider, deploy it, revoke the old one. Best: **short-lived** dynamic credentials (Vault, cloud IAM roles) so there's nothing long-lived to leak |

---

### Step 1: Secrets come from outside the code, and the app refuses to start without them

```js
function requireSecretList(name, minLength = 32) {
  const values = (process.env[name] ?? "").split(",").map((v) => v.trim()).filter(Boolean);
  if (values.length === 0 || values.some((v) => v.length < minLength)) {
    console.error(`❌ ${name} is missing, or one of its values is shorter than ${minLength} characters. Refusing to start.`);
    process.exit(1);
  }
  return values;
}
```

Where the value comes from, from worst to best:

| Place | OK for | Notes |
|---|---|---|
| Hard-coded in code | ❌ never | It's in Git history even after you delete the line |
| `.env` file | Local development | Add `.env` to `.gitignore`; commit a `.env.example` with **placeholders**. Node 20+: `node --env-file=.env server.js` |
| Platform env vars / secrets (Render, Vercel, Heroku, GitHub Actions secrets, Kubernetes Secrets) | Most apps | Set in the dashboard, injected at deploy. Kubernetes Secrets are only base64, so turn on encryption at rest |
| **Secrets manager** (AWS Secrets Manager, GCP Secret Manager, Azure Key Vault, HashiCorp Vault, Doppler, Infisical) | Production | Central, access-controlled, **audited**, supports scheduled rotation |
| **KMS / HSM** (AWS KMS, GCP KMS, Cloud HSM) | Encryption and signing keys | The key **never leaves** the KMS. You send data in, get ciphertext or a signature back |

| ✅ Do | ❌ Don't |
|---|---|
| **Fail fast** at boot with a clear message | Fall back to a default like `process.env.JWT_SECRET \|\| "secret"`: production silently runs with `"secret"` |
| Check length/format (a 32-byte random key, not `admin123`) | Accept any non-empty string |
| Generate keys with `crypto.randomBytes(32)` / `openssl rand -hex 32` | Use a password or a word as a key |
| Give each environment its **own** secrets (dev, staging, prod) | Copy production secrets to a laptop or to staging |
| Run a secret scanner (gitleaks, trufflehog, GitHub push protection) in CI and as a pre-commit hook | Hope code review catches it |

---

### Step 2: Never let a secret reach a log, a URL or a response

```js
const SENSITIVE = /pass|token|secret|key|authorization|cookie|pan/i;
const redact = (obj) => Object.fromEntries(Object.entries(obj ?? {}).map(([k, v]) => [k, SENSITIVE.test(k) ? "[REDACTED]" : v]));
// → POST /login {"email":"rahul@mail.com","password":"[REDACTED]"}
```

Secrets leak through side doors more often than through the front door:

| Side door | Fix |
|---|---|
| `console.log(req.body)`, `console.log(req.headers)` | Redact (pino has `redact: ["req.headers.authorization", "*.password"]`) |
| Error objects and stack traces sent to the client or to Sentry | Send a generic error; scrub Sentry events |
| Tokens in URLs (`?token=…`) | They land in server logs, browser history and the `Referer` header. Use headers or POST bodies |
| An admin "show config" endpoint | Show key **IDs and status**, never key material. Our `/admin/keys` does exactly that |
| Frontend bundles | Anything in `NEXT_PUBLIC_*` / `VITE_*` is **public**. Server secrets never go to the browser |
| Docker images, CI logs | Don't `COPY .env`; mask secrets in CI output |

---

### Step 3: Rotate signing keys with a `kid`

The problem: if the server knows only **one** key, changing it makes every existing token invalid at once.

The fix: a **key ring**. Every token says which key signed it:

```json
{"alg":"EdDSA","typ":"JWT","kid":"sig-1"}
```

```js
const key = signingKeys.get(header.kid);              // pick from OUR ring
if (!key) return { error: "Unknown or retired signing key" };
crypto.verify(null, data, key.publicKey, signature);
```

Rotation in four moves:

| Move | Signs new tokens | Verifies tokens |
|---|---|---|
| 1. Only `sig-1` | `sig-1` | `sig-1` |
| 2. **Add** `sig-2` and publish it in the JWKS (optional "pre-publish" so caches see it first) | `sig-1` | `sig-1`, `sig-2` |
| 3. **Switch**: `sig-2` becomes current | `sig-2` | `sig-1` (verify-only), `sig-2` |
| 4. Wait **longer than the token lifetime** (15 min here), then **retire** `sig-1` | `sig-2` | `sig-2` |

Nobody is logged out. Old tokens die naturally, new ones use the new key.

With **asymmetric** keys (EdDSA, RS256, ES256), other services verify with the **public** keys from `/.well-known/jwks.json` and never hold a private key. That endpoint is usually cached for minutes, which is why step 2 publishes the new key **before** using it.

**Emergency** (the private key leaked): skip the wait. Rotate, then retire the leaked key **immediately**. Every token it signed, the attacker's forged ones and real users' alike, gets a 401. Users log in again. That's the price, and it's the right call.

| ✅ Do | ❌ Don't |
|---|---|
| Put `kid` in every token and look keys up in **your own** ring | Use `kid` as a file path, URL or SQL value (topic 53 attacks) |
| Pin the algorithm (`alg` must be `EdDSA`) | Let the token header choose the algorithm |
| Keep the old key **verify-only** for one token lifetime | Delete the old key the moment you rotate |
| Rotate on a schedule (for example every 90 days) **and** have a tested emergency runbook | Rotate only "when something happens" |

---

### Step 4: Rotate encryption keys with a key ID and re-encryption

Encrypted data has a problem tokens don't: **it doesn't expire**. A PAN encrypted in 2024 must still be readable in 2030. So every row stores the ID of the key that encrypted it:

```json
{"keyId":"data-1","iv":"qvG90pLQLY2jZy6O","tag":"16s+XrIaHFiTHLSYhXKjMQ==","ciphertext":"Y9t7V1bNoUy/TA=="}
```

Rotation:

1. **Add** `data-2` and make it current → new writes use `data-2`; old rows still say `data-1`, so they still decrypt
2. **Re-encrypt** old rows in the background: decrypt with `data-1`, encrypt with `data-2` (or lazily: re-encrypt a row whenever it's read)
3. When **no row** uses `data-1`, retire it

**Never delete a data key that still has rows.** That data is unreadable forever. Our demo refuses with `409`:

```json
{"error":"1 row(s) are still encrypted with data-1. Re-encrypt them first, or that data is lost."}
```

**Envelope encryption** (what KMS-based systems do): each row (or table) gets its own random **data key (DEK)**. The DEK is encrypted ("wrapped") by a **key-encryption key (KEK)** that lives in the KMS, and the **wrapped DEK** is stored next to the data. Rotating the KEK only means re-wrapping the small DEKs, not re-encrypting terabytes of data. Our demo is the simple version: the key ring plays the role of the KEK.

| ✅ Do | ❌ Don't |
|---|---|
| AES-256-**GCM** with a fresh random 12-byte IV every time | Reuse an IV with the same key (GCM breaks badly), or use ECB |
| Store `keyId` with every ciphertext | Assume "there's only one key" |
| Bind the ciphertext to its row with AAD (we use the email) so it can't be copied into another row | Encrypt values with no context |
| Show only what the screen needs (`******234F`) | Decrypt and return the full value everywhere |

---

### Step 5: Rotate shared secrets with a two-value overlap

For a secret that **both sides** know (an admin token, a webhook secret, a partner's API key), accept **two values** for a while:

```bash
ADMIN_TOKENS=old-admin-token-…,new-admin-token-…   # during the switch
ADMIN_TOKENS=new-admin-token-…                     # after every caller uses the new one
```

1. Deploy with `old,new` → both work
2. Update every caller to `new`
3. Deploy with just `new` → the old one stops working

Stripe does the same for API keys ("roll key": you choose how long the old key keeps working, up to 7 days).

Compare tokens with `crypto.timingSafeEqual`, not `===` (topic 51). We hash both sides first so they're the same length.

---

### 🤔 Tricky parts

**1. Deleting a secret from the code doesn't remove it.** It's still in Git history, forks, clones and CI caches. Once a secret is pushed, **rotate it**. Rewriting history (git filter-repo, BFG) is cleanup, not a fix.

**2. Rotating the JWT key doesn't revoke refresh tokens.** Refresh tokens are usually random strings in the database (topic 23). On a leak, also revoke the sessions and refresh tokens you think are affected.

**3. Password hashes are not rotated like keys.** You can't re-hash a password you don't know. Upgrade a user's hash **at their next login** (topic 08). A **pepper** (a secret added to every password hash) needs a pepper ID per row, like a data key ID.

**4. Symmetric JWT keys (HS256) spread.** Every service that **verifies** HS256 tokens can also **sign** them. More copies = more places to leak, and rotation means updating every service. Asymmetric keys + JWKS fix both.

**5. The app needs a secret to fetch secrets.** The "secret zero" problem. Use the platform's identity (AWS IAM role, GCP service account, Kubernetes service-account token) so there's no long-lived bootstrap password.

**6. Caches.** JWKS consumers cache keys; your own servers may cache the key ring. A rotation isn't finished until every instance and every consumer has the new key.

**7. Backups.** If you retire (destroy) a data key, backups encrypted with it become unreadable too. Usually that's what you want ("crypto-shredding"), but decide on purpose.

---

### Common beginner mistakes

1. **`const JWT_SECRET = "mysecret"` in the code.**
   Load it from the environment or a secrets manager.

2. **Committing `.env`.**
   Add it to `.gitignore` before the first commit; commit `.env.example` with placeholders.

3. **Default fallbacks: `process.env.SECRET || "dev-secret"`.**
   Production runs with the dev secret and nobody notices. Fail fast.

4. **Logging whole requests, headers or error objects.**
   Redact passwords, tokens and `Authorization`.

5. **Weak keys.**
   A key must be random bytes (`crypto.randomBytes(32)`), not a word or a password.

6. **No `kid`, so rotation logs everyone out.**
   Add a key ID from day one; it costs nothing.

7. **Deleting the old key the moment you rotate.**
   Tokens it signed fail early; data it encrypted is lost. Keep it verify/decrypt-only first.

8. **Encrypted data without a key ID.**
   After the first rotation you don't know which key opens which row.

9. **Putting server secrets in frontend env vars** (`NEXT_PUBLIC_…`, `VITE_…`).
   Those are shipped to every browser.

10. **Same secrets in dev, staging and prod.**
    A leak from a laptop becomes a production breach.

---

### Interview questions

1. **Where should an app keep its secrets?**
   Never in code or Git. In development a git-ignored `.env`; in production platform secrets or a secrets manager (AWS Secrets Manager, Vault, etc.), and signing/encryption keys ideally in a KMS/HSM where they never leave. Access is least-privilege and audited.

2. **How do you rotate a JWT signing key without logging users out?**
   Key ring with a `kid` in every token header. Add the new key (publish its public key in JWKS), switch signing to it, keep the old key verify-only for one access-token lifetime, then remove it.

3. **The JWT private key leaked. What do you do?**
   Generate a new key and switch to it, retire the leaked key immediately (all its tokens get 401, so users log in again), revoke refresh tokens/sessions if needed, find how it leaked, check logs for forged tokens, and notify as required (topic 55).

4. **How do you rotate the key that encrypts data at rest?**
   Store a key ID with every ciphertext. New writes use the new key; a background job (or lazy re-encryption on read) moves old rows; when no rows use the old key, retire it. With envelope encryption you only re-wrap the data keys.

5. **What is envelope encryption?**
   Data is encrypted with a data key (DEK); the DEK is encrypted by a key-encryption key (KEK) held in a KMS; the wrapped DEK is stored with the data. The KEK never leaves the KMS, and rotating it doesn't require re-encrypting all the data.

6. **How do you rotate a shared secret like a webhook or API key with no downtime?**
   Accept both the old and new value during a transition window, move every caller to the new one, then stop accepting the old one.

7. **Why are asymmetric keys better than HS256 for JWTs across many services?**
   Only the auth server holds the private key; others verify with public keys from JWKS. A compromised verifier can't mint tokens, and rotation is just publishing a new public key.

8. **A developer pushed an AWS key to GitHub and deleted it in the next commit. Are we safe?**
   No. It's in the history and may already be scraped. Revoke/rotate the key now, check usage logs (CloudTrail) for abuse, then clean the history.

---

### Quick recap

- Secrets **out of code and Git**: `.env` locally, platform secrets / **secrets manager** / **KMS** in production
- **Fail fast** at startup on a missing or weak secret; no default fallbacks
- **Never log** secrets; redact bodies, headers and errors; no tokens in URLs
- Signing keys: **`kid`** in every token, old key **verify-only** for one token lifetime, then retire; **JWKS** for public keys
- Encryption keys: **key ID** with every ciphertext, **re-encrypt**, never delete a key that still has rows; **envelope encryption** in real systems
- Shared secrets: accept **old + new** during the switch
- Have an **emergency rotation runbook** and practise it; audit logs and alerts are next (topic 55)

## Code

A small **Express** app, **PaisaVault**, that shows all five steps:

| Part | Endpoints |
|---|---|
| Step 1: fail fast on missing secrets | Reads `ADMIN_TOKENS` from the environment at boot |
| Step 2: redacted request log | Every request is logged with passwords, tokens and PAN masked |
| Step 3: JWT signing keys (Ed25519, from scratch with `crypto`) | `POST /login`, `GET /api/me`, `GET /.well-known/jwks.json`, `POST /admin/signing-keys/rotate`, `DELETE /admin/signing-keys/:kid` |
| Step 4: AES-256-GCM data keys | `PUT/GET /api/me/pan`, `POST /admin/data-keys/rotate`, `POST /admin/data-keys/reencrypt`, `DELETE /admin/data-keys/:id` |
| Step 5: two admin tokens at once | `ADMIN_TOKENS=old,new`; `GET /admin/keys` shows key IDs and status, never key material |

Keys are generated in memory at startup (a real app keeps them in a KMS), so a restart starts fresh with `sig-1` and `data-1`.

📄 **Full code: [server.js](server.js)**. Open it and read the comments, which follow the same steps as the notes above.

Install Express once (from this folder):

```bash
npm install
```

Start it **without** the secret first, to see the fail-fast check:

```bash
node server.js
```
→ `❌ ADMIN_TOKENS is missing, or one of its values is shorter than 32 characters. Refusing to start.` (`ADMIN_TOKENS=admin123` gets the same answer.)

Now start it with **two** admin tokens, as during a rotation (Git Bash):

```bash
ADMIN_TOKENS=old-admin-token-0123456789abcdef0123,new-admin-token-fedcba9876543210fedc node server.js
```
→
```
💳 PaisaVault on http://localhost:3000
🔑 Signing key sig-1 and data key data-1 ready. 2 admin token(s) loaded (values never logged).
```

> These admin tokens are demo values for your laptop. Real ones come from `openssl rand -hex 32` and never go into a README. Port 3000 busy? Add `PORT=3054` in front: `ADMIN_TOKENS=… PORT=3054 node server.js`. The outputs below were recorded on port 3054.

### Try it (Git Bash)

```bash
APP=http://localhost:3054
ADMIN="Authorization: Bearer new-admin-token-fedcba9876543210fedc"
```

🔐 **① Rahul logs in.** The token says which key signed it:

```bash
OLD=$(curl -s $APP/login -H "Content-Type: application/json" -d '{"email":"rahul@mail.com","password":"chai-and-code-42"}' | sed 's/.*"accessToken":"\([^"]*\)".*/\1/')
echo $OLD | cut -d. -f1 | base64 -d 2>/dev/null; echo
curl -s $APP/api/me -H "Authorization: Bearer $OLD"
```
→
```
{"alg":"EdDSA","typ":"JWT","kid":"sig-1"}
{"email":"rahul@mail.com","tokenSignedWith":"sig-1","currentSigningKey":"sig-1"}
```

The server log shows the redaction (Step 2):
```
→ POST /login {"email":"rahul@mail.com","password":"[REDACTED]"}
→ GET /api/me {} auth=[REDACTED]
```

🔒 **② He saves his PAN.** It's encrypted before it's stored:

```bash
curl -s -X PUT $APP/api/me/pan -H "Authorization: Bearer $OLD" -H "Content-Type: application/json" -d '{"pan":"ABCDE1234F"}'
curl -s $APP/api/me/pan -H "Authorization: Bearer $OLD"
```
→ `{"message":"PAN saved, encrypted","encryptedWith":"data-1"}` and `{"pan":"******234F","encryptedWith":"data-1"}`

What the "database row" holds (server log), a key ID and ciphertext, no PAN:
```
💾 users[rahul@mail.com].pan = {"keyId":"data-1","iv":"qvG90pLQLY2jZy6O","tag":"16s+XrIaHFiTHLSYhXKjMQ==","ciphertext":"Y9t7V1bNoUy/TA=="}
```

🌐 **③ The public keys** other services use to verify tokens:

```bash
curl -s $APP/.well-known/jwks.json
```
→ `{"keys":[{"kty":"OKP","crv":"Ed25519","x":"d1F7Of4wKcK7_96Cj7o2IlXz6q_rmbP1A92YKRxsw48","kid":"sig-1","use":"sig","alg":"EdDSA"}]}`

🛂 **④ Admin endpoints** need an admin token. **Both** the old and the new one work during the switch (Step 5):

```bash
curl -s $APP/admin/keys
curl -s $APP/admin/keys -H "Authorization: Bearer old-admin-token-0123456789abcdef0123"
```
→ `{"error":"Admin token required"}` then
`{"signingKeys":[{"kid":"sig-1","status":"current",...}],"dataKeys":[{"id":"data-1","status":"current","rows":1,...}]}`

🔄 **⑤ Rotate the signing key.** Old tokens keep working; new logins get the new key:

```bash
curl -s -X POST $APP/admin/signing-keys/rotate -H "$ADMIN"
NEW=$(curl -s $APP/login -H "Content-Type: application/json" -d '{"email":"rahul@mail.com","password":"chai-and-code-42"}' | sed 's/.*"accessToken":"\([^"]*\)".*/\1/')
curl -s $APP/api/me -H "Authorization: Bearer $OLD"
curl -s $APP/api/me -H "Authorization: Bearer $NEW"
```
→
```
{"message":"New tokens are signed with sig-2. sig-1 still verifies old tokens until you retire it.","current":"sig-2"}
{"email":"rahul@mail.com","tokenSignedWith":"sig-1","currentSigningKey":"sig-2"}
{"email":"rahul@mail.com","tokenSignedWith":"sig-2","currentSigningKey":"sig-2"}
```
The JWKS now lists both `sig-1` and `sig-2`.

🗑️ **⑥ Retire the old key** (after 15 minutes in real life; right away in an emergency). The current key can't be retired:

```bash
curl -s -X DELETE $APP/admin/signing-keys/sig-2 -H "$ADMIN"
curl -s -X DELETE $APP/admin/signing-keys/sig-1 -H "$ADMIN"
curl -s $APP/api/me -H "Authorization: Bearer $OLD"
curl -s $APP/api/me -H "Authorization: Bearer $NEW"
```
→
```
{"error":"That's the current key. Rotate first, then retire it."}
{"message":"sig-1 retired. Tokens it signed are now rejected."}
{"error":"Invalid token","reason":"Unknown or retired signing key: sig-1"}
{"email":"rahul@mail.com","tokenSignedWith":"sig-2","currentSigningKey":"sig-2"}
```

🔑 **⑦ Rotate the data key.** Rahul's PAN still opens (its row says `data-1`), and the old key can't be deleted yet:

```bash
curl -s -X POST $APP/admin/data-keys/rotate -H "$ADMIN"
curl -s $APP/api/me/pan -H "Authorization: Bearer $NEW"
curl -s -X DELETE $APP/admin/data-keys/data-1 -H "$ADMIN"
```
→
```
{"message":"New writes use data-2. 1 row(s) still use data-1 until re-encrypted.","current":"data-2"}
{"pan":"******234F","encryptedWith":"data-1"}
{"error":"1 row(s) are still encrypted with data-1. Re-encrypt them first, or that data is lost."}
```

🔁 **⑧ Re-encrypt, then retire:**

```bash
curl -s -X POST $APP/admin/data-keys/reencrypt -H "$ADMIN"
curl -s $APP/api/me/pan -H "Authorization: Bearer $NEW"
curl -s -X DELETE $APP/admin/data-keys/data-1 -H "$ADMIN"
curl -s $APP/admin/keys -H "$ADMIN"
```
→
```
{"message":"Re-encrypted 1 row(s) with data-2"}
{"pan":"******234F","encryptedWith":"data-2"}
{"message":"data-1 retired. No data used it."}
{"signingKeys":[{"kid":"sig-2","status":"current",...}],"dataKeys":[{"id":"data-2","status":"current","rows":1,...}]}
```

🚫 **⑨ A forged token** with `"alg":"none"` is refused before any key is used (topic 53):

```bash
H=$(printf '{"alg":"none","kid":"sig-2"}' | base64 | tr '+/' '-_' | tr -d '=')
curl -s $APP/api/me -H "Authorization: Bearer $H.$(echo $NEW | cut -d. -f2)."
```
→ `{"error":"Invalid token","reason":"Unexpected alg"}`

**Finish the admin-token rotation:** stop the server and start it with only the new token. The old one now gets `{"error":"Admin token required"}`.

> **Windows PowerShell users:** the single quotes in `-d '...'`, `$(...)` and `VAR=value node ...` work in Git Bash. In PowerShell, use Git Bash or Postman, or set variables with `$env:ADMIN_TOKENS="old-…,new-…"; $env:PORT=3054; node server.js`. Restart the server to reset all keys and data.
