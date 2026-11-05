# 32. API Keys

## Notes

### What is an API key?

Everything so far authenticated **people**: they type a password, get a session or a token. But Rahul's chai stall also has **programs** that call your API: his POS machine pushes new orders every few minutes, a delivery app pulls them, a nightly script exports them to his accountant. Nobody is there to type a password or click "Log in with Google". These programs use an **API key**: a long random secret that says "I'm calling on behalf of Rahul's account, with these permissions".

> **One-line answer:** an API key is a **long random secret** (with a recognisable prefix) that a **program** sends in a **header** (`X-API-Key`) to call an API. The server stores only its **hash**, shows it **once**, ties it to an **owner** and limited **scopes**, can **expire**, **revoke** and **rotate** it, **rate-limits** each key, and logs which key did what.

---

### Why does it matter?

| Without proper API keys | What goes wrong |
|---|---|
| The POS machine logs in with Rahul's **password** | The password sits in a config file; changing it breaks every integration; a leak = full account takeover |
| One key that can do **everything** | A leaked read-only sync key can also delete orders |
| Keys stored in plain text | A database leak hands out working keys for every customer |
| Keys sent as `?api_key=...` | They end up in server logs, proxy logs, browser history, analytics |
| No way to revoke one key | A leaked key means rotating **everything**, or living with it |
| No per-key limits | One buggy script hammers your API for everyone |
| Keys committed to GitHub | Bots scan public repos and use them within minutes |

---

### Real-life example: a building's access cards for vendors 🪪

Rahul runs a chai stall in an office tower in Gurugram. Vendors come in every day:

- The **milk supplier** gets a card that opens **only the service lift and the kitchen** → **scopes**
- The card is **not** Rahul's own ID card; if it's lost, Rahul still gets into his office → a key is **not your password**
- Security writes down the **card number**, not a copy of the card → the server stores a **hash**
- The card has a **validity date** printed on it → **expiry**
- When the supplier changes, security **deactivates** that one card in seconds → **revocation**
- New card first, then the old one is switched off → **rotation** with no downtime
- The turnstile only lets each card through **so many times an hour** → **rate limiting**
- The entry log says **which card** opened which door → **audit by key id**

---

### The flow, step by step

#### 📊 Diagrams

Open **[diagrams.html](diagrams.html)** in your browser (just double-click the file) to see:

- **Flow diagram**: what the server checks for every request with an API key
- **Data flow**: a key's whole life: created, used, limited, rotated, revoked
- **Key anatomy**: what the key looks like, and what the database stores

In short: `user logs in → creates a key with scopes (shown once, stored as sha256) → program sends X-API-Key → key in URL? 400 → hash → found, not revoked, not expired? else 401 → rate limit? else 429 → has the scope? else 403 → act for the key's owner → log the key id`.

---

### Step 1: Create the key: random, prefixed, shown once, stored hashed

```js
const key = "chai_key_" + crypto.randomBytes(32).toString("base64url"); // 256 random bits
apiKeys.set(sha256(key), { id: "key_9b69d0e5", userId, scopes, hint: "chai_key_7qlk…w1ig", expiresAt });
res.status(201).json({ id, key, warning: "Copy this key now. It will not be shown again." });
```

- **Random**: `crypto.randomBytes(32)`, never `Math.random()`, a UUID v1, or something built from the user id.
- **Prefix** (`chai_key_`, like `ghp_` for GitHub or `xoxb-` for Slack): people can tell what it is, and **secret scanners** (GitHub push protection, GitGuardian) can find it when it's leaked.
- **Stored as a hash**: like a password, but **SHA-256 is enough**. Passwords need slow hashes (scrypt/argon2, topic 04) because humans pick guessable ones; a 256-bit random key can't be guessed, so a fast hash is safe, and it's fast to look up on every request.
- **Shown once**. The dashboard shows only a **hint** (first and last few characters) so the user can recognise it.

| ✅ Do | ❌ Don't |
|---|---|
| `randomBytes(32)` + a prefix | Short or predictable keys |
| Store `sha256(key)`, a hint, an id | Store the key itself, or show it again later |
| Log the **key id** | Log the key |

---

### Step 2: Send it in a header, check it on every request

```bash
curl https://api.example.com/api/orders -H "X-API-Key: chai_key_7qlk4HUw..."
```

```js
const record = key?.startsWith("chai_key_") && apiKeys.get(sha256(key));
if (!record || record.revokedAt || isExpired(record)) return res.status(401).json({ error: "Invalid API key" });
```

- A **header** (`X-API-Key` or `Authorization: Bearer ...`), over **HTTPS** only.
- **Never in the URL**: query strings are written to access logs, proxy logs, browser history and `Referer` headers. The demo refuses `?api_key=` with a `400` and tells the developer to rotate the key.
- **One answer** for unknown, revoked and expired keys (`401 Invalid API key`); the real reason goes to the log.
- Keep human sessions and API keys **separate**: an API key can't call the dashboard (`/keys`), so a leaked key can't create more keys.

---

### Step 3: Scopes: least privilege per key

```js
app.post("/api/orders", requireApiKey, requireScope("orders:write"), createOrder);
```

- Each key gets **only** the scopes its program needs. The delivery app syncs orders → `orders:read` only. The POS machine creates them → `orders:read` + `orders:write`.
- A scope says **what** the key may do; the owner says **whose** data (`orders.filter(o => o.userId === req.apiKey.userId)`, topic 31). Sneha's key never sees Rahul's orders.
- Validate requested scopes against an **allow-list** when creating the key.

---

### Step 4: Rate-limit per key

```
X-RateLimit-Limit: 10
X-RateLimit-Remaining: 0
Retry-After: 59
→ 429 Too Many Requests
```

- Limits **per key** (not just per IP): one customer's broken script can't slow everyone down, and a leaked key can't be used for unlimited scraping.
- Tell clients where they stand with `X-RateLimit-*` headers and `Retry-After`.
- The demo uses a fixed window in memory. Real APIs use **Redis** so all servers share the counters (topic 16).

---

### Step 5: Expire, revoke, rotate, and watch usage

- **Expiry** (`expiresInDays: 90`): forgotten keys stop working by themselves.
- **Revocation** (`DELETE /keys/:id`): instant, because every request looks the key up. Only the **owner** can revoke their keys (Sneha gets `404` for Rahul's key).
- **Rotation without downtime**: create the new key → update the program → check the old key's `lastUsedAt` stops changing → revoke the old key. That's why a user may have **several** active keys.
- **`lastUsedAt`**: shows keys nobody uses anymore (delete them) and when a leaked key was last used.
- **Audit**: every write logs the **key id** (`key_a6123946 created ord_3a1a21c2`).

---

### API keys vs other options

| | API key | User session / JWT (Levels 1–3) | OAuth 2.0 client credentials (Level 5) | mTLS (Level 8) |
|---|---|---|---|---|
| Who | A program, for one account | A person | A program/service | A service |
| Lifetime | Long (months), until revoked | Minutes to days | Short-lived tokens from a long-lived secret | Certificate lifetime |
| Good for | Simple server-to-server integrations, CLIs, webhooks | Apps people use | Platforms, third-party apps, fine-grained tokens | Internal service mesh |
| Weakness | A long-lived bearer secret: whoever has it, is it | Not for unattended programs | More moving parts | Certificate management |

API keys **identify and authorize a caller**. They are **not** a way to log users in, and they should never be put in a **browser or mobile app**, where anyone can extract them. (Publishable/"public" keys like Stripe's `pk_` are a special case: they're designed to be public and can do almost nothing.)

---

### 🤔 Tricky parts

**1. A key is a bearer secret.**
Whoever holds it **is** the caller. Store it in a secret manager or environment variable on the server, never in Git, front-end code or screenshots (Level 7: secrets management).

**2. Leaked key playbook.**
Revoke it → create a new one → check the audit log by key id for what it did → find how it leaked. GitHub's secret scanning will often tell you first, if your keys have a prefix.

**3. Test and live keys.**
Many APIs issue separate keys for test and production data (`sk_test_` / `sk_live_` at Stripe). A test key can never touch real money.

**4. Timing attacks.**
Looking a key up by its **hash** in a map or a unique database index is fine. Comparing raw keys with `===` in a loop leaks timing (topic 51). If you compare secrets directly, use `crypto.timingSafeEqual`.

**5. Keys belong to an account, not a person.**
If Rahul's employee creates a key and leaves the company, the key keeps working. Show who created each key, and review keys regularly.

**6. Idempotency.**
Programs retry. For `POST`s like "create order", real APIs accept an `Idempotency-Key` header so a retry doesn't create two orders. (Out of scope for this demo.)

---

### Common beginner mistakes

1. **Storing keys in plain text.**
   Store `sha256(key)`; show the key once.

2. **Accepting keys in the query string.**
   Header only; reject `?api_key=`.

3. **One all-powerful key per account.**
   Scopes, several keys, one per integration.

4. **No revoke, no expiry.**
   Leaked keys work forever.

5. **Logging the full key** (or the whole request headers).
   Log the key **id**; redact `X-API-Key` and `Authorization` in request logs.

6. **Putting a secret key in frontend or mobile code.**
   Anyone can read it from DevTools or the app bundle. Call your own backend, which holds the key.

7. **Using `Math.random()` or short keys.**
   `crypto.randomBytes(32)`.

8. **Letting an API key manage API keys.**
   Key management needs a logged-in human (ideally with MFA, Level 6).

9. **Forgetting ownership.**
   A valid key for Rahul's account must not read Sneha's data.

---

### Interview questions

1. **What is an API key and when would you use one?**
   A long random secret that identifies a calling program and the account it acts for. Use it for server-to-server integrations, scripts, CLIs and webhooks, not for logging users in.

2. **How do you store API keys?**
   Only a hash (SHA-256 is fine because keys are high-entropy random), plus an id, a display hint, owner, scopes, created/expiry/last-used timestamps. Show the full key once at creation.

3. **Why SHA-256 for keys but scrypt/argon2 for passwords?**
   Passwords are low-entropy and guessable, so hashing must be slow. Random 256-bit keys can't be brute-forced, so a fast hash is safe and cheap on every request.

4. **Where should the client send the key?**
   In a header over HTTPS. Never in the URL, because URLs are logged and cached.

5. **How do you limit the damage of a leaked key?**
   Scopes (least privilege), expiry, instant revocation, per-key rate limits, audit logs by key id, a recognisable prefix for secret scanning, and separate test/live keys.

6. **How do you rotate a key without downtime?**
   Allow multiple active keys: create the new one, deploy it, confirm the old one is no longer used (`lastUsedAt`), then revoke the old one.

7. **API key vs OAuth 2.0?**
   API keys are simple, long-lived, and tied to one account. OAuth issues short-lived, scoped tokens, supports third-party apps acting for many users with their consent, and avoids sharing long-lived secrets widely.

8. **Can you put an API key in a React app?**
   Not a secret one. Anything shipped to the browser is public. Proxy through your backend, or use a publishable key designed to be public.

9. **What do you return for a bad key, a missing scope, and too many requests?**
   `401` (invalid/expired/revoked key, generic message), `403` (valid key without the scope), `429` with `Retry-After`.

---

### Quick recap

- API keys authenticate **programs**, acting for **one account**
- `prefix + randomBytes(32)`; show **once**; store **sha256** + id + hint
- Send in a **header** over HTTPS; **never** in the URL
- Generic **401** for unknown/revoked/expired keys; reason in the log
- **Scopes** per key (least privilege) + **ownership** of the data
- **Rate-limit per key**: `429` + `Retry-After`
- **Expire**, **revoke**, **rotate** (several active keys), track **`lastUsedAt`**
- Log the **key id**, never the key; keep keys out of Git and frontends
- Level 4 done. Next: letting users log in with Google, GitHub and others (Level 5: OAuth 2.0)

## Code

A small **Express** API for shop owners. A person logs in (`/login`) and manages keys in the "dashboard" (`POST/GET/DELETE /keys`). Programs call `/api/orders` with `X-API-Key`. Keys are random with a `chai_key_` prefix, shown once, stored as **SHA-256**, have **scopes**, optional **expiry**, **revocation**, a **per-key rate limit** (10 requests per minute; change with `RATE_LIMIT`), and `lastUsedAt` tracking.

| User | Shop | Orders |
|---|---|---|
| `rahul` | Rahul's Chai Stall | `ord_1` (Masala chai x 40, ₹800) |
| `sneha` | Sneha's Sarees | `ord_2` (Kanjeevaram saree, ₹18,500) |

Every demo user's password is `chai1234`.

📄 **Full code: [server.js](server.js)**. Open it and read the comments, which follow the same steps as the notes above.

Install the dependencies once (from this folder), then start the server:

```bash
npm install
```

```bash
node server.js
```

> Port 3000 busy? Run it on another port: `PORT=3032 node server.js` (Git Bash), then use that port in the commands below.

### Try it

Keys and ids are random, so yours will be different.

✅ **Log in as a person** (Git Bash):

```bash
login() { curl -s http://localhost:3000/login -H "Content-Type: application/json" -d "{\"username\":\"$1\",\"password\":\"chai1234\"}" | grep -o '"accessToken":"[^"]*' | cut -d'"' -f4; }
R=$(login rahul); S=$(login sneha)
```

✅ **Create a read-only key** for the delivery app:

```bash
curl http://localhost:3000/keys -H "Authorization: Bearer $R" -H "Content-Type: application/json" -d '{"name":"Delivery app sync","scopes":["orders:read"]}'
```
→
```json
{"id":"key_9b69d0e5","name":"Delivery app sync","hint":"chai_key_7qlk…w1ig","scopes":["orders:read"],"createdAt":"2026-11-05T03:01:29.337Z","expiresAt":null,"lastUsedAt":null,"revoked":false,"key":"chai_key_7qlk4HUwtdIPJTcsd9J9xyTBlmK-OkQ9n18eH2Uw1ig","warning":"Copy this key now. It will not be shown again."}
```
Copy it: `K1=chai_key_...`

✅ **Create a read + write key** for the POS machine, valid for 90 days:

```bash
curl http://localhost:3000/keys -H "Authorization: Bearer $R" -H "Content-Type: application/json" -d '{"name":"POS machine","scopes":["orders:read","orders:write"],"expiresInDays":90}'
```
→ `{"id":"key_a6123946","name":"POS machine","hint":"chai_key_kSmY…1s0o","scopes":["orders:read","orders:write"],...,"expiresAt":"2027-02-03T03:01:29.553Z",...,"key":"chai_key_kSmY..."}`. Copy it: `K2=chai_key_...`

❌ **Unknown scope, or no login:**

```bash
curl http://localhost:3000/keys -H "Authorization: Bearer $R" -H "Content-Type: application/json" -d '{"name":"x","scopes":["admin"]}'
curl http://localhost:3000/keys -H "Content-Type: application/json" -d '{"name":"x","scopes":["orders:read"]}'
```
→
```
{"error":"scopes must be a non-empty list from: orders:read, orders:write"} 400
{"error":"Please log in"} 401
```

✅ **The dashboard never shows the key again**, only the hint:

```bash
curl http://localhost:3000/keys -H "Authorization: Bearer $R"
```
→ `{"keys":[{"id":"key_9b69d0e5","name":"Delivery app sync","hint":"chai_key_7qlk…w1ig","scopes":["orders:read"],...,"revoked":false},{"id":"key_a6123946","name":"POS machine",...}]}`

🧪 **Use the keys:**

```bash
curl http://localhost:3000/api/orders -H "X-API-Key: $K1"
curl -X POST http://localhost:3000/api/orders -H "X-API-Key: $K1" -H "Content-Type: application/json" -d '{"item":"Adrak chai x 10","total":200}'
curl -X POST http://localhost:3000/api/orders -H "X-API-Key: $K2" -H "Content-Type: application/json" -d '{"item":"Adrak chai x 10","total":200}'
```
→
```
{"orders":[{"id":"ord_1","userId":"u_rahul","item":"Masala chai x 40","total":800}]} 200
{"error":"This API key is missing the orders:write scope"} 403
{"id":"ord_3a1a21c2","userId":"u_rahul","item":"Adrak chai x 10","total":200} 201
```

✅ **A key only sees its owner's data.** Sneha creates her own key and reads:

```bash
KS=$(curl -s http://localhost:3000/keys -H "Authorization: Bearer $S" -H "Content-Type: application/json" -d '{"name":"Sneha shop sync","scopes":["orders:read"]}' | grep -o '"key":"[^"]*' | cut -d'"' -f4)
curl http://localhost:3000/api/orders -H "X-API-Key: $KS"
```
→ `{"orders":[{"id":"ord_2","userId":"u_sneha","item":"Kanjeevaram saree","total":18500}]}`

❌ **Wrong ways to send a key:**

```bash
curl http://localhost:3000/api/orders
curl http://localhost:3000/api/orders -H "X-API-Key: chai_key_guess"
curl "http://localhost:3000/api/orders?api_key=$K1"
curl http://localhost:3000/keys -H "Authorization: Bearer $K1"
```
→
```
{"error":"Invalid API key"} 401
{"error":"Invalid API key"} 401
{"error":"Send the API key in the X-API-Key header, never in the URL. Treat this key as leaked and rotate it."} 400
{"error":"Please log in"} 401          ← an API key can't manage keys
```

✅ **Revoke** (only the owner can), and the key dies at once:

```bash
curl -X DELETE http://localhost:3000/keys/key_9b69d0e5 -H "Authorization: Bearer $S"
curl -X DELETE http://localhost:3000/keys/key_9b69d0e5 -H "Authorization: Bearer $R"
curl http://localhost:3000/api/orders -H "X-API-Key: $K1"
```
→
```
{"error":"Key not found"} 404                    ← Sneha can't touch Rahul's keys
{"id":"key_9b69d0e5",...,"lastUsedAt":"...","revoked":true} 200
{"error":"Invalid API key"} 401
```

🧪 **Rate limit:** 11 quick calls with the POS key (it already made 1 request this minute):

```bash
for i in $(seq 1 11); do printf "$i: "; curl -s -o /dev/null -D - http://localhost:3000/api/orders -H "X-API-Key: $K2" | grep -iE "^HTTP|remaining|retry-after" | tr -d '\r' | tr '\n' ' '; echo; done
```
→
```
1: HTTP/1.1 200 OK X-RateLimit-Remaining: 8
...
9: HTTP/1.1 200 OK X-RateLimit-Remaining: 0
10: HTTP/1.1 429 Too Many Requests X-RateLimit-Remaining: 0 Retry-After: 59
11: HTTP/1.1 429 Too Many Requests X-RateLimit-Remaining: 0 Retry-After: 59
```

📋 **The server log** has key **ids**, never keys:

```
🔑 u_rahul created key_9b69d0e5 (Delivery app sync) scopes=[orders:read]
🔑 u_rahul created key_a6123946 (POS machine) scopes=[orders:read,orders:write]
🚫 key_9b69d0e5 needs orders:write
🧾 key_a6123946 created ord_3a1a21c2 for u_rahul
❌ API key rejected: unknown key
🗑️  u_rahul revoked key_9b69d0e5
❌ API key rejected: key_9b69d0e5 is revoked
```

> **Windows PowerShell users:** `login()`, `$R`, `$K1`, the `for` loop and `PORT=... node ...` work in Git Bash. In PowerShell, use Git Bash, Postman, or `$env:PORT=3032; node server.js`.
