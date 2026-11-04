# 03. Hashing vs Encryption vs Encoding

## Notes

### Why learn this before auth?

These three words get mixed up all the time, even by experienced developers. In auth they matter a lot:

- **Passwords** must be **hashed** (never encrypted, never encoded)
- **JWTs** are **encoded** (so anyone can read them!) and **signed** (so no one can change them)
- **Sensitive data** like API keys stored for a user should be **encrypted**

Pick the wrong one, and you get a security hole.

---

### The one-line answer

| | Question it answers | Can you get the original back? |
|---|---|---|
| **Encoding** | "How do I change the **format** so it can travel safely?" | ✅ Yes, **anyone** can |
| **Encryption** | "How do I **hide** data so only people with the key can read it?" | ✅ Yes, but **only with the key** |
| **Hashing** | "How do I make a **fingerprint** of data that can't be reversed?" | ❌ **No, never** |

---

### A real-life example: sending a message

Imagine you want to send the message `"meet at 5"`:

- **Encoding** = writing it in **Morse code**.
  Anyone with a Morse code chart can read it. It's not secret, just a different format.
  👉 `"hello"` → `.... . .-.. .-.. ---`

- **Encryption** = putting it in a **locked box**.
  Only the person with the **key** can open it and read the message.
  👉 `x8#kP!2qZ` → (with key) → `"meet at 5"`

- **Hashing** = putting it through a **paper shredder** that always shreds the same paper into the exact same pattern.
  You can't rebuild the paper from the shreds, but if someone gives you a new paper, you can shred it and check whether the patterns match.
  👉 `"meet at 5"` → `a3f9c1...` (and there's no way back)

---

### 1. Encoding: changing the format (NOT security)

**Encoding** changes data into another format so it can be **safely sent or stored**, like turning binary data or special characters into plain text.

- **No key** and **no secret**
- **Anyone** can decode it
- Purpose: **compatibility**, not security

#### Common encodings

| Encoding | Example | Used for |
|---|---|---|
| **Base64** | `hello` → `aGVsbG8=` | Sending binary data as text, HTTP Basic Auth, JWTs (base64url) |
| **URL encoding** | `a b&c` → `a%20b%26c` | Putting special characters safely in URLs |
| **Hex** | `hi` → `6869` | Showing raw bytes as readable text |

#### ⚠️ Base64 is NOT encryption

This is the #1 beginner mistake. Look at an HTTP Basic Auth header:

```
Authorization: Basic cmFodWw6c2VjcmV0MTIz
```

It looks secret, but anyone can decode it in one second:

```
cmFodWw6c2VjcmV0MTIz  →  rahul:secret123
```

Same with JWTs: the middle part of a JWT is just Base64. **Anyone can read what's inside.** Never put passwords or secrets in a JWT.

---

### 2. Encryption: locking data with a key

**Encryption** scrambles data using a **key**. Only someone with the right key can **decrypt** it back to the original.

```
"my secret"  ──encrypt with key──►  "x8#kP!2qZ..."  ──decrypt with key──►  "my secret"
```

- Uses a **key**
- **Two-way**: lock it, then unlock it
- Purpose: **keep data secret** but still be able to read it later

#### Two types of encryption

**Symmetric encryption: one key for both**

Like a house key: the **same key** locks and unlocks the door.

```
       same key 🔑                 same key 🔑
"hello" ────────► "x8#kP!" ────────► "hello"
```

- Example algorithm: **AES** (e.g. AES-256-GCM)
- Fast
- Problem: both sides need the same key, so how do you share it safely?

**Asymmetric encryption: a key pair**

Like a **mailbox with a slot**: anyone can drop a letter in (**public key**), but only the owner with the mailbox key can open it (**private key**).

```
        public key 🔓                private key 🔑
"hello" ───────────► "x8#kP!" ───────────► "hello"
   (anyone can lock)          (only owner can unlock)
```

- Example algorithms: **RSA**, **ECC**
- Slower, but solves the key-sharing problem
- Used in **HTTPS** (topic 05) and **RS256 JWTs** (topic 18)

#### When to use encryption in backend

- Storing third-party API keys or tokens for users (e.g. a user's GitHub token)
- Storing sensitive personal data (e.g. Aadhaar or PAN numbers)
- Sending data over the network (**HTTPS** does this for you)

---

### 3. Hashing: a one-way fingerprint

**Hashing** turns any input into a **fixed-length string** (the "hash"). It's **one-way**, so you can **never** get the original back.

```
"hello"        ──SHA-256──►  2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
"hello!"       ──SHA-256──►  ce06092fb948d9ffac7d1a376e404b26b7575bcc11ee05a4615fef4fec3a308b
"a whole book" ──SHA-256──►  (still exactly 64 characters)
```

#### Properties of a good hash

| Property | Meaning |
|---|---|
| **One-way** | You can't turn the hash back into the input |
| **Same input → same output** | `"hello"` always gives the same hash |
| **Tiny change → totally different hash** | `"hello"` vs `"hello!"` look nothing alike |
| **Fixed length** | 1 letter or a 1 GB file gives the same-length output |
| **No collisions** | Practically impossible for two inputs to give the same hash |

#### Why hashing is perfect for passwords

The server **never needs to know your actual password**. It only needs to check that you typed the **same** one again.

```
SIGNUP
  User types: "secret123"
  Server stores: hash("secret123") = "ef92b7..."      ← only the hash is saved

LOGIN
  User types: "secret123"
  Server computes: hash("secret123") = "ef92b7..."
  Does it match the stored hash? ✅ Yes → logged in
```

If hackers steal the database, they only get hashes, **not passwords**.

#### ⚠️ But NOT just any hash

**SHA-256 / MD5 are too fast for passwords.** A hacker's GPU can try **billions** of guesses per second.

For passwords, use **slow hash functions built for passwords**:
- **bcrypt**
- **argon2** (the modern recommended choice)
- **scrypt**

These also add a **salt** (a random value per user), so two users with the same password get different hashes.

*(Topic 04 covers bcrypt, argon2, salt, and pepper in detail.)*

#### Other uses of hashing

- **File integrity**: check that a downloaded file wasn't changed (compare its SHA-256)
- **Storing tokens**: store a hash of reset-password tokens or API keys, not the raw value
- **Signatures**: HMAC (hash + secret key) is how **HS256 JWTs** are signed

---

### Bonus: what is HMAC? (hashing + a key)

**HMAC** = a hash made with a **secret key**. Only someone who knows the key can create the same hash.

```
HMAC("user=rahul", secretKey) → "9f2a1c..."
```

This proves two things:
1. The data **wasn't changed** (any change gives a different hash)
2. It was created by someone **who knows the key**

This is exactly how a **JWT signature** works (HS256 = HMAC + SHA-256). The data is **readable** (encoded), but it **can't be faked** (signed).

---

### Side-by-side comparison

| | Encoding | Encryption | Hashing |
|---|---|---|---|
| Purpose | Change format | Keep data secret | Verify data / store passwords |
| Reversible? | ✅ Yes, by anyone | ✅ Yes, with key | ❌ No |
| Needs a key? | ❌ No | ✅ Yes | ❌ No (HMAC uses one) |
| Output length | Grows with input | Grows with input | **Always fixed** |
| Is it security? | ❌ **No** | ✅ Yes | ✅ Yes |
| Examples | Base64, URL encoding, Hex | AES, RSA | SHA-256, bcrypt, argon2 |
| Auth use case | Basic Auth header, JWT format | HTTPS, storing API keys | **Passwords**, token storage, JWT signature (HMAC) |

---

### Which one should I use? (quick guide)

```
Do you need to get the original data back later?
        │
        ├── No ──► HASHING
        │            └── Is it a password? ──► use bcrypt / argon2 (NOT plain SHA-256)
        │
        └── Yes ──► Should only certain people be able to read it?
                         │
                         ├── Yes ──► ENCRYPTION (AES, RSA)
                         │
                         └── No, just need a safe format ──► ENCODING (Base64, URL)
```

| Situation | Use |
|---|---|
| Storing user passwords | **Hashing** (bcrypt / argon2) |
| Storing a user's third-party API key you must use later | **Encryption** (AES) |
| Putting binary data in JSON | **Encoding** (Base64) |
| Sending a username and password in a Basic Auth header | **Encoding** (and you **must** use HTTPS!) |
| Checking a downloaded file wasn't tampered with | **Hashing** (SHA-256) |
| Signing a JWT so no one can change it | **HMAC** (HS256) or asymmetric signature (RS256) |

---

### Common beginner mistakes

1. **Thinking Base64 is encryption.**
   It's just a different format. Anyone can decode it instantly.

2. **Encrypting passwords instead of hashing them.**
   If the key leaks, **every password** is exposed at once. With hashing there's no key to steal.

3. **Hashing passwords with MD5 or SHA-256.**
   They're way too fast, so hackers can guess billions per second. Use bcrypt or argon2.

4. **Putting secrets inside a JWT.**
   JWT payloads are only encoded, and anyone can read them. Signing stops changes, **not reading**.

5. **Saying "decrypt the hash".**
   Hashes can't be decrypted. Attackers can only **guess** inputs and compare hashes.

6. **Hardcoding encryption keys in code.**
   Keep keys in environment variables or a secret manager, never in Git.

---

### Interview questions

1. **What's the difference between encoding, encryption, and hashing?**
   Encoding changes the format and anyone can reverse it. Encryption hides data and can be reversed only with a key. Hashing is a one-way fingerprint that can't be reversed.

2. **Why do we hash passwords instead of encrypting them?**
   We never need the original password, only to check that it matches. Hashing is one-way, so even if the database leaks, the passwords aren't directly exposed. Encryption would need a key, and if that key leaks, every password leaks.

3. **Is Base64 secure?**
   No. It's encoding, not encryption. Anyone can decode it.

4. **Why not use SHA-256 for passwords?**
   It's designed to be fast, which makes brute-force attacks easy. Password hashes like bcrypt or argon2 are deliberately slow and include a salt.

5. **Symmetric vs asymmetric encryption?**
   Symmetric uses one shared key for both encrypting and decrypting (AES, fast). Asymmetric uses a public key to encrypt and a private key to decrypt (RSA, slower, solves key sharing).

6. **Is a JWT encrypted?**
   Normally no. A standard JWT (JWS) is Base64url-encoded and signed. Anyone can read it, but nobody can modify it without breaking the signature. (Encrypted JWTs, called JWE, exist but are less common.)

7. **What is HMAC?**
   A hash made with a secret key. It proves the data wasn't changed and was created by someone who has the key. It's used to sign HS256 JWTs and webhooks.

---

### Quick recap

- **Encoding** = change format = **anyone** can reverse = **not security** (Base64)
- **Encryption** = lock with a key = **reverse only with the key** (AES, RSA)
- **Hashing** = one-way fingerprint = **can never reverse** (SHA-256, bcrypt)
- **Passwords** → hash with **bcrypt / argon2**, never encrypt or encode
- **JWT** = encoded + signed → readable by anyone, but can't be changed

## Code

All three, using only Node.js's built-in `crypto` module (no libraries to install).

```js
// demo.js
const crypto = require("crypto");

const message = "hello";

// 1. ENCODING: anyone can reverse it, no key needed
const encoded = Buffer.from(message).toString("base64");
const decoded = Buffer.from(encoded, "base64").toString();
console.log("Encoded:", encoded);   // aGVsbG8=
console.log("Decoded:", decoded);   // hello

// 2. ENCRYPTION: reversible only with the key (AES-256-GCM)
const key = crypto.randomBytes(32);  // keep this secret! (env variable in real apps)
const iv = crypto.randomBytes(12);   // random value, new for every encryption

const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
const encrypted = Buffer.concat([cipher.update(message), cipher.final()]);
const authTag = cipher.getAuthTag(); // detects if the encrypted data was tampered with
console.log("Encrypted:", encrypted.toString("hex"));

const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
decipher.setAuthTag(authTag);
const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]).toString();
console.log("Decrypted:", decrypted); // hello

// 3. HASHING: one-way, same input always gives the same output
const hash = (text) => crypto.createHash("sha256").update(text).digest("hex");
console.log("Hash of 'hello': ", hash("hello"));
console.log("Hash of 'hello!':", hash("hello!")); // totally different
console.log("Same input, same hash?", hash("hello") === hash("hello")); // true
// There is no "unhash" function. That's the point.

// BONUS: HMAC, a hash with a secret key (how HS256 JWTs are signed)
const hmac = crypto.createHmac("sha256", "my-secret-key").update("user=rahul").digest("hex");
console.log("HMAC:", hmac);

// ⚠️ For PASSWORDS, don't use sha256. Use bcrypt or argon2 (see topic 04).
```

Run it:

```bash
node demo.js
```

Notice:
- The **encoded** value turns straight back into `hello`, with no key needed.
- The **encrypted** value is different every run (random key + IV), but always decrypts to `hello`.
- The **hash** is the same every run, and changing one character changes everything.
