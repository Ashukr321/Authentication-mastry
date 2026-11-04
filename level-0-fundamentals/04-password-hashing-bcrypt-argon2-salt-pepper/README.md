# 04. Password Hashing: bcrypt, argon2, scrypt, Salt, Pepper

## Notes

### Why this topic matters

In topic 03 we learned: **passwords must be hashed, not encrypted.**

But **how** you hash matters a lot. If you do `sha256(password)` and your database leaks, attackers can crack most of the passwords in **hours**.

This topic answers:
1. Why are normal hashes (SHA-256, MD5) **bad** for passwords?
2. What is a **salt**, and why does every user need a different one?
3. Why should password hashing be **slow** on purpose?
4. Which one should I use: **bcrypt, argon2, or scrypt**?
5. What is a **pepper**?

---

### First: how do attackers crack hashed passwords?

Remember, hashes **can't be reversed**. So attackers don't "decrypt" anything. They **guess**:

```
Attacker steals hash: "ef92b778..."

Guess "123456"    → hash → "8d969eef..."  ❌ no match
Guess "password"  → hash → "5e884898..."  ❌ no match
Guess "secret123" → hash → "ef92b778..."  ✅ MATCH! Password is "secret123"
```

They use three main tricks:

| Attack | How it works | Simple example |
|---|---|---|
| **Brute force** | Try every possible combination | `aaaa`, `aaab`, `aaac`, ... |
| **Dictionary attack** | Try common passwords and leaked password lists | `123456`, `password`, `iloveyou`, ... |
| **Rainbow table** | A huge **pre-computed** list of "password → hash" | Look up the hash instantly, no guessing needed |

So our goal is simple: **make guessing as slow and expensive as possible.**

---

### Problem 1: SHA-256 and MD5 are too fast

SHA-256 was designed to be **fast**. That's great for checking files, but terrible for passwords.

| Hash | Guesses per second on one gaming GPU (roughly) |
|---|---|
| MD5 | ~100+ **billion** |
| SHA-256 | ~10+ **billion** |
| bcrypt (cost 12) | ~a few **thousand** |
| argon2id | ~a few **hundred** or less (depends on settings) |

With SHA-256, an attacker can try **every 8-character lowercase password in seconds**.

👉 **Fix: use a slow hash built for passwords** (bcrypt, argon2, scrypt).

---

### Problem 2: same password → same hash

Without a salt:

```
Rahul's password: "secret123"  → hash: ef92b778...
Priya's password: "secret123"  → hash: ef92b778...   ← identical!
Amit's password:  "secret123"  → hash: ef92b778...   ← identical!
```

This is bad because:
- If an attacker cracks **one**, they've cracked **all three**
- Attackers can use **rainbow tables** (pre-computed hashes) to look up common passwords instantly

👉 **Fix: add a salt.**

---

### 1. Salt: a random value added to each password

A **salt** is a **random string**, generated **separately for every user**, that is mixed into the password **before hashing**.

```
Rahul: hash("secret123" + "x7Kp2q")  → a91c3f...
Priya: hash("secret123" + "Lm9vT4")  → 3be07d...   ← totally different!
Amit:  hash("secret123" + "Qz81wR")  → f40b6a...   ← totally different!
```

#### Real-life example: secret spice

Three cooks make the same dish (same password), but each one adds their **own random spice** (salt). Now the dishes all taste different, and you can't tell they started with the same recipe.

#### Key facts about salt

| Question | Answer |
|---|---|
| Is the salt secret? | ❌ **No.** It's stored right next to the hash in the database. |
| Then what's the point? | It makes **every hash unique**, so rainbow tables are useless and each password must be cracked **one by one** |
| One salt for all users? | ❌ **Never.** Each user gets a **new random salt** |
| Do I create it myself? | Usually no. **bcrypt, argon2, and scrypt libraries do it for you** automatically |
| How long? | At least 16 bytes of random data |

---

### 2. Work factor: making the hash slow on purpose

Password hashing functions have a **"cost" setting** that controls how slow they are.

- For your server: hashing **once** at login takes ~**250 ms**. The user doesn't even notice.
- For an attacker: trying **1 billion** guesses at 250 ms each takes **~8 years** on one machine. 💸

#### Real-life example: a heavy vault door

Opening a vault door that takes **2 seconds** is fine for the bank employee who opens it once a day. But a thief who has to try **millions** of combinations, each taking 2 seconds, gives up.

#### Memory-hard hashing

Attackers use **GPUs**, which have thousands of tiny cores. **argon2** and **scrypt** also use a lot of **memory** for every hash. GPUs have little memory per core, so this kills their advantage.

```
bcrypt  → slow (CPU-heavy)
scrypt  → slow + uses lots of memory
argon2  → slow + uses lots of memory + very configurable  ← best today
```

---

### 3. The three password hashing algorithms

#### bcrypt (1999): the old reliable

- Used everywhere, with libraries in every language
- Has a **cost** setting (10 to 12 is common; each +1 **doubles** the time)
- Creates and stores the salt for you
- ⚠️ Only uses the **first 72 bytes** of the password. Anything longer is silently ignored.

**What a bcrypt hash looks like:**

```
$2b$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW
 │   │  └──────── salt (22 chars) ──────┘└──── hash (31 chars) ────┘
 │   └── cost (12 means 2^12 rounds)
 └── algorithm version (2b = bcrypt)
```

Everything needed to check a password (algorithm, cost, salt, hash) is in **one string**. You store just this string in your database.

#### scrypt (2009): memory-hard

- Uses lots of **memory** to make GPU attacks expensive
- **Built into Node.js** (`crypto.scrypt`), so no library is needed
- Settings: `N` (cost), `r` (block size), `p` (parallelism)

#### argon2 (2015): the modern winner 🏆

- **Won the Password Hashing Competition** in 2015
- **OWASP's top recommendation** today
- Three versions: `argon2d`, `argon2i`, and **`argon2id`** ← always use this one
- Settings: **memory** (how much RAM), **time** (how many passes), **parallelism** (how many threads)

**What an argon2 hash looks like:**

```
$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG
 │        │    │       │   │   │           └── hash
 │        │    │       │   │   └── salt
 │        │    │       │   └── parallelism (threads)
 │        │    │       └── time cost (passes)
 │        │    └── memory in KB (65536 KB = 64 MB)
 │        └── version
 └── algorithm
```

#### Comparison

| | bcrypt | scrypt | argon2id |
|---|---|---|---|
| Year | 1999 | 2009 | 2015 |
| Slow (CPU) | ✅ | ✅ | ✅ |
| Memory-hard (beats GPUs) | ❌ | ✅ | ✅ |
| Salt handled for you | ✅ | ❌ in Node's built-in, ✅ in libraries | ✅ |
| Password length limit | ⚠️ 72 bytes | None | None |
| Built into Node.js | ❌ (`npm i bcrypt`) | ✅ | ❌ (`npm i argon2`) |
| Recommendation | Fine for existing apps | Good | **Best choice for new apps** |

#### OWASP recommended minimum settings (good starting point)

| Algorithm | Settings |
|---|---|
| **argon2id** | memory = 19 MiB, time = 2, parallelism = 1 |
| **scrypt** | N = 2^17, r = 8, p = 1 |
| **bcrypt** | cost = 10 or more |

👉 Rule of thumb: tune it so **one hash takes about 250 ms to 1 second on your server**.

---

### 4. Pepper: a secret salt kept outside the database

A **pepper** is a **secret value** added to every password, stored **outside the database** (in an environment variable or a secret manager).

| | Salt | Pepper |
|---|---|---|
| Secret? | ❌ No | ✅ **Yes** |
| Where is it stored? | In the **database**, next to the hash | In **env variables / secret manager**, never in the DB |
| Different per user? | ✅ Yes, unique per user | ❌ No, usually one for the whole app |
| Required? | ✅ **Always** | ⚠️ **Optional** extra layer |

#### Why would I need a pepper?

Imagine attackers steal **only your database** (e.g. through SQL injection), but not your server's environment variables.

- **Without pepper:** they have the salt + hash, so they can start guessing.
- **With pepper:** they're missing the secret ingredient, so **every guess is useless**.

#### Real-life example: a two-part safe code

Half the safe code is written on a note **taped to the safe** (salt). The other half is in the **manager's head** (pepper). Stealing the safe isn't enough. You also need the manager.

#### How to add a pepper (the right way)

Don't just glue it on. Run the password through **HMAC** with the pepper first, then hash that with argon2 or bcrypt:

```
peppered = HMAC-SHA256(password, PEPPER)    ← PEPPER comes from env variable
stored   = argon2id(peppered)               ← salt added automatically
```

⚠️ **Downside:** if you **lose** the pepper, **nobody can log in ever again**. And changing it is hard. Many apps skip the pepper and rely on a strong argon2/bcrypt setup.

---

### 5. The full flow: signup and login

#### Signup

```
User sends: { email: "rahul@mail.com", password: "secret123" }
                    │
                    ▼
     hash = argon2.hash("secret123")
     (library makes a random salt and puts it inside the hash string)
                    │
                    ▼
DB saves: { email: "rahul@mail.com", passwordHash: "$argon2id$v=19$m=65536,t=3,p=4$..." }
```

**Never** store the plain password. Not in the DB, not in logs, nowhere.

#### Login

```
User sends: { email: "rahul@mail.com", password: "secret123" }
                    │
                    ▼
   Find user by email → get stored passwordHash
                    │
                    ▼
   argon2.verify(storedHash, "secret123")
   (library reads the salt + settings from the stored hash,
    hashes the typed password the same way, and compares)
                    │
          ┌─────────┴─────────┐
          ▼                   ▼
       ✅ match           ❌ no match
     Log them in       401 "Invalid email or password"
```

Notice: **you never "un-hash" anything.** You hash the new attempt and compare.

#### Use the library's compare, not `===`

Normal `===` stops at the **first different character**. An attacker can measure tiny time differences to learn information (a **timing attack**). Library functions like `bcrypt.compare()` and `argon2.verify()` compare safely. If you compare yourself, use `crypto.timingSafeEqual()`.

#### Upgrading old hashes (rehash on login)

Computers get faster every year, so you'll want to raise the cost over time. You can't re-hash passwords you don't know, but at **login** you have the plain password for a moment:

```
If login succeeds AND the stored hash uses old/weak settings:
    → hash the password again with new settings
    → save the new hash
```

The same trick moves users from an old algorithm (like MD5 or SHA-1) to argon2.

---

### Common beginner mistakes

1. **Using `sha256(password)` or `md5(password)`.**
   Way too fast. Use argon2id, bcrypt, or scrypt.

2. **Using one salt for every user (or no salt).**
   Each user needs their own random salt. Libraries do this for you, so let them.

3. **Writing your own hashing scheme.**
   `sha256(sha256(password + "abc"))` is still weak. Use a proven library.

4. **Comparing hashes with `===`.**
   Use `bcrypt.compare()`, `argon2.verify()`, or `crypto.timingSafeEqual()`.

5. **Storing the pepper in the same database as the hashes.**
   Then it's not a secret anymore. Keep it in env variables or a secret manager.

6. **Forgetting bcrypt's 72-byte limit.**
   Two long passwords that start with the same 72 bytes would both match. Limit password length or use argon2.

7. **Setting a tiny max password length (like 12 characters).**
   Allow long passphrases (at least 64 characters). Hashes are always the same size anyway.

8. **Logging the request body on signup/login.**
   This puts plain passwords in your log files. Remove password fields before logging.

9. **Making the cost too high.**
   If one hash takes 5 seconds, attackers can overload your server just by spamming login (a DoS). Aim for ~250 ms to 1 s, and add rate limiting (topic 16).

---

### Interview questions

1. **Why shouldn't we use SHA-256 to hash passwords?**
   It's built to be fast, so attackers can try billions of guesses per second. Password hashes like argon2 and bcrypt are slow on purpose.

2. **What is a salt, and is it secret?**
   A random value unique to each user, mixed in before hashing. It's not secret, and it's stored with the hash. It makes identical passwords produce different hashes and defeats rainbow tables.

3. **What's the difference between a salt and a pepper?**
   A salt is unique per user and stored in the DB. A pepper is a single secret stored outside the DB (env/secret manager). The pepper protects you if only the database is stolen.

4. **bcrypt vs argon2: which would you choose?**
   argon2id for new projects. It's memory-hard (resists GPU attacks), has no 72-byte limit, and is OWASP's top recommendation. bcrypt is still acceptable and widely supported.

5. **What does "memory-hard" mean?**
   The algorithm needs a lot of RAM per hash. GPUs and custom hardware have little memory per core, so attackers can't run millions of guesses in parallel cheaply.

6. **How does login work if the hash can't be reversed?**
   You hash the typed password with the same salt and settings (read from the stored hash) and compare the result with the stored hash.

7. **How would you migrate users from MD5 hashes to argon2?**
   At each successful login, verify with the old MD5 hash, then hash the plain password with argon2 and save it. (For extra safety, you can also wrap existing MD5 hashes in argon2 right away: `argon2(md5Hash)`.)

8. **What is a timing attack, and how do you prevent it in password checks?**
   Normal string comparison stops at the first mismatch, so response time leaks information. Use constant-time comparison (`crypto.timingSafeEqual`) or the library's verify function.

---

### Quick recap

- Attackers crack hashes by **guessing**, so make each guess **slow and unique**
- **Never** use MD5 or SHA-256 alone for passwords
- **Salt** = random per user, **not secret**, stored with the hash, and libraries handle it
- **Work factor** = deliberate slowness (~250 ms to 1 s per hash)
- **argon2id** is the best choice → **bcrypt** is fine → **scrypt** is built into Node
- **Pepper** = optional secret stored **outside** the DB, applied with HMAC
- Always compare with the **library's verify function**, never `===`

## Code

### 1. scrypt: built into Node.js (no install needed)

This shows each step by hand (salt, slow hash, safe compare, pepper), so you can see what libraries do for you.

```js
// scrypt-demo.js
const crypto = require("crypto");

const PEPPER = process.env.PEPPER || "dev-only-pepper"; // real apps: env variable, never in code or DB
const OPTIONS = { N: 2 ** 17, r: 8, p: 1, maxmem: 256 * 1024 * 1024 }; // OWASP minimum for scrypt

function hashPassword(password) {
  const peppered = crypto.createHmac("sha256", PEPPER).update(password).digest();
  const salt = crypto.randomBytes(16); // new random salt for every user
  const hash = crypto.scryptSync(peppered, salt, 64, OPTIONS);
  return `${salt.toString("hex")}:${hash.toString("hex")}`; // store salt + hash together
}

function verifyPassword(password, stored) {
  const [saltHex, hashHex] = stored.split(":");
  const peppered = crypto.createHmac("sha256", PEPPER).update(password).digest();
  const attempt = crypto.scryptSync(peppered, Buffer.from(saltHex, "hex"), 64, OPTIONS);
  return crypto.timingSafeEqual(attempt, Buffer.from(hashHex, "hex")); // safe compare, not ===
}

// Same password, two users → different hashes (thanks to the salt)
const rahul = hashPassword("secret123");
const priya = hashPassword("secret123");
console.log("Rahul:", rahul);
console.log("Priya:", priya);
console.log("Same hash?", rahul === priya); // false

// Login
console.time("one hash took");
console.log("Correct password:", verifyPassword("secret123", rahul)); // true
console.timeEnd("one hash took");
console.log("Wrong password:  ", verifyPassword("wrong", rahul));     // false
```

```bash
node scrypt-demo.js
```

### 2. argon2: the recommended choice for real apps

```bash
npm install argon2
```

```js
// argon2-demo.js
const argon2 = require("argon2");

(async () => {
  // Signup: salt is created and stored inside the hash automatically
  const hash = await argon2.hash("secret123", {
    type: argon2.argon2id,
    memoryCost: 19456, // 19 MiB (in KB)
    timeCost: 2,
    parallelism: 1,
  });
  console.log("Stored hash:", hash);

  // Login
  console.log("Correct:", await argon2.verify(hash, "secret123")); // true
  console.log("Wrong:  ", await argon2.verify(hash, "wrong"));     // false

  // Should this hash be upgraded to stronger settings?
  console.log("Needs rehash?", argon2.needsRehash(hash, { memoryCost: 65536 })); // true
})();
```

```bash
node argon2-demo.js
```

### 3. bcrypt: still very common

```bash
npm install bcrypt
```

```js
// bcrypt-demo.js
const bcrypt = require("bcrypt");

(async () => {
  const hash = await bcrypt.hash("secret123", 12); // 12 = cost (each +1 doubles the time)
  console.log("Stored hash:", hash); // $2b$12$...

  console.log("Correct:", await bcrypt.compare("secret123", hash)); // true
  console.log("Wrong:  ", await bcrypt.compare("wrong", hash));     // false
  console.log("Cost used:", bcrypt.getRounds(hash));                // 12
})();
```

```bash
node bcrypt-demo.js
```

Notice:
- Run any demo twice and the hash **changes every time** (new random salt), but verify still works.
- The stored string contains **everything** (algorithm, settings, salt, hash), so you store just one column.
