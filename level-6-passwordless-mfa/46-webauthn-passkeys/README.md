# 46. WebAuthn / Passkeys / FIDO2

## Notes

### What is a passkey?

A **passkey** is a login that uses a **key pair** instead of a password. Your phone or laptop makes a private key that **never leaves the device**, and gives the website only the **public** key. To log in, the website sends a random challenge, you touch the fingerprint sensor (or use Face ID, Windows Hello or the screen-lock PIN), and the device **signs** the challenge. The website checks the signature with the public key.

> **One-line answer:** a passkey = a private key on your device (unlocked by fingerprint/face/PIN) + the public key on the server; login = the server sends a random **challenge**, the device **signs** it together with the site's **origin**, the server **verifies** the signature. No shared secret, nothing to type, nothing to phish.

The names you'll hear:

| Name | What it is |
|---|---|
| **FIDO2** | The whole standard from the FIDO Alliance = WebAuthn + CTAP2 |
| **WebAuthn** | The **browser API** (W3C): `navigator.credentials.create()` and `.get()`. This is what your website uses |
| **CTAP2** | How the browser talks to the **authenticator** (a USB key, the phone over Bluetooth, the laptop's chip) |
| **Authenticator** | The thing holding the private key: Touch ID, Windows Hello, Android/iPhone screen lock, a YubiKey |
| **Relying party (RP)** | Your website. The **RP ID** is your domain, like `printkaro.com` |
| **Passkey** | A FIDO credential that is **discoverable** (login without typing a username) and usually **synced** (iCloud Keychain, Google Password Manager) |
| **Security key** | A hardware passkey (YubiKey): device-bound, never synced |

---

### Why does it matter?

| Problem with passwords (and codes) | With passkeys |
|---|---|
| Phishing: Rahul types his password **and** his TOTP code into `printkaro-login.in` | The device checks the site's real domain itself. A fake site **can't** get a signature for `printkaro.com` |
| Database leak: hashes get cracked (topic 04) | The server stores only **public** keys. A leak gives attackers nothing to log in with |
| Reused passwords: credential stuffing (topic 52) | Every site gets a **different** key pair |
| Users forget passwords: reset emails, support tickets (topic 13) | Nothing to remember |
| SMS codes: SIM swap; TOTP codes: phishable (topics 43, 44) | No code to steal or relay |
| Two steps: password + code (topic 45) | **One** step that's already two factors: the device (have) + fingerprint/PIN (are/know) |

That's why Google, Apple, Microsoft, GitHub, Amazon, PayPal and many Indian apps now offer "Sign in with a passkey".

---

### Real-life example: Rahul's bank locker seals 🔏

Rahul has a locker at home that opens only with his **thumbprint**. Inside are **seals** (rubber stamps), one per shop, each with the shop's name engraved: "PrintKaro", "Zomato", "SBI".

1. **Registering** at PrintKaro: Rahul's locker makes a brand-new seal for PrintKaro and gives the shop a **sample print** of it (the public key). The seal itself never leaves the locker
2. **Logging in**: PrintKaro hands him a slip with a **random number** on it (the challenge). Rahul's thumb opens the locker, he stamps the slip, and PrintKaro compares the stamp with its sample. Match → he's in
3. Next time the shop writes a **different** random number. An old stamped slip is useless (no replay)
4. A **fake shop** called "Pr1ntKaro" asks him to stamp a slip. The locker reads the **shop's real signboard** itself and finds no seal for "Pr1ntKaro". Nothing gets stamped. Rahul doesn't even need to notice the fake name
5. A thief who **steals the shop's sample prints** can't make stamps from them. Samples only check, they can't sign
6. If the locker is stolen, it still needs Rahul's **thumb** to open

---

### The two ceremonies

WebAuthn calls the two flows **ceremonies**: **registration** (make a passkey) and **authentication** (use it). Each is two requests to your server: get **options** (with a challenge), then **verify** the result.

#### 📊 Diagrams

Open **[diagrams.html](diagrams.html)** in your browser (just double-click the file) to see:

- **Server checks**: every check the server makes on registration and login, and what fails where
- **Data flow**: signing up with a passkey, then logging in, with the real JSON
- **Why phishing fails**: the real site vs a look-alike site, side by side

In short: `register: options { challenge, rp, user } → device makes key pair (after fingerprint) → verify { clientDataJSON, attestationObject } → save public key` and `login: options { challenge } → device signs (authenticatorData + hash(clientDataJSON)) → verify signature with saved public key → session`

| Step | Request | What happens |
|---|---|---|
| 1 | `POST /register/options` | Server makes a challenge and says who the user is |
| 2 | (browser) `navigator.credentials.create()` | Fingerprint → new key pair for this site |
| 3 | `POST /register/verify` | Server checks and saves the **public key** |
| 4 | `POST /login/options` | Server makes a challenge |
| 5 | (browser) `navigator.credentials.get()` + `POST /login/verify` | Fingerprint → signature → server checks it → session |

---

### Step 1: Registration options

```js
POST /register/options { "email": "rahul@mail.com", "name": "Rahul Sharma" }
→ {
  "challenge": "79kkpQluWa54YuKNYNSOT4XnlZxOO3YZ78EvpDf3u6M",
  "rp": { "id": "localhost", "name": "PrintKaro" },
  "user": { "id": "aZXF_1eLYjV3XtpSieRC_Q", "name": "rahul@mail.com", "displayName": "Rahul Sharma" },
  "pubKeyCredParams": [{ "type": "public-key", "alg": -7 }, { "type": "public-key", "alg": -257 }],
  "authenticatorSelection": { "residentKey": "required", "userVerification": "required" },
  "excludeCredentials": [],
  "attestation": "none"
}
```

| Field | Meaning |
|---|---|
| `challenge` | 32 random bytes. Stored on the server, **single use**, 5 minutes |
| `rp.id` | Your domain. The passkey will **only** ever work on this domain and its subdomains |
| `user.id` | The **user handle**: random bytes, **not** the email (it's stored on the device, and emails change) |
| `pubKeyCredParams` | Which algorithms you accept: `-7` = ES256 (everyone), `-257` = RS256 (older Windows Hello) |
| `residentKey: "required"` | Make a **discoverable** credential, so login works without typing the email |
| `userVerification: "required"` | The device must check a fingerprint, face or PIN, not just a tap |
| `excludeCredentials` | Passkeys the user already has, so the same device doesn't make a second one |
| `attestation: "none"` | "I don't need proof of which device model this is" (fine for consumer apps) |

| ✅ Do | ❌ Don't |
|---|---|
| Fresh random challenge per ceremony, stored server-side | A fixed or predictable challenge (replay) |
| `rp.id` = your **registrable domain**: `printkaro.com` | `www.printkaro.com` (then `app.printkaro.com` can't use it). You can't change it later without new passkeys |
| Random `user.id` | The email or the database id as `user.id` |

---

### Step 2: The browser and the authenticator

```js
const credential = await navigator.credentials.create({ publicKey: PublicKeyCredential.parseCreationOptionsFromJSON(options) });
await fetch("/register/verify", { method: "POST", body: JSON.stringify(credential.toJSON()), headers: { "Content-Type": "application/json" } });
```

What happens inside, in order:

1. The **browser** checks that `rp.id` is the page's own domain (or a parent domain). A page on `printkaro-login.in` asking for `rp.id: "printkaro.com"` gets a `SecurityError`
2. The browser writes **`clientDataJSON`** itself: `{ type: "webauthn.create", challenge, origin: "https://printkaro.com" }`. The page **can't** change the origin
3. The **authenticator** asks for the fingerprint, makes a new key pair, and keeps the private key (in the secure chip, or in iCloud Keychain / Google Password Manager for synced passkeys)
4. It returns **`authenticatorData`**: `sha256(rpId)`, flags, a counter, the new credential id and the **public key** (in COSE format, CBOR-encoded), wrapped in an **`attestationObject`**

---

### Step 3: Verify the registration

The response looks like this (all binary fields are base64url):

```json
{ "id": "g7NqE_8_KKFb7wLpgAekZQ", "type": "public-key",
  "response": { "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwi…", "attestationObject": "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRo…", "transports": ["internal"] } }
```

The server checks, in this order:

| # | Check | Stops |
|---|---|---|
| 1 | `clientDataJSON.challenge` is one **we** issued, not expired, then **delete it** | Replay |
| 2 | `clientDataJSON.type === "webauthn.create"` | Using a login response to register |
| 3 | `clientDataJSON.origin === "https://printkaro.com"` **exactly** | Phishing, a hacked subdomain |
| 4 | Decode the `attestationObject` (CBOR) → `authData` | |
| 5 | `authData.rpIdHash === sha256("printkaro.com")` | A credential made for another site |
| 6 | Flags: **UP** (user present) and **UV** (user verified) set | No fingerprint/PIN |
| 7 | Credential id not already registered | Registering one key on two accounts |
| 8 | Public key algorithm is one we allow | |
| 9 | Save `{ credentialId, publicKey, signCount, transports, backedUp }` for this user | |

`authenticatorData` is bytes, not JSON:

```
[ 32 bytes sha256(rpId) ][ 1 byte flags ][ 4 bytes signCount ][ registration only: AAGUID 16 | id length 2 | credential id | COSE public key ]

flags:  0x01 UP (touched)   0x04 UV (fingerprint/face/PIN)   0x08 BE (can sync)   0x10 BS (is synced)   0x40 AT (key included)
```

The **public key** is the only thing you store, and it isn't a secret. If it leaks, nobody can log in with it.

---

### Step 4: Login options

```js
POST /login/options
→ { "challenge": "03PDfudX3ZS4H8ExhF7WrgLZeLki2HW5O4JcDrxigMk", "rpId": "localhost", "allowCredentials": [], "userVerification": "required" }
```

`allowCredentials: []` means **usernameless** login: no email box. The device shows "Sign in as Rahul Sharma?" from the passkeys it has for this site. (If you ask for the email first, you can list that user's credential ids here instead, but that leaks which emails have accounts, topic 51.)

---

### Step 5: Verify the login

The device returns:

```json
{ "id": "g7NqE_8_KKFb7wLpgAekZQ",
  "response": { "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0Ii…", "authenticatorData": "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MFAAAAAQ",
                "signature": "MEUCIQD9Xyfg1ad2llBAz-csfVynFmw6…", "userHandle": "aZXF_1eLYjV3XtpSieRC_Q" } }
```

The server:

1. Checks `clientDataJSON` the same way: **challenge** (then delete it), `type === "webauthn.get"`, **origin**
2. Finds the credential by `id`. Unknown → `401`. If `userHandle` is sent, it must match the owner
3. Checks `authenticatorData`: `rpIdHash`, **UP** and **UV**
4. **Verifies the signature:**

```js
const signedBytes = Buffer.concat([authenticatorData, sha256(clientDataJSON)]); // challenge + origin are inside clientDataJSON
crypto.verify("sha256", signedBytes, storedPublicKey, signature); // true → it really is Rahul's device
```

5. **signCount:** if the counter is used and didn't go **up**, two devices may hold the same key (a **clone**) → reject and alert. Synced passkeys always send `0`, so skip the check then
6. New session (topic 50: new id). The login is already two factors, so `amr: ["hwk", "mfa"]` (topic 45)

| ✅ Do | ❌ Don't |
|---|---|
| Verify the signature over the **raw** bytes you received | Re-encode `clientDataJSON` and hash your version |
| Compare `origin` with a **fixed** value | Build the expected origin from the `Host` header |
| Delete the challenge on first use, even if a check fails | Let a challenge be used again |
| Use a library in production (`@simplewebauthn/server`, `fido2-lib`) | Ship your own CBOR/COSE parser (this demo does it only to show what's inside) |

---

### Step 6: Managing passkeys

| Rule | Why |
|---|---|
| Let users have **several** passkeys (phone, laptop, security key) | Losing one device shouldn't lock them out |
| Show a list: name, created, **last used**, synced or not | They can spot one they don't recognise |
| **Don't delete the last** passkey unless there's another way in | Lockout |
| Email the user when a passkey is **added or removed** | An attacker adding their own passkey is how accounts get taken over |
| Adding/removing passkeys needs a **recent** login (step-up, topic 45) | A stolen session cookie shouldn't add an attacker's passkey |
| Keep a recovery path: a second passkey, recovery codes, or a slow verified process | Phones get lost |

---

### 🤔 Tricky parts

**1. Synced vs device-bound passkeys.** Synced passkeys (Apple, Google, 1Password) live in a cloud account and appear on all your devices: great for normal users, but the passkey is only as safe as that cloud account. Device-bound ones (YubiKey, some Windows Hello) never leave the chip: banks and admins may require them. The **BE/BS** flags tell you which you got. Synced ones send `signCount: 0`.

**2. Attestation.** With `attestation: "direct"` the device sends a certificate proving its **model** (the AAGUID says "YubiKey 5"). Enterprises use it to allow only approved keys. Consumer apps use `"none"`: it adds privacy prompts and work for little gain.

**3. Passkey autofill (conditional UI).** Put `autocomplete="username webauthn"` on the email box and call `navigator.credentials.get({ mediation: "conditional", ... })` when the page loads. The passkey then shows up in the browser's autofill list like a saved password. It's the smoothest way to move users from passwords to passkeys.

**4. Cross-device sign-in.** On a computer with no passkey, the browser shows a **QR code**. Rahul scans it with his phone, which checks the computer is **nearby over Bluetooth** (so a phisher across the internet can't use the trick) and signs.

**5. Phishing-proof only if the password is gone.** If the account still accepts "password + SMS code", attackers phish that instead. Long term: passkey first, password removed or behind extra checks.

**6. RP ID and origins.** `rp.id` can't be changed later. Using it on another domain (`printkaro.in`) needs the **Related Origins** file at `/.well-known/webauthn`. Android and iOS apps link to your domain with `assetlinks.json` / `apple-app-site-association`.

**7. `userVerification`.** `"required"` = fingerprint/face/PIN every time, so the passkey alone counts as MFA. `"preferred"` lets some security keys log in with just a tap: then it's only one factor, and you should check the **UV flag** before treating it as MFA.

**8. WebAuthn as a second factor.** You can also keep the password and use a security key only as the second step in topic 45's flow (`residentKey: "discouraged"`, `allowCredentials` = the user's keys). That's still phishing-proof for the second factor.

---

### Common beginner mistakes

1. **Not checking the origin** (or checking with `includes`/`startsWith`). That removes the phishing protection.
2. **Reusing challenges** or making them predictable. Generate 32 random bytes, store, delete on use.
3. **Not checking `rpIdHash`** or the **UV** flag.
4. **Verifying the signature over the wrong bytes**: it's `authenticatorData + sha256(clientDataJSON)`, with the raw bytes as received.
5. **Using the email as `user.id`.**
6. **Trusting `userHandle` or the credential id without verifying the signature.** They are just labels; the signature is the proof.
7. **Allowing only one passkey** per account, or letting users delete the last one.
8. **No alerts** when a passkey is added or removed.
9. **Rejecting synced passkeys because `signCount` is 0.**
10. **Picking `www.` as the RP ID**, then being stuck with it.
11. **Keeping the phishable password + SMS login next to passkeys forever.**
12. **Writing your own WebAuthn verification in production.** Use a maintained library; it also handles attestation formats, extensions and spec changes.

---

### Interview questions

1. **What is a passkey and how is it different from a password?**
   A key pair: the private key stays on the device, the server stores the public key. Login is signing a random challenge, so there's no secret to type, reuse, phish or leak from the database.

2. **What are WebAuthn, CTAP2 and FIDO2?**
   WebAuthn is the browser API websites call, CTAP2 is how the browser talks to authenticators, FIDO2 is both together.

3. **Why are passkeys phishing-resistant?**
   The browser puts the real origin into `clientDataJSON` and only allows the site's own RP ID; the authenticator only has keys scoped to that RP ID; the server checks the origin and `rpIdHash`. A look-alike domain can't get a valid signature.

4. **Walk through registration.**
   Server sends a challenge, RP info, user handle and allowed algorithms. The authenticator verifies the user and creates a key pair. The server checks challenge, type, origin, rpIdHash and flags, then stores the credential id and public key.

5. **Walk through authentication.**
   Server sends a challenge. The authenticator signs `authenticatorData + sha256(clientDataJSON)`. The server checks challenge, origin, rpIdHash, UP/UV flags, verifies the signature with the stored public key and checks the sign counter.

6. **What is the sign counter for?**
   Detecting cloned authenticators: it should go up on every use. If it doesn't, two copies of the key exist. Synced passkeys always send 0.

7. **What is attestation, and do you need it?**
   A signed statement about the authenticator's model. Most consumer apps use `none`; enterprises use it to allow only approved hardware keys.

8. **Discoverable vs non-discoverable credentials?**
   Discoverable (resident) keys are stored on the device with the user handle, so login works without a username. Non-discoverable ones need the server to send `allowCredentials` first.

9. **Does a passkey count as MFA?**
   Yes when user verification happened: the device (something you have) plus fingerprint/face/PIN (are/know). Check the UV flag.

10. **What happens if the user loses their phone?**
    Synced passkeys come back on a new device via the cloud account. Otherwise they use another registered passkey or the recovery process, which is why you allow several passkeys and protect recovery carefully.

---

### Quick recap

- Passkey = **private key on the device** + **public key on the server**; login = sign a **random challenge**
- Two ceremonies, each **options → verify**: registration saves the public key, authentication checks a signature
- Server checks: **challenge** (single use), **type**, **origin** (exact), **rpIdHash**, **UP + UV** flags, **signature**, **signCount**
- The browser writes the origin; the authenticator only signs for its own RP ID → **phishing-proof**
- `user.id` = random handle; `residentKey: "required"` for usernameless login; `attestation: "none"` for consumer apps
- Synced passkeys: BE/BS flags, counter 0; security keys: device-bound, counter goes up
- Several passkeys per user, alerts on add/remove, never delete the last one, use a library in production

## Code

A small **Express** app: **PrintKaro** where you can **sign up with only a passkey** (no password at all), sign in, add a second device and remove a lost one. WebAuthn verification is written **from scratch** with Node's `crypto` (CBOR, COSE keys, signature check) so you can see every step.

📄 **Full code: [server.js](server.js)**. Open it and read the comments, which follow the same steps as the notes above.

It has three parts:

1. A tiny **CBOR** decoder/encoder (the binary format authenticators use), with self-checks from RFC 8949
2. A **pretend authenticator** you run from the terminal, so you can test with curl. A `.json` file plays the device and holds its private keys (like a cookie jar plays the browser)
3. The **website**: the WebAuthn endpoints, plus a small page at `/` to try a **real** passkey

Install Express once (from this folder), then start the server:

```bash
npm install
```

```bash
node server.js
```

> Port 3000 busy? Run it on another port: `PORT=3046 node server.js` (Git Bash), then use that port in the commands below. The outputs below were recorded on port 3046. The expected origin follows the port automatically.

### Try it with a real passkey (browser)

Open `http://localhost:3046` in Chrome, Edge, Safari or Firefox (2024 or newer), type an email and click **Create account with a passkey**. Windows Hello, Touch ID or your phone (via QR code) will ask for your fingerprint, face or PIN. Then **Log out** and **Sign in with a passkey**: no email needed. `localhost` counts as a secure context, so this works without HTTPS.

### Try it with curl (Git Bash)

```bash
APP=http://localhost:3046
```

📝 **① Sign up:** ask for registration options.

```bash
curl -s $APP/register/options -H "Content-Type: application/json" -d '{"email":"rahul@mail.com","name":"Rahul Sharma"}' > options.json
cat options.json
```
→ `{"challenge":"79kkpQluWa54YuKNYNSOT4XnlZxOO3YZ78EvpDf3u6M","rp":{"id":"localhost","name":"PrintKaro"},"user":{"id":"aZXF_1eLYjV3XtpSieRC_Q","name":"rahul@mail.com","displayName":"Rahul Sharma"},"pubKeyCredParams":[{"type":"public-key","alg":-7},{"type":"public-key","alg":-257}],"authenticatorSelection":{"residentKey":"required","userVerification":"required"},"excludeCredentials":[],"attestation":"none","timeout":300000}`

👆 **② The "phone" makes a passkey.** The pretend authenticator reads the options, makes a key pair, saves the private key in `phone.json` and prints what a browser would send:

```bash
node server.js authenticator phone.json $APP < options.json > credential.json
cat credential.json
```
→
```
👆 Fingerprint OK. New passkey for rahul@mail.com on "localhost" saved in phone.json
{"id":"g7NqE_8_KKFb7wLpgAekZQ","rawId":"g7NqE_8_KKFb7wLpgAekZQ","type":"public-key","authenticatorAttachment":"platform","response":{"clientDataJSON":"eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiNzlra3BRbHVXYTU0WXVLTllOU09UNFhubFp4T08zWVo3OEV2cERmM3U2TSIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6MzA0NiIsImNyb3NzT3JpZ2luIjpmYWxzZX0","attestationObject":"o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YViUSZYN5Yg…","transports":["internal"]}}
```

Decode the `clientDataJSON` to see what the browser signed up for: `node -e "console.log(Buffer.from(process.argv[1], 'base64url').toString())" PASTE_IT` → `{"type":"webauthn.create","challenge":"79kk…","origin":"http://localhost:3046","crossOrigin":false}`

✅ **③ Send it to the server:** it checks everything and saves the public key. A new account, signed in right away.

```bash
curl -s -i -c phone.jar -b phone.jar -A "Rahul's phone" $APP/register/verify -H "Content-Type: application/json" -d @credential.json
```
→
```
HTTP/1.1 201 Created
Set-Cookie: sid=K-TbiGTvOFBCv3x-tkq3vb2nELX6BJwN3CT1Ymqe1Ec; Max-Age=604800; Path=/; Expires=...; HttpOnly; SameSite=Lax
{"message":"Account created with a passkey","passkey":{"id":"g7NqE_8_KKFb7wLpgAekZQ","label":"Rahul's phone","alg":"ES256","synced":false,"signCount":0,"createdAt":"2026-11-05T09:29:00.714Z","lastUsedAt":null}}
```

④ **Who am I?**

```bash
curl -s -b phone.jar $APP/me
```
→ `{"email":"rahul@mail.com","name":"Rahul Sharma","amr":["hwk","mfa"],"authAt":"2026-11-05T09:29:00.715Z","passkeys":[{"id":"g7NqE_8_KKFb7wLpgAekZQ","label":"Rahul's phone","alg":"ES256","synced":false,"signCount":0,"createdAt":"2026-11-05T09:29:00.714Z","lastUsedAt":null}]}`

🔑 **⑤ Log out, then sign in with the passkey.** No email, no password:

```bash
curl -s -b phone.jar -c phone.jar -X POST $APP/logout
curl -s -X POST $APP/login/options > login-options.json
node server.js authenticator phone.json $APP < login-options.json > assertion.json
curl -s -c phone.jar -b phone.jar $APP/login/verify -H "Content-Type: application/json" -d @assertion.json
```
→
```
{"message":"Logged out"}
👆 Fingerprint OK. Signed the challenge as rahul@mail.com (counter 1)
{"message":"Signed in as rahul@mail.com","passkey":"Rahul's phone"}
```

`login-options.json` is just `{"challenge":"03PDfudX…","rpId":"localhost","allowCredentials":[],"userVerification":"required","timeout":300000}`, and `assertion.json` holds the `authenticatorData`, the `signature` and the `userHandle`.

🛡️ **⑥ Replay:** send the same signed login again.

```bash
curl -s $APP/login/verify -H "Content-Type: application/json" -d @assertion.json
```
→ `{"error":"Challenge expired or already used"}`

🎣 **⑦ Phishing:** a look-alike site relays PrintKaro's options. The authenticator (really: the browser) checks the page's domain and refuses:

```bash
curl -s -X POST $APP/login/options | node server.js authenticator phone.json http://printkaro-login.in
```
→ `❌ SecurityError: a page on printkaro-login.in can't use passkeys for "localhost"`

A page on a **subdomain** (say a hacked blog) **may** use the parent's passkeys, but the origin goes into the signed data, and the server only accepts its own:

```bash
curl -s -X POST $APP/login/options | node server.js authenticator phone.json http://blog.localhost:3046 | curl -s $APP/login/verify -H "Content-Type: application/json" -d @-
```
→
```
👆 Fingerprint OK. Signed the challenge as rahul@mail.com (counter 2)
{"error":"Wrong origin: expected http://localhost:3046, got http://blog.localhost:3046"}
```

🧬 **⑧ A cloned key:** copy the "device" file (like cloning a security key), use the real one, then the copy. The copy's counter didn't go up:

```bash
cp phone.json clone.json
curl -s -X POST $APP/login/options | node server.js authenticator phone.json $APP | curl -s $APP/login/verify -H "Content-Type: application/json" -d @-
curl -s -X POST $APP/login/options | node server.js authenticator clone.json $APP | curl -s $APP/login/verify -H "Content-Type: application/json" -d @-
```
→
```
👆 Fingerprint OK. Signed the challenge as rahul@mail.com (counter 3)
{"message":"Signed in as rahul@mail.com","passkey":"Rahul's phone"}
👆 Fingerprint OK. Signed the challenge as rahul@mail.com (counter 3)
{"error":"Sign counter went backwards: this passkey may have been cloned"}
```
and the server logs `⚠️  Possible cloned passkey … counter 3 <= 3`.

💻 **⑨ Add a second device ("laptop")** while signed in. Now `excludeCredentials` lists the phone's passkey, so the phone refuses to make a second one, and the laptop makes a new one:

```bash
curl -s -b phone.jar -X POST $APP/register/options > add.json
node server.js authenticator phone.json $APP < add.json
node server.js authenticator laptop.json $APP < add.json | curl -s -b phone.jar -A "Rahul's laptop" $APP/register/verify -H "Content-Type: application/json" -d @-
```
→
```
❌ InvalidStateError: this device already has a passkey for this account
👆 Fingerprint OK. New passkey for rahul@mail.com on "localhost" saved in laptop.json
{"message":"Passkey added","passkey":{"id":"w3Dj4P2mWPnyM4XffMgsXg","label":"Rahul's laptop","alg":"ES256","synced":false,"signCount":0,"createdAt":"2026-11-05T09:29:02.773Z","lastUsedAt":null}}
```

📵 **⑩ Lost the phone:** sign in on the laptop and remove the phone's passkey. Removing the **last** one is refused:

```bash
curl -s -X POST $APP/login/options | node server.js authenticator laptop.json $APP | curl -s -c laptop.jar $APP/login/verify -H "Content-Type: application/json" -d @-
PHONE=$(grep -o '"id": "[^"]*"' phone.json | cut -d'"' -f4)
LAPTOP=$(grep -o '"id": "[^"]*"' laptop.json | cut -d'"' -f4)
curl -s -b laptop.jar -X DELETE $APP/passkeys/$PHONE
curl -s -b laptop.jar -X DELETE $APP/passkeys/$LAPTOP
curl -s -X POST $APP/login/options | node server.js authenticator phone.json $APP | curl -s $APP/login/verify -H "Content-Type: application/json" -d @-
```
→
```
👆 Fingerprint OK. Signed the challenge as rahul@mail.com (counter 1)
{"message":"Signed in as rahul@mail.com","passkey":"Rahul's laptop"}
{"message":"Passkey removed","passkeysLeft":1}
{"error":"This is your only passkey. Add another one first, or you'll be locked out."}
👆 Fingerprint OK. Signed the challenge as rahul@mail.com (counter 4)
{"error":"Unknown passkey (it was deleted, or it belongs to another site)"}
```
The terminal shows a `📧 A passkey was removed from your PrintKaro account` alert email.

🛡️ **⑪ Bad requests:**

```bash
curl -s $APP/register/options -H "Content-Type: application/json" -d '{"email":"Rahul@mail.com"}'; echo
curl -s $APP/login/verify -H "Content-Type: application/json" -d '{}'; echo
```
→
```
{"error":"This email already has an account. Sign in with your passkey, then add a new one."}
{"error":"clientDataJSON must be a base64url string"}
```
A changed signature gives `{"error":"Bad signature"}`.

> The `.json` "device" files hold private keys, in plain text, for the demo only. Delete them when you're done (`rm phone.json clone.json laptop.json *.jar`). Restarting the server forgets every account, so delete them then too.

> **Windows PowerShell users:** the pipes, `< file`, `$(...)`, `grep` and `cut` work in Git Bash. In PowerShell, use Git Bash, or the browser page at `/`.
