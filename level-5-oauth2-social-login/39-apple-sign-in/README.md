# 39. Apple Sign-In

## Notes

### What is Sign in with Apple?

"Sign in with Apple" is Apple's **OpenID Connect** login (topic 36). The user taps the button and confirms with Face ID, Touch ID or their Apple ID password. Your app gets a signed **ID token** that says who they are. It looks like Google login (topic 37), but Apple adds a few rules of its own: the **client secret is a JWT you sign yourself**, the answer comes back as a **POST** to your site, the user's **name is sent only once**, and the user can **hide their real email** behind a relay address.

> **One-line answer:** sign a short **client-secret JWT** with your `.p8` key, send the user to Apple with `response_mode=form_post`, take the **POST** at your callback, swap the code for tokens, **verify the ID token** (Apple's keys, `iss`, `aud`, `nonce`), and key the account by **`sub`**. **Save the name the first time** (you never get it again), accept **`@privaterelay.appleid.com`** emails, handle Apple's **server notifications**, and **revoke** Apple's tokens when the user deletes their account.

---

### Why does it matter?

| Problem | What goes wrong if you miss it |
|---|---|
| The App Store asks apps with third-party logins (Google, Facebook…) to also offer a privacy-friendly login such as Apple's | Your iPhone app gets rejected in review |
| The **name is sent only on the first sign-in**, and it isn't signed | Your server crashes or errors that one time → the user is "(no name)" forever |
| Apple answers with a **cross-site POST** (`form_post`) | Your `SameSite=Lax` session cookie isn't sent → "state mismatch" for every user |
| The **client secret is a JWT** that expires (6 months max) | Login suddenly breaks one day in production |
| **Hide My Email** gives you `k7x2mqp9vd@privaterelay.appleid.com` | Your emails bounce (domain not registered), or you can't match the user to their old account |
| Apple's booleans have been **strings** (`"true"`) | `if (claims.email_verified === true)` is false |
| The user can **stop using Apple ID** with your app, or delete their Apple ID | You keep sessions alive and email a dead relay address |
| App Store apps that let you sign up must let you **delete the account** and **revoke** Apple's tokens | App review rejection |

---

### Real-life example: a sealed letter from the passport office ✉️

Rahul signs up at **TiffinBox**, a lunch-box delivery app, with "Sign in with Apple":

- Apple is like the **passport office**. It sends TiffinBox a **sealed, signed letter** (the ID token) that says "this is customer #001234.5f2c…". TiffinBox checks the seal, not the handwriting.
- Rahul's **name** is written on a **sticky note** stuck to the first letter only. It isn't sealed, and there will never be another one. If TiffinBox loses it, it's gone.
- Priya chose **Hide My Email**. Her letter gives a **PO box** (`k7x2mqp9vd@privaterelay.appleid.com`). Apple forwards mail from the PO box to her real inbox, but only from senders TiffinBox has registered with Apple. She can close the PO box any time, and Apple **tells TiffinBox** (a notification).
- To collect letters, TiffinBox shows a **stamped ID** (the client-secret JWT) that it makes itself with its own stamp (the `.p8` key). The stamp is valid for at most 6 months.
- When Rahul deletes his TiffinBox account, TiffinBox tells the passport office "**forget us**" (revoke), so TiffinBox disappears from his Apple ID's app list.

---

### Sign in with Apple at a glance

| | Value |
|---|---|
| Protocol | OpenID Connect (authorization code flow) |
| Authorize | `https://appleid.apple.com/auth/authorize` |
| Token | `https://appleid.apple.com/auth/token` |
| Keys (JWKS) | `https://appleid.apple.com/auth/keys` |
| Revoke | `https://appleid.apple.com/auth/revoke` |
| Issuer (`iss`) | `https://appleid.apple.com` |
| `aud` / `client_id` | **Services ID** for the website (`in.tiffinbox.web`), **bundle ID** for the iPhone app (`in.tiffinbox.app`) |
| Scopes | `name email` (no `openid` needed, no `profile`) |
| Permanent id | `sub`: the same for all apps of **one developer team**, different for other teams |
| Email | real or **private relay**; `email_verified`, `is_private_email` (may be strings) |
| Name | **first sign-in only**, in a `user` form field (web) or `fullName` (iOS), **not signed** |
| Client secret | an **ES256 JWT** signed with your `.p8` key, valid for **up to 6 months** |

Apple changes details over time: check the current Apple developer docs when you build it.

---

### The flow, step by step

#### 📊 Diagrams

Open **[diagrams.html](diagrams.html)** in your browser (just double-click the file) to see:

- **Flow diagram**: from the button to a session, with every check
- **Data flow**: the first sign-in vs the second (where the name disappears)
- **After login**: the iPhone app's login, Apple's notifications, and account deletion

In short: `/login/apple → state + nonce (+ SameSite=None cookie) → Apple (form_post) → POST /callback/apple { code, state, user? } → state matches → client-secret JWT → token exchange → verify ID token → account by sub → save the name NOW → new session`.

---

### Step 1: Set things up in the Apple Developer portal

You need a paid Apple Developer account. Then, under **Certificates, Identifiers & Profiles**:

| What | Example | Why |
|---|---|---|
| **Team ID** | `A1B2C3D4E5` | The `iss` of your client secret |
| **App ID** with "Sign in with Apple" | `in.tiffinbox.app` | The iPhone app; its bundle ID is its `client_id`. Make it the **primary** App ID |
| **Services ID** | `in.tiffinbox.web` | The **website's** `client_id`. Add your domain and the exact **return URL** (`https://tiffinbox.in/callback/apple`) |
| **Key** with "Sign in with Apple" | `AuthKey_KEY7XQ2P9M.p8` | Signs your client secret. **Download it once**: Apple won't show it again |
| **Server-to-Server Notification Endpoint** | `https://tiffinbox.in/apple/notifications` | Apple tells you about email and consent changes |
| **Private Email Relay**: your sending domains / addresses | `mail.tiffinbox.in` | Only registered senders can email `@privaterelay.appleid.com` |

Apple doesn't accept `localhost` or plain `http://` return URLs, so the real thing needs a domain with HTTPS. That's why this demo runs against a **mock** Apple.

---

### Step 2: The client secret is a JWT you sign

Other providers give you a client secret string. Apple gives you a **private key**, and you make the secret yourself:

```js
const clientSecret = jwt.sign({ sub: SERVICES_ID }, P8_KEY, {
  algorithm: "ES256",           // the .p8 key is an EC P-256 key
  keyid: KEY_ID,                // header kid
  issuer: TEAM_ID,              // iss
  audience: "https://appleid.apple.com",
  expiresIn: "1h",              // Apple allows up to 6 months
});
```

| ✅ Do | ❌ Don't |
|---|---|
| Keep the `.p8` in a secret store; make short secrets and cache them | Commit the `.p8` to Git |
| Use `sub` = the `client_id` you're calling with (Services ID **or** bundle ID) | Reuse the website's secret for the iPhone app's code |
| Regenerate before `exp` | Paste a 6-month secret into `.env` and forget it until login breaks |

---

### Step 3: Send the user to Apple

```js
const params = new URLSearchParams({
  response_type: "code",
  response_mode: "form_post",   // REQUIRED when you ask for name or email
  client_id: SERVICES_ID,
  redirect_uri: REDIRECT_URI,   // exactly as registered
  scope: "name email",
  state, nonce,
});
res.append("Set-Cookie", `apple_login=${loginId}; HttpOnly; Secure; SameSite=None; Path=/callback/apple; Max-Age=600`);
res.redirect(`https://appleid.apple.com/auth/authorize?${params}`);
```

- `state` stops login CSRF; `nonce` ties the ID token to this login (topic 35).
- **The cookie trap:** Apple's page sends the user back with a **cross-site POST**. Browsers **don't** send `SameSite=Lax` cookies on cross-site POSTs. So the cookie that remembers `state` and `nonce` must be `SameSite=None; Secure`. Keep it narrow: short-lived, `HttpOnly`, and limited to `Path=/callback/apple`. Your normal session cookie stays `Lax`.

---

### Step 4: Handle the POST at the callback

Apple's page makes the browser POST a form to your `redirect_uri`:

```
code=c_8f2a...&state=Kp3x...&user={"name":{"firstName":"Rahul","lastName":"Sharma"},"email":"rahul@example.com"}
```

`user` is there **only the first time**. Then:

1. Read the `apple_login` cookie, find the pending login, **delete it** (one try only), and compare `state`.
2. If `error` is set (for example `user_cancelled_authorize`), stop.
3. Swap the `code` at `/auth/token` with `client_id`, `client_secret` (the JWT), `grant_type=authorization_code` and the same `redirect_uri`.
4. **Verify the ID token**: signature with Apple's JWKS (pick the key by `kid`), `iss = https://appleid.apple.com`, `aud = your Services ID`, `exp`, and `nonce`.

| ✅ Do | ❌ Don't |
|---|---|
| Take the **email from the verified ID token** | Take the email from the `user` field (anyone can POST anything) |
| Use the `user` field only as a **display name**, length-limited | Trust it for identity |
| Accept `email_verified === true \|\| === "true"` | Compare to `true` only |

---

### Step 5: Save the account, and the name, right away

```js
let account = accounts.get(claims.sub);          // key = Apple's sub
if (!account) account = create({ appleSub: claims.sub });
if (name && !account.name) account.name = name;  // first time only: save it NOW
account.email = claims.email;                    // may be a private relay address
account.appleRefreshToken = tokens.refresh_token; // needed to revoke later (encrypt at rest)
```

- **`sub`** is the account key. It's the same for the website and the iPhone app (same team), so Rahul gets **one** account either way.
- If anything fails between receiving `user` and saving it, the name is lost. The user can only get it sent again by going to **Settings → Apple ID → Sign in with Apple → TiffinBox → Stop using**, then signing in again. Save the name **before** risky work, or ask for it in your own form if it's missing.
- **Private relay emails are real, verified emails.** Send to them normally (after registering your sending domain). Never ask "please give us your real email".
- Apple's tokens are not your session. Start **your own** session (new session id, topic 50).

---

### Step 6: The iPhone app

The iOS app uses `ASAuthorizationAppleIDProvider` (no web page). After Face ID it gets an `identityToken`, an `authorizationCode`, and (first time only) `fullName` and `email`. It sends them to your backend:

```
POST /auth/apple/native
{ "identityToken": "eyJ...", "authorizationCode": "c_...", "rawNonce": "9f86d0...", "fullName": "Rahul Sharma" }
```

- Check the ID token like on the web, but with **`aud = bundle ID`**.
- The common iOS pattern passes **`SHA256(rawNonce)`** to Apple as the nonce, so the backend checks `claims.nonce === sha256(rawNonce)`. A stolen identity token is useless without the raw nonce.
- **Redeem the `authorizationCode`** (with a client secret whose `sub` is the bundle ID). It proves the code is fresh and gives you the **refresh token** you need for revoking.
- `fullName` is unsigned, like the web `user` field: display name only.

---

### Step 7: Listen to Apple's server-to-server notifications

Apple POSTs `{ "payload": "<JWT>" }` to your notification endpoint. The JWT is signed with Apple's keys, and its `events` claim (a JSON **string**) says what happened:

| `type` | Meaning | What TiffinBox does |
|---|---|---|
| `email-disabled` | User turned off forwarding for the relay address | Stop emailing it (mails bounce) |
| `email-enabled` | Forwarding is back on | Email again |
| `consent-revoked` | User tapped "Stop using Apple ID" for your app | Log them out everywhere, drop Apple tokens |
| `account-delete` | The Apple ID itself was deleted | Delete or close the account |

Verify the JWT (signature, `iss`, `aud`), ignore duplicates by `jti`, and answer `200` fast.

---

### Step 8: Account deletion means revoking

App Store rules: if your app lets people create an account, it must let them **delete** it from inside the app. For Sign in with Apple, deletion also means calling `/auth/revoke` with the stored refresh token:

```js
await postForm("https://appleid.apple.com/auth/revoke", {
  client_id, client_secret: clientSecret(client_id), token: account.appleRefreshToken, token_type_hint: "refresh_token",
});
```

After that, TiffinBox disappears from the user's Apple ID app list, and the next sign-in is a **first** sign-in again (the name is sent again).

---

### 🤔 Tricky parts

**1. "It works in dev but every real login says state mismatch."**
Your dev setup was same-site (`localhost` to `localhost`), so the `Lax` cookie was sent. In production, `appleid.apple.com` → `tiffinbox.in` is cross-site. Use a separate `SameSite=None; Secure` cookie for the pending login.

**2. The name is gone.**
A deploy, a crash, or a bug in the first callback loses the name forever (for that user and app). Save it first; fall back to "Add your name" in your own UI.

**3. Same person, two accounts.**
Rahul signed up with Google as `rahul@example.com`, then with Apple using Hide My Email. The emails don't match, so TiffinBox can't (and shouldn't) guess. Let the logged-in user **link** Apple to their account (topic 40).

**4. Different team = different `sub`.**
If the app moves to another developer team (an app transfer), every `sub` changes. Apple provides a migration process (transfer identifiers) for this; plan for it before the transfer.

**5. Web and iPhone have different `aud` values.**
Accept the **Services ID** on the website callback and the **bundle ID** on the native endpoint. Don't accept "any of my ids" everywhere.

**6. Refresh tokens.**
You can use the refresh token to check that the user still has an active Apple authorization, but Apple asks you not to call it more than about **once a day**. Most apps only keep it for revoking.

**7. Use a library in production.**
`openid-client` (topic 41), Passport's Apple strategy or Auth.js's Apple provider handle the client-secret JWT and token checks. This demo shows what they do inside.

---

### Common beginner mistakes

1. **Using `SameSite=Lax` for the cookie that holds `state`.**
   The form POST from Apple won't carry it. Use a dedicated `SameSite=None; Secure` cookie.

2. **Expecting the name on every login.**
   It comes once. Save it immediately.

3. **Trusting the `user` field or `fullName`.**
   It's not signed. Display name only; the email comes from the ID token.

4. **Rejecting `@privaterelay.appleid.com` emails** (or asking for the "real" email).
   They're valid and verified. Register your sending domain so they're delivered.

5. **Checking `email_verified === true`.**
   It can be the string `"true"`.

6. **A 6-month client secret pasted into `.env`.**
   It expires silently. Generate short ones from the `.p8` key in code.

7. **One `aud` check for both web and iOS.**
   Services ID for web, bundle ID for the app.

8. **Ignoring server-to-server notifications.**
   You keep emailing dead relays and keep sessions of users who revoked consent.

9. **Deleting the account without revoking Apple's tokens.**
   App Store rejection, and your app stays in the user's Apple ID list.

10. **Matching accounts by email.**
    Key by `sub`; linking is topic 40.

---

### Interview questions

1. **How is Sign in with Apple different from Google login?**
   Same OIDC code flow, but the client secret is an ES256 JWT you sign with a `.p8` key; name/email scopes need `response_mode=form_post`; the name is sent only once and unsigned; users can hide their email behind a relay; and Apple sends server-to-server notifications.

2. **How do you create Apple's client secret?**
   A JWT with header `alg: ES256`, `kid: <key id>`, and claims `iss: <team id>`, `sub: <client id>`, `aud: https://appleid.apple.com`, `iat`, `exp` (at most 6 months later), signed with the downloaded `.p8` private key.

3. **Which field identifies an Apple user?**
   `sub`. It's stable for your developer team, shared by the team's apps (web Services ID and iOS bundle ID), and different for other teams.

4. **Why might your session cookie be missing in Apple's callback?**
   `form_post` is a cross-site POST, and `SameSite=Lax` cookies aren't sent on those. Use a short-lived `SameSite=None; Secure` cookie for the login state.

5. **What is Hide My Email?**
   Apple gives your app a unique random address at `privaterelay.appleid.com` that forwards to the user's real inbox, only from senders you registered. The user can turn forwarding off; Apple notifies you.

6. **How does an iOS app's Apple login reach your backend safely?**
   The app sends the identity token, authorization code and raw nonce. The backend verifies the token (JWKS, `iss`, `aud` = bundle ID, `exp`, `nonce` = SHA256(raw nonce)), redeems the code, then creates its own session or tokens.

7. **What must happen when a user deletes their account?**
   Revoke the Apple refresh/access token at `/auth/revoke`, then delete the account. App Store guidelines require in-app account deletion.

8. **What are Apple's server-to-server notifications?**
   Signed JWTs Apple POSTs to your endpoint for `email-disabled`, `email-enabled`, `consent-revoked` and `account-delete`, so you can update or close the account.

---

### Quick recap

- Apple = **OIDC** with extras: **client secret is a JWT** (ES256, `.p8`, max 6 months)
- `scope=name email` ⇒ **`response_mode=form_post`** ⇒ callback is a **POST** ⇒ login-state cookie must be **`SameSite=None; Secure`**
- **Name: first time only, unsigned**: save it immediately, display only
- **Email from the ID token**; may be a **private relay**; booleans may be **strings**
- Account key = **`sub`** (team-wide: web and iOS share it)
- Web `aud` = **Services ID**, iOS `aud` = **bundle ID**; iOS nonce = **SHA256(raw nonce)**
- Handle **notifications**; on deletion **revoke** Apple's tokens
- Next: linking several logins to one account (topic 40), auth libraries (topic 41)

## Code

One **Express** file, two apps:

| Port | App |
|---|---|
| `3000` | 🍱 **TiffinBox**: the website's "Sign in with Apple", the iPhone app's `/auth/apple/native`, the notification endpoint and account deletion |
| `3001` | 🍎 **Mock Apple**: a small fake of `appleid.apple.com` with its quirks (form_post, first-time-only name, JWT client secret, revoke, notifications) |

Real Apple needs a paid developer account and an HTTPS domain, so the demo runs against a **mock**. Instead of Face ID, the mock page offers **Continue as rahul / priya**:

| User | What's interesting |
|---|---|
| `rahul` | shares his real email `rahul@example.com` |
| `priya` | chose **Hide My Email**: `k7x2mqp9vd@privaterelay.appleid.com` |

The mock also has two demo-only endpoints: `/mock/ios-sign-in` (what an iPhone gets after Face ID) and `/mock/notify` (the user changes something in their Apple ID settings).

📄 **Full code: [server.js](server.js)**. Part 1 is the mock Apple, Part 2 is TiffinBox. Read the comments, which follow the same steps as the notes above.

Install the dependencies once (from this folder), then start the server:

```bash
npm install
```

```bash
node server.js
```

> Port 3000 busy? Run it on other ports: `PORT=3039 node server.js` (Git Bash) uses **3039** and **3040**. The outputs below were recorded that way, so they show those ports.

### Try it in the browser

Open **http://localhost:3000** → **Sign in with Apple** → **Continue as priya (Hide My Email)** → the mock page auto-POSTs the form back → `/me` shows:

```json
{"id":"acct_G4oIeQ","appleSub":"001234.9b1e7c3a5d2f4e8a6c0b3d9f1e7a2c5b.1137","name":"Priya Nair","createdAt":"2026-11-05T06:04:07.725Z","email":"k7x2mqp9vd@privaterelay.appleid.com","emailVerified":true,"isPrivateEmail":true,"emailForwarding":true}
```

### Try it with curl (Git Bash)

curl doesn't run the mock page's auto-submit script, so the `apple` helper does what the browser does: it reads the hidden form fields and POSTs them to the callback.

```bash
APP=http://localhost:3000; APPLE=http://localhost:3001
red() { curl -s -o /dev/null -w "%{redirect_url}" "$@"; }
apple() {   # apple <cookie-jar> <mock user>
  L=$(red -c $1.jar -b $1.jar "$APP/login/apple")
  mapfile -t F < <(curl -s "$L&mock_user=$2" | grep -o 'name="[a-z_]*" value="[^"]*"' | sed -E 's/name="([^"]*)" value="([^"]*)"/\1=\2/; s/&quot;/"/g')
  A=(); for f in "${F[@]}"; do A+=(--data-urlencode "$f"); done
  curl -s -c $1.jar -b $1.jar -o /dev/null "${A[@]}" "$APP/callback/apple"; curl -s -b $1.jar $APP/me; echo
}
```

✅ **First sign-in, second sign-in, Hide My Email:**

```bash
apple r1 rahul; apple r2 rahul; apple p1 priya
```
→
```
{"id":"acct_5K4XQQ","appleSub":"001234.5f2c9a7e1b8d4c60a3e9f1d2b7c4a6e8.0420","name":"Rahul Sharma",...,"email":"rahul@example.com","emailVerified":true,"isPrivateEmail":false,"emailForwarding":true}
{"id":"acct_5K4XQQ","appleSub":"001234.5f2c9a7e1b8d4c60a3e9f1d2b7c4a6e8.0420","name":"Rahul Sharma",...}      ← same account
{"id":"acct_G4oIeQ","appleSub":"001234.9b1e7c3a5d2f4e8a6c0b3d9f1e7a2c5b.1137","name":"Priya Nair",...,"email":"k7x2mqp9vd@privaterelay.appleid.com","emailVerified":true,"isPrivateEmail":true,"emailForwarding":true}
```

The terminal shows the name arriving **only once**:

```
🆕 Apple (website): Rahul Sharma → acct_5K4XQQ (sub 001234.5f2c9…), email rahul@example.com, name received (first time only!)
👋 Apple (website): Rahul Sharma → acct_5K4XQQ (sub 001234.5f2c9…), email rahul@example.com, no name sent this time
🆕 Apple (website): Priya Nair → acct_G4oIeQ (sub 001234.9b1e7…), email k7x2mqp9vd@privaterelay.appleid.com 🕶️ private relay, name received (first time only!)
```

📱 **The iPhone app** (Rahul signs in on his phone: same `sub`, so the **same account**):

```bash
RAW=$(openssl rand -hex 16); HASH=$(printf %s "$RAW" | sha256sum | cut -d' ' -f1)
IOS=$(curl -s "$APPLE/mock/ios-sign-in?user=rahul&nonce=$HASH")
IT=$(echo "$IOS" | sed -E 's/.*"identityToken":"([^"]*)".*/\1/'); AC=$(echo "$IOS" | sed -E 's/.*"authorizationCode":"([^"]*)".*/\1/')
curl -s -c ios.jar $APP/auth/apple/native -H "Content-Type: application/json" -d "{\"identityToken\":\"$IT\",\"authorizationCode\":\"$AC\",\"rawNonce\":\"$RAW\"}" -w " %{http_code}\n"
```
→ `{"id":"acct_5K4XQQ",...,"name":"Rahul Sharma","email":"rahul@example.com",...} 200`
Terminal: `👋 Apple (iPhone app): Rahul Sharma → acct_5K4XQQ (sub 001234.5f2c9…), email rahul@example.com, no name sent this time`

🚫 **A stolen identity token** (wrong raw nonce), and **the same code twice**:

```bash
curl -s $APP/auth/apple/native -H "Content-Type: application/json" -d "{\"identityToken\":\"$IT\",\"authorizationCode\":\"$AC\",\"rawNonce\":\"attacker\"}" -w " %{http_code}\n"
curl -s $APP/auth/apple/native -H "Content-Type: application/json" -d "{\"identityToken\":\"$IT\",\"authorizationCode\":\"$AC\",\"rawNonce\":\"$RAW\"}" -w " %{http_code}\n"
```
→
```
{"error":"Apple login failed"} 401      ← terminal: 🚨 Apple native login failed: nonce mismatch
{"error":"Apple login failed"} 401      ← terminal: 🚨 Apple native login failed: token exchange: invalid_grant
```

📬 **Apple's notifications:** Priya turns off email forwarding, Rahul stops using his Apple ID with TiffinBox:

```bash
curl -s $APPLE/mock/notify -d user=priya -d type=email-disabled; echo
curl -s -b p1.jar $APP/me; echo
curl -s $APPLE/mock/notify -d user=rahul -d type=consent-revoked; echo
curl -s -b r1.jar $APP/me -w " %{http_code}\n"; curl -s -b ios.jar $APP/me -w " %{http_code}\n"
```
→
```
{"sent":"email-disabled","to":"priya","yourServerSaid":200}
{"id":"acct_G4oIeQ",...,"email":"k7x2mqp9vd@privaterelay.appleid.com","emailVerified":true,"isPrivateEmail":true,"emailForwarding":false}   ← stop emailing her
{"sent":"consent-revoked","to":"rahul","yourServerSaid":200}
{"error":"Not logged in. Open / and sign in with Apple"} 401     ← website session ended
{"error":"Not logged in. Open / and sign in with Apple"} 401     ← iPhone session ended too
```

A **forged** notification (an attacker's JWT, not signed by Apple) is refused:
```
{"error":"Invalid notification"} 400        ← terminal: 🚨 Rejected Apple notification: unknown kid
```

🗑️ **Delete the account** (revokes at Apple), then sign in again: it's a **first** sign-in again, so the name comes back:

```bash
curl -s -b p1.jar -X DELETE $APP/me; echo
apple p2 priya
```
→
```
{"deleted":"acct_G4oIeQ"}
{"id":"acct_3CGInw","appleSub":"001234.9b1e7c3a5d2f4e8a6c0b3d9f1e7a2c5b.1137","name":"Priya Nair",...,"isPrivateEmail":true,"emailForwarding":true}
```
Terminal:
```
🍎 revoked TiffinBox for priya
🗑️  Deleted acct_G4oIeQ and revoked its Apple tokens
🆕 Apple (website): Priya Nair → acct_3CGInw (sub 001234.9b1e7…), email k7x2mqp9vd@privaterelay.appleid.com 🕶️ private relay, name received (first time only!)
```

🧪 **The traps:**

```bash
# a callback POST without the apple_login cookie (what a Lax cookie would cause, or a CSRF attempt)
L=$(red -c s.jar -b s.jar "$APP/login/apple"); ST=$(echo "$L" | sed 's/.*state=\([^&]*\).*/\1/')
curl -s -X POST $APP/callback/apple -d code=x -d state=$ST -w " %{http_code}\n"
# asking for name + email without form_post
curl -s "$APPLE/auth/authorize?client_id=in.tiffinbox.web&redirect_uri=$APP/callback/apple&response_type=code&scope=name%20email&state=x" -w " %{http_code}\n"
# a plain password instead of a signed client-secret JWT
curl -s $APPLE/auth/token -d client_id=in.tiffinbox.web -d client_secret=my-password -d code=x -d grant_type=authorization_code -w " %{http_code}\n"
```
→
```
{"error":"This login didn't start here (state mismatch)"} 400
response_mode must be form_post when name or email scope is requested 400
{"error":"invalid_client"} 400
```

### Going live

Replace `APPLE_URL` with `https://appleid.apple.com`, set your real `TEAM_ID`, `KEY_ID`, `SERVICES_ID`, `BUNDLE_ID` and HTTPS `REDIRECT_URI`, and load the `.p8` key from a secret store instead of generating one (`crypto.createPrivateKey(fs.readFileSync(...))` or an env variable). Register the return URL, the notification endpoint and your email sending domains in the developer portal (Step 1). This demo is only tested against the mock, so check Apple's current docs for details.

> **Windows PowerShell users:** the variables, `red()` / `apple()` functions, `mapfile`, cookie jars and `PORT=... node ...` work in Git Bash. In PowerShell, use the browser, Git Bash, or `$env:PORT=3039; node server.js`.
