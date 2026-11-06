# 61. Single Logout (SLO)

## Notes

### What is Single Logout?

With SSO (topic 57) you log in **once** at the identity provider (IdP: Okta, Azure AD/Entra ID, Google, Keycloak) and then get into Mail, Drive and Chat without typing a password again. **Single Logout** is the other half: you log out **once** and you're logged out of **all** of them.

> **One-line answer:** SLO = the IdP **remembers every app you signed in to** during your login session, and when you log out (from any app or from the IdP) it **ends its own session and tells each app to end theirs**. In OpenID Connect that's **RP-Initiated Logout** (the app sends the browser to the IdP's `end_session_endpoint`) plus **Back-Channel Logout** (the IdP's server POSTs a signed `logout_token` to each app's server). SAML does the same with `LogoutRequest` messages (topic 58).

There are **three layers** of "being logged in" in SSO, and a real logout has to reach all of them:

| Layer | Lives where | Ends when |
|---|---|---|
| **IdP session** (`idp_sid` cookie) | The IdP | IdP logout, or its timeout |
| **App sessions** (`mail_sid`, `drive_sid`, …) | Each app's server | That app's logout, **or a message from the IdP** |
| **Tokens** (ID / access / refresh tokens) | The apps | Expiry, or revocation at the IdP (topic 70) |

---

### Why it matters

| Problem | What goes wrong |
|---|---|
| App only does a **local logout** | The IdP session is still alive, so the next "Sign in" click logs you **straight back in, no password** (the logout "doesn't stick") |
| Other apps never hear about it | You logged out of Mail on a library computer; the next person opens Drive and it's still you |
| Admin disables a hacked account / fired employee | The IdP session dies, but every app session lives on for hours |
| `post_logout_redirect_uri` not checked | The IdP's logout URL becomes an **open redirect** to a phishing page |
| Logout by a plain link (GET) with no check | Any website can log you out of everything with `<img src="…/logout">` (logout CSRF) |
| Back-channel endpoint trusts any token | An attacker logs out any user, or replays an ID token as a "logout" |

Compliance rules (banks, hospitals, government) usually require that logout ends **all** access. "We cleared one cookie" fails the audit.

---

### Real-life example: the hotel key card 🏨

Rahul checks in at a hotel in Goa. The **reception** (IdP) gives him one key card. With it he gets a wristband at the **gym**, the **pool** and the **lounge** (the apps, each with its own session). The reception writes down every place where he picked up a wristband.

1. **Local logout:** Rahul takes off his gym wristband. Next morning he taps his key card at the gym → new wristband, no questions. Nothing really ended.
2. **Single logout:** Rahul checks out at reception. Reception **deactivates the key card** and **phones** the gym and the pool: "cut wristband #4521" (back-channel). Now nothing works anywhere.
3. **The old lounge has no phone line** (an app without SLO support). His lounge wristband keeps working until it expires at midnight, and someone could still use his ₹500 of lounge credit. That's why every app also needs its own **short session**.
4. **A prankster** calls the gym pretending to be reception: "cut Rahul's wristband." The gym checks the **reception's seal** (signature) before believing it.

---

### The big picture

#### 📊 Diagrams

Open **[diagrams.html](diagrams.html)** in your browser (just double-click the file) to see:

- **Flow diagram**: what happens on "Sign out", step by step, and where each check sits
- **Data flow (single logout)**: Mail → IdP → back-channel calls to Drive and Chat, with the real requests from our run
- **Back-channel vs front-channel**: the two ways the IdP can tell the apps, side by side

In short: `app ends its session → browser to IdP /logout (id_token_hint) → IdP ends its session → IdP POSTs a signed logout_token to every app → each app deletes its session → browser back to the app`.

| Way to log out | Who starts it | Reaches other apps? |
|---|---|---|
| **Local logout** | One app | ❌ No. The IdP session even logs you back in |
| **RP-initiated logout** | An app ("Sign out" in Mail) → redirects to the IdP | ✅ Yes, through the IdP |
| **IdP-initiated logout** | The IdP ("Sign out everywhere", admin, password reset) | ✅ Yes |
| **Back-channel logout** | IdP server → app server, signed JWT | The *delivery* method. Reliable, no browser needed |
| **Front-channel logout** | IdP page loads hidden iframes of every app | The old delivery method. Breaks when third-party cookies are blocked |
| **SAML SLO** | `LogoutRequest` / `LogoutResponse` passed from app to app | Same idea, more fragile (one broken app stops the chain) |

---

### Step 1: The IdP remembers which apps you signed in to

At login the IdP creates a session with a **public id**, `sid`, and every time it gives a code to an app it adds that app to the list:

```js
const s = { sid: crypto.randomUUID(), userId: user.id, email, apps: new Set() }; // at /idp/login
cur.s.apps.add(client.id);                                                     // at /idp/authorize
```

The `sid` goes into the **ID token** (topic 60), and the app stores it next to its own session:

```json
{ "iss": "http://localhost:4861/idp", "sub": "user-1001", "aud": "mail", "email": "rahul@mail.com", "sid": "ebd36806-…" }
```

| ✅ Do | ❌ Don't |
|---|---|
| Use a separate random `sid` as the public name of the session | Put the IdP **cookie value** in tokens (that's the password to the session) |
| Store `sid` + the ID token with the app session | Throw the ID token away (you need it as the `id_token_hint`) |
| Register every app's logout URLs up front | Accept URLs from the request |

---

### Step 2: RP-initiated logout (the app sends you to the IdP)

The user clicks "Sign out" in Mail. Mail:

1. **deletes its own session first** (if the user closes the tab now, at least Mail is done),
2. redirects the browser to the IdP's `end_session_endpoint` (from the discovery document):

```
GET /idp/logout?id_token_hint=eyJhbGciOi…&client_id=mail&post_logout_redirect_uri=http://localhost:4861/mail/logged-out
```

| Parameter | Why |
|---|---|
| `id_token_hint` | Proves **which** session is logging out. Without it, the IdP should **ask** before logging out (could be logout CSRF) |
| `post_logout_redirect_uri` | Where to send the browser back. Must **exactly match** a registered URL, or it's an open redirect |
| `client_id` | Needed to look up registered URLs when there's no hint |
| `state` (optional) | Echoed back, so the app can show the right page after logout |

The IdP checks all of that, ends its session, **tells every app** (Step 3), and only then redirects back.

| ✅ Do | ❌ Don't |
|---|---|
| Make the app's "Sign out" button a **POST** | Log out on `GET /logout` (any site can trigger it) |
| Accept an **expired** `id_token_hint` (it only says *who*) | Accept a hint with a bad signature or wrong `iss` |
| Exact-match `post_logout_redirect_uri` against the registered list | Prefix match, or "any URL on our domain" |
| Show "Sign out of all apps?" when there's no valid hint | Silently log out everywhere on any GET |

---

### Step 3: The IdP tells every app: back-channel logout

For each app in the session that registered a `backchannel_logout_uri`, the IdP's **server** POSTs a **logout token**, a JWT signed with the IdP's key:

```
POST /drive/backchannel-logout
Content-Type: application/x-www-form-urlencoded

logout_token=eyJhbGciOiJSUzI1NiIsInR5cCI6ImxvZ291dCtqd3QifQ…
```

Decoded:

```json
// header
{ "alg": "RS256", "typ": "logout+jwt" }
// payload
{
  "iss": "http://localhost:4861/idp",
  "aud": "drive",
  "iat": 1793946867, "exp": 1793946987,
  "jti": "5f0c…",
  "sub": "user-1001",
  "sid": "ebd36806-…",
  "events": { "http://schemas.openid.net/event/backchannel-logout": {} }
}
```

- Calls go out **in parallel**, each with a **timeout** (3 s in our demo), so one slow app can't hang the logout.
- A failed call is **logged and retried** (real IdPs). The user still gets logged out of the IdP.
- Apps **without** a back-channel URL can't be told. They rely on their own short session (Step 6).

---

### Step 4: The app's back-channel endpoint checks the token, then deletes sessions

No browser is involved, so there is **no cookie** to clear. The app deletes its **server-side** session; the next request with the old cookie gets 401.

```js
if (!jwt) return reject("bad signature or alg");
if (header.typ !== "logout+jwt" || !t.events?.[BACKCHANNEL_EVENT]) return reject("not a logout token");
if ("nonce" in t) return reject("a logout token must not contain a nonce");
// ...iss, aud, iat/exp, sid or sub, jti not seen before...
for (const [key, s] of sessions) if (s.idpSid === t.sid) sessions.delete(key);
res.sendStatus(200);
```

| Check | Stops |
|---|---|
| Signature with the IdP's key, `alg` fixed to `RS256` | Forged tokens, `alg: none` (topic 53) |
| `typ: logout+jwt`, `events` claim present, **no** `nonce` | An **ID token** (also signed by the IdP!) being replayed as a logout token |
| `iss` = our IdP, `aud` = this app | A token meant for another app |
| `iat` recent, `exp` in the future | Old tokens |
| `jti` not seen before | Replays |
| `sid` or `sub` present | A token that doesn't say whom to log out |

Then answer **200** (even if no session matched: the user is logged out either way) with `Cache-Control: no-store`. Any check fails → **400**.

| `sid` in token | `sub` only |
|---|---|
| End only sessions from **that** IdP login (this laptop) | End **every** session of that user (all devices) |

---

### Step 5: Front-channel logout and SAML SLO (the older ways)

**Front-channel logout:** the IdP's logout page contains a hidden `<iframe src="https://drive.chai.com/frontchannel-logout?iss=…&sid=…">` for each app. Each iframe runs in the **browser** and clears that app's cookie.

- It needs the app's cookie inside a **third-party iframe**. Safari, Firefox and (more and more) Chrome **block third-party cookies**, so the iframe sees no cookie and nothing happens.
- If the user closes the tab early, some iframes never load.
- Only use it for apps the IdP can't reach server-to-server, and treat it as best-effort.

**SAML SLO** (topic 58): the IdP sends a signed `<LogoutRequest>` to each SP, usually through **browser redirects** one SP after another, and each answers with `<LogoutResponse>`. One broken SP stops the chain, so many companies turn SAML SLO off. The SOAP (back-channel) binding is more reliable but needs a network path from the IdP to every SP.

---

### Step 6: Apps that can't be told, and tokens

SLO is **best-effort**. Plan for the apps it doesn't reach:

| Gap | Fix |
|---|---|
| App doesn't support back-channel (our ChaiChat) | Short app sessions (minutes to hours, not weeks); re-check with the IdP using `prompt=none` from time to time |
| IdP can't reach the app (intranet app, SaaS IdP) | Front-channel as a fallback, or the app polls/re-checks the IdP |
| **Refresh tokens** from that session | Revoke them at the IdP during logout (topic 70) |
| **Access tokens** already handed out | Can't be recalled. Keep them short (5–15 min) or use introspection (topic 70) |
| Stateless JWT session cookies in the app | Back-channel can't delete them. Keep a small denylist of ended `sid`s until those cookies expire (topic 24) |

---

### 🤔 Tricky parts

**1. Local logout looks like it works.** Mail says "Signed out". Click "Sign in" and you're back without a password, because the IdP session never ended. That's step ④ in our demo.

**2. `id_token_hint` travels in the URL.** It ends up in browser history, proxy logs and the IdP's access logs, and it contains the user's email. In our demo that's how the "attacker" in Part C gets an ID token to replay. OIDC also allows sending these parameters as a **POST form**, which keeps them out of logs.

**3. The back-channel call has no cookie.** So the app **must** have server-side sessions (or a denylist) that it can find by `sid`. If you run 5 app servers, the session store must be shared (Redis), because the IdP's call can land on any of them.

**4. The ID token is signed by the same key as the logout token.** Without the `typ` / `events` / no-`nonce` checks, anyone holding an old ID token (from a log file) could send it to your back-channel endpoint. That's step ⑩.

**5. `sid` vs `sub`.** A logout token with only `sub` logs the user out on **every** device. Usually you want only the session they clicked "Sign out" in. Global logout is a separate "Sign out everywhere" button.

**6. Order matters.** App first deletes its session, then redirects. The IdP first deletes its session, then calls the apps, then redirects. Each step is safe even if the next one never happens.

**7. Logging back in during logout.** If the IdP calls the apps **before** deleting its own session, an app could silently get a new code in between. Delete the IdP session first (our `endIdpSession` does).

---

### Common beginner mistakes

1. **Only clearing the app's own cookie.**
   The IdP session logs the user straight back in.

2. **Logout as a GET link with no confirmation.**
   Any site can log your users out (logout CSRF).

3. **Not validating `post_logout_redirect_uri`.**
   Open redirect for phishing.

4. **Trusting any JWT at the back-channel endpoint.**
   Check signature, `alg`, `typ`, `events`, `iss`, `aud`, `iat`/`exp`, `jti`, and no `nonce`.

5. **Storing app sessions only in a signed cookie.**
   The back-channel call has nothing to delete.

6. **Calling every app one after another with no timeout.**
   One dead app makes the user wait forever. Parallel + timeout + retry.

7. **Putting the IdP cookie value in tokens instead of a separate `sid`.**

8. **Forgetting refresh tokens.**
   The app sessions die, but a refresh token keeps minting access tokens.

9. **Long-lived app sessions "because SLO handles it".**
   SLO doesn't reach every app. Short sessions are the safety net.

10. **Relying on front-channel iframes in 2026.**
    Third-party cookie blocking makes them silently do nothing.

---

### Interview questions

1. **What is Single Logout?**
   Logging out once and being logged out of the IdP and every app that used that SSO session. The IdP tracks which apps the session was used for and notifies each one.

2. **What's the difference between local logout and single logout?**
   Local logout ends only the app's session; the IdP session survives, so the next login is silent. Single logout ends the IdP session and every app session.

3. **Explain OIDC RP-Initiated Logout.**
   The app ends its session and redirects the browser to the IdP's `end_session_endpoint` with `id_token_hint`, `post_logout_redirect_uri` (must be registered) and optionally `client_id` and `state`. The IdP ends its session, notifies other apps, and redirects back.

4. **Back-channel vs front-channel logout?**
   Back-channel: the IdP's server POSTs a signed `logout_token` JWT to each app's server. Reliable, no browser needed, but the IdP must reach the app and the app needs server-side sessions. Front-channel: the IdP renders iframes pointing at each app's logout URL in the browser. No server connection needed, but third-party cookie blocking and closed tabs break it.

5. **What does an app check in a logout token?**
   Signature with the IdP's key and a fixed `alg`; `iss`, `aud`, `iat`, `exp`; the `events` claim with the back-channel logout event; `typ` `logout+jwt`; no `nonce`; a `sid` or `sub`; and a `jti` not seen before.

6. **Why must a logout token not contain a `nonce`?**
   ID tokens have a `nonce`, logout tokens don't. That rule (plus `events` and `typ`) stops an ID token, signed by the same key, from being accepted as a logout token.

7. **How does an app find the session to end?**
   By the `sid` claim, which the IdP also put in the ID token at login and the app stored with its session. Without `sid`, by `sub` (all of that user's sessions).

8. **Is SLO guaranteed?**
   No. Apps may be down, unreachable or not support it. Keep app sessions and access tokens short, revoke refresh tokens, and log failed notifications.

9. **How does SAML SLO work, and why is it often disabled?**
   Signed `LogoutRequest`/`LogoutResponse` messages passed to each SP, usually by browser redirects in a chain. One misbehaving SP breaks the chain and the user sees errors, so teams often turn it off.

---

### Quick recap

- SSO has **three layers**: IdP session, app sessions, tokens. Logout must reach all three
- The IdP **remembers each app** in the session and puts a public **`sid`** into ID tokens
- **RP-initiated:** app ends its session (POST), redirects to `end_session_endpoint` with `id_token_hint` and a **registered** `post_logout_redirect_uri`
- **Back-channel:** IdP POSTs a signed **`logout_token`** to each app, in parallel, with a timeout
- App checks **signature, `typ`, `events`, no `nonce`, `iss`, `aud`, time, `jti`**, then deletes sessions by `sid`, answers 200
- Front-channel iframes and SAML redirect chains are fragile; SLO is **best-effort**, so keep app sessions and tokens short
- Next: SCIM provisioning (topic 62), which ends access at the **account** level when someone leaves

## Code

One **Express** process plays four "sites": a small OIDC **IdP** at `/idp` and three apps that sign in with it: **📧 ChaiMail** (`/mail`), **📁 ChaiDrive** (`/drive`) and **💬 ChaiChat** (`/chat`, an old app with **no** back-channel logout). Each has its own cookie (`idp_sid`, `mail_sid`, …) scoped with `Path=`, so they behave like separate sites.

| Route | What it does |
|---|---|
| `GET /idp/.well-known/openid-configuration` | Discovery: `end_session_endpoint`, `backchannel_logout_supported` |
| `POST /idp/login` | Sign in at the IdP (JSON, instead of a login page) |
| `GET /idp/authorize`, `POST /idp/token` | Minimal code flow. The ID token carries `sid` |
| `GET /idp/me` | Your IdP session and the apps it was used for |
| `GET /<app>/login` → `/callback` | SSO into that app |
| `GET /<app>/me` | Are you signed in to that app? |
| `POST /<app>/logout-local` | ❌ Ends only that app's session |
| `POST /<app>/logout` | ✅ RP-initiated logout: ends the app's session, redirects to the IdP |
| `GET /idp/logout` | ✅ `end_session_endpoint`: checks the hint and redirect URL, ends the IdP session, notifies the apps |
| `POST /idp/logout` | ✅ IdP-initiated "Sign out everywhere" |
| `POST /mail/backchannel-logout`, `POST /drive/backchannel-logout` | ✅ Where the IdP's server delivers logout tokens |

Logout tokens and ID tokens are real **RS256 JWTs**, signed and verified with Node's `crypto` (no JWT library). Everything is in memory, so a restart resets it.

📄 **Full code: [server.js](server.js)**. Open it and read the comments, which follow the same steps as the notes above.

Install Express once (from this folder), then start the server:

```bash
npm install
```

```bash
node server.js
```

> Port 3000 busy? Run it on another port: `PORT=4861 node server.js` (Git Bash). The outputs below were recorded on port 4861. Your `sid` values and tokens will be different.

### Try it (Git Bash)

```bash
APP=http://localhost:4861
J="Content-Type: application/json"
```

`-c rahul.jar -b rahul.jar` is "Rahul's browser": it saves and sends all four sites' cookies. `-L` follows redirects (app → IdP → app).

#### Setup: one login, three apps

**① What the IdP says it supports:**

```bash
curl -s $APP/idp/.well-known/openid-configuration
```
→
```json
{"issuer":"http://localhost:4861/idp","authorization_endpoint":"http://localhost:4861/idp/authorize","token_endpoint":"http://localhost:4861/idp/token","end_session_endpoint":"http://localhost:4861/idp/logout","backchannel_logout_supported":true,"backchannel_logout_session_supported":true,"frontchannel_logout_supported":false}
```

**② Rahul signs in at the IdP once, then into all three apps without a password.** Every app gets the same `sid`:

```bash
curl -s -c rahul.jar -b rahul.jar $APP/idp/login -H "$J" -d '{"email":"rahul@mail.com","password":"chai-and-code-42"}'
for a in mail drive chat; do curl -s -L -c rahul.jar -b rahul.jar $APP/$a/login; echo; done
curl -s -b rahul.jar $APP/idp/me
```
→
```
{"message":"Signed in to the IdP as rahul@mail.com","sid":"ebd36806-b692-445b-b633-cd70097a26ce"}
{"message":"Signed in to 📧 ChaiMail as rahul@mail.com","sid":"ebd36806-b692-445b-b633-cd70097a26ce"}
{"message":"Signed in to 📁 ChaiDrive as rahul@mail.com","sid":"ebd36806-b692-445b-b633-cd70097a26ce"}
{"message":"Signed in to 💬 ChaiChat as rahul@mail.com","sid":"ebd36806-b692-445b-b633-cd70097a26ce"}
{"email":"rahul@mail.com","sid":"ebd36806-b692-445b-b633-cd70097a26ce","appsSignedIn":["mail","drive","chat"]}
```

#### Part A: local logout only ❌

**③ Rahul signs out of Mail, locally:**

```bash
curl -s -c rahul.jar -b rahul.jar -X POST $APP/mail/logout-local
curl -s -b rahul.jar $APP/mail/me
```
→
```
{"message":"Signed out of 📧 ChaiMail (only here)"}
{"error":"Not signed in to 📧 ChaiMail"}
```

**④ …but it doesn't stick.** "Sign in" again works **without a password** (the IdP session is alive), and Drive never heard anything:

```bash
curl -s -L -c rahul.jar -b rahul.jar $APP/mail/login
curl -s -b rahul.jar $APP/drive/me
```
→
```
{"message":"Signed in to 📧 ChaiMail as rahul@mail.com","sid":"ebd36806-b692-445b-b633-cd70097a26ce"}
{"app":"📁 ChaiDrive","email":"rahul@mail.com","sid":"ebd36806-b692-445b-b633-cd70097a26ce"}
```

#### Part B: single logout ✅

**⑤ The IdP's logout endpoint refuses two tricks.** An unregistered redirect (open redirect), and a bare `GET /idp/logout` with no `id_token_hint` (could be an `<img>` on another site), which only **asks**:

```bash
curl -s -b rahul.jar "$APP/idp/logout?client_id=mail&post_logout_redirect_uri=https://evil.example/phish"
curl -s -b rahul.jar $APP/idp/logout
```
→
```
{"error":"post_logout_redirect_uri is not registered for this app"}
{"message":"Sign out of all apps as rahul@mail.com?","confirm":"POST /idp/logout"}
```

**⑥ Rahul clicks "Sign out" in Mail.** Mail deletes its session and redirects to the IdP with the `id_token_hint`. We follow the hops one at a time to see them:

```bash
curl -s -i -c rahul.jar -b rahul.jar -X POST $APP/mail/logout | tr -d '\r' | tee hop1.txt | grep -iE '^(HTTP|set-cookie|location)'
LOC=$(grep -i '^location' hop1.txt | cut -d' ' -f2)
```
→ (token shortened)
```
HTTP/1.1 302 Found
Set-Cookie: mail_sid=; Path=/mail; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; SameSite=Lax
Location: http://localhost:4861/idp/logout?id_token_hint=eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3Mi…&client_id=mail&post_logout_redirect_uri=http%3A%2F%2Flocalhost%3A4861%2Fmail%2Flogged-out
```

**⑦ The browser lands on the IdP.** It ends its session, calls the apps' back-channel endpoints, and only then sends the browser back to Mail:

```bash
curl -s -i -c rahul.jar -b rahul.jar "$LOC" | tr -d '\r' | grep -iE '^(HTTP|set-cookie|location)'
curl -s $APP/mail/logged-out
```
→
```
HTTP/1.1 302 Found
Set-Cookie: idp_sid=; Path=/idp; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; SameSite=Lax
Location: http://localhost:4861/mail/logged-out
{"message":"You're signed out of 📧 ChaiMail"}
```
Server terminal (the server-to-server part you can't see in curl):
```
⚠️  💬 ChaiChat has no backchannel_logout_uri: its own session stays alive until it expires
🔒 📧 ChaiMail: logout_token OK for sid ebd36806-b692-445b-b633-cd70097a26ce, ended 0 session(s)
📡 back-channel logout → 📧 ChaiMail: 200
🔒 📁 ChaiDrive: logout_token OK for sid ebd36806-b692-445b-b633-cd70097a26ce, ended 1 session(s)
📡 back-channel logout → 📁 ChaiDrive: 200
```
Mail ended 0 sessions: it had already deleted its own in step ⑥. That's fine, it still answers 200.

**⑧ Now check every layer.** Drive is out, the IdP is out, and "Sign in" to Mail needs a password again. ChaiChat (no SLO support) is **still signed in**: that's the gap short sessions must cover:

```bash
curl -s -b rahul.jar $APP/drive/me
curl -s -b rahul.jar $APP/chat/me
curl -s -b rahul.jar $APP/idp/me
curl -s -L -c rahul.jar -b rahul.jar $APP/mail/login
```
→
```
{"error":"Not signed in to 📁 ChaiDrive"}
{"app":"💬 ChaiChat","email":"rahul@mail.com","sid":"ebd36806-b692-445b-b633-cd70097a26ce"}
{"error":"Not signed in to the IdP"}
{"error":"login_required","hint":"POST /idp/login first"}
```

#### Part C: attacking the back-channel endpoint 😈

The back-channel URL is just a public POST endpoint. Vikram tries to log people out with tokens he made himself.

**⑨ A forged token with `alg: none`** (no signature):

```bash
H=$(printf '{"alg":"none","typ":"logout+jwt"}' | base64 | tr '+/' '-_' | tr -d '=\n')
P=$(printf '{"iss":"%s/idp","aud":"drive","sub":"user-1001","iat":%s,"exp":%s,"jti":"fake-1","events":{"http://schemas.openid.net/event/backchannel-logout":{}}}' $APP $(date +%s) $(( $(date +%s) + 120 )) | base64 | tr '+/' '-_' | tr -d '=\n')
curl -s $APP/drive/backchannel-logout -d "logout_token=$H.$P."
```
→ `{"error":"invalid_request","error_description":"bad signature or alg (only RS256 signed by our IdP)"}`

**⑩ A real ID token, signed by the real IdP,** copied from the logout URL in step ⑥ (URLs end up in logs, tricky part 2):

```bash
HINT=$(echo "$LOC" | sed 's/.*id_token_hint=\([^&]*\).*/\1/')
curl -s $APP/mail/backchannel-logout -d "logout_token=$HINT"
```
→ `{"error":"invalid_request","error_description":"not a logout token (typ / events claim)"}`

The signature is valid, but it's an ID token: no `events` claim, `typ` is `JWT`. Server terminal:
```
🛑 📁 ChaiDrive rejected a logout_token: bad signature or alg (only RS256 signed by our IdP)
🛑 📧 ChaiMail rejected a logout_token: not a logout token (typ / events claim)
```

#### Part D: "Sign out everywhere" from the IdP ✅

**⑪ IdP-initiated logout.** Rahul signs in again, opens Mail and Drive, then uses the IdP's own button. The response lists every app it told:

```bash
curl -s -c rahul.jar -b rahul.jar $APP/idp/login -H "$J" -d '{"email":"rahul@mail.com","password":"chai-and-code-42"}'
for a in mail drive; do curl -s -L -c rahul.jar -b rahul.jar $APP/$a/login; echo; done
curl -s -c rahul.jar -b rahul.jar -X POST $APP/idp/logout
curl -s -b rahul.jar $APP/mail/me
curl -s -b rahul.jar $APP/drive/me
```
→
```
{"message":"Signed in to the IdP as rahul@mail.com","sid":"b835f774-e59a-4f18-9f94-cf35f871b3cb"}
{"message":"Signed in to 📧 ChaiMail as rahul@mail.com","sid":"b835f774-e59a-4f18-9f94-cf35f871b3cb"}
{"message":"Signed in to 📁 ChaiDrive as rahul@mail.com","sid":"b835f774-e59a-4f18-9f94-cf35f871b3cb"}
{"message":"Signed out of the IdP and every app","apps":[{"app":"mail","result":200},{"app":"drive","result":200}]}
{"error":"Not signed in to 📧 ChaiMail"}
{"error":"Not signed in to 📁 ChaiDrive"}
```

Notice that the old ChaiChat session from Part B was not in this new IdP session, and it's still alive. It ends on its own 8 hours after login (`APP_SESSION_MS` in `server.js`).

> **Windows PowerShell users:** the single quotes in `-d '...'`, `$(…)`, `base64` and `VAR=value node ...` work in Git Bash. In PowerShell, use Git Bash or Postman, or set the port with `$env:PORT=4861; node server.js`. Restart the server to reset everything (it also makes a new signing key, so old tokens stop verifying).
