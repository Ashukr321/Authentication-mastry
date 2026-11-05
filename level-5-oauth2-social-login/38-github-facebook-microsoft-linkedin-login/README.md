# 38. GitHub / Facebook / Microsoft / LinkedIn Login

## Notes

### What's different about each provider?

"Log in with X" always follows the same shape (topics 33–36): redirect to X, the user logs in and agrees, a `code` comes back, your server swaps it for tokens, and you find the user. But every provider fills in the details differently. **GitHub and Facebook speak plain OAuth 2.0** (no ID token: you call their API to ask who the user is). **Microsoft and LinkedIn speak OpenID Connect** (you verify an ID token). Each has its own **permanent user id**, its own **email rules**, its own **error format**, and its own traps.

> **One-line answer:** keep **one** login flow (state, nonce for OIDC, PKCE where supported, exact redirect URIs, one callback per provider) and write a small **adapter** per provider that turns its answer into the same shape: `{ provider, providerUserId, name, email, emailVerified }`. Store accounts by **(provider, providerUserId)**: GitHub's numeric `id`, Facebook's app-scoped `id`, Microsoft's `tid` + `oid`, LinkedIn's `sub`. **Never** by username or email, and only trust an email the provider says is **verified**.

---

### Why does it matter?

| Provider | Trap | What goes wrong if you miss it |
|---|---|---|
| **GitHub** | Usernames can be **renamed**, and the old name can be taken by someone else | Keyed by `login`, a stranger who grabs `rahul-dev` gets Rahul's account |
| **GitHub** | `/user` returns `email: null` for private emails; `/user/emails` lists **unverified** ones too | Attacker adds the victim's email to their GitHub (unverified) and your app merges them |
| **GitHub** | Token errors come back as **HTTP 200** with `{"error": ...}` | Code that only checks `res.ok` treats an error as success |
| **Facebook** | User ids are **app-scoped** (different per app), and some users have **no email** | Matching ids across your apps fails; code that requires an email crashes |
| **Microsoft** | Work accounts live in **tenants**; the `common` endpoint issues tokens from **many issuers** | Fixed-issuer checks break, or no issuer check at all |
| **Microsoft** | The `email` / `preferred_username` claims can be set by a tenant admin to **any** address ("**nOAuth**") | Attacker creates a tenant, sets their email to the victim's, logs in to an app that matches by email = **account takeover** |
| **LinkedIn** | The old "Sign In with LinkedIn" (v1 profile API) is **retired**; the current product is **OpenID Connect** | Old tutorials don't work |
| **All** | Each needs its own app registration, secret, redirect URI and review rules | Login works in dev, fails in production |

---

### Real-life example: ID at a Mumbai co-working space 🏢

Rahul's co-working space accepts four kinds of ID at the front desk:

- **Company ID card** (Microsoft work account): it's issued by **his company**, so the desk records **company + employee number**, not the name printed on it. Anyone can start a company and print any name on a card. → `tid` + `oid`, never `email`
- **Gym membership card** (GitHub): it has a **member number** and a **nickname**. Members can change nicknames, and old nicknames get reused. → numeric `id`, never `login`
- **Society visitor pass** (Facebook): the number is **different at every building** he visits, and some passes have no phone number on them. → app-scoped `id`, email may be missing
- **Passport** (LinkedIn OIDC): a standard, signed document. → verify the ID token, use `sub`
- For all of them: the desk writes down **"which ID + its number"**. Two cards with the **same name** are **not** merged into one person without checking (topic 40).

---

### The four providers at a glance

| | GitHub | Facebook | Microsoft (Entra ID / personal) | LinkedIn |
|---|---|---|---|---|
| Protocol | OAuth 2.0 | OAuth 2.0 (OIDC only via "Limited Login" on iOS) | **OpenID Connect** | **OpenID Connect** |
| Who is the user? | `GET /user` (+ `/user/emails`) | `GET /me?fields=id,name,email` | **ID token** (verify with JWKS) | **ID token** (or `/v2/userinfo`) |
| Permanent id | `id` (number) | `id` (**per app**) | `tid` + `oid` (or `sub`, per app) | `sub` |
| Changeable | `login` (username) | name | `email`, `preferred_username`, `upn` | name, email |
| Email | via `/user/emails`, check `verified` | may be missing; no "verified" flag | **not verified**: never trust for identity | `email` + `email_verified` |
| Scopes | `read:user user:email` | `public_profile email` | `openid profile email` (+ Graph scopes) | `openid profile email` |
| Quirks | Errors as HTTP 200; send `Accept: application/json` | Own error shape; token exchange can be a GET; app review + data deletion URL | `common` / `organizations` / `consumers` / tenant id endpoints; issuer contains the tenant | Needs the "Sign In with LinkedIn using OpenID Connect" product on your app |

Provider APIs change: check each one's current docs when you build it.

---

### The flow, step by step

#### 📊 Diagrams

Open **[diagrams.html](diagrams.html)** in your browser (just double-click the file) to see:

- **Flow diagram**: one login flow, four adapters, one account model
- **Data flow**: the nOAuth attack on an app that trusts Microsoft emails, and how keying by `tid` + `oid` stops it
- **Adapters**: what each adapter calls and which field becomes the account key

In short: `/login/:provider → state (+ nonce, + PKCE) → provider → /callback/:provider → state matches AND was started for this provider → adapter: exchange code, get identity → account by (provider, providerUserId) → new session`.

---

### Step 1: Register your app with each provider

| Provider | Where | You get |
|---|---|---|
| GitHub | Settings → Developer settings → **OAuth Apps** (or a GitHub App) | Client ID, client secret, **one** callback URL |
| Facebook | developers.facebook.com → create app → **Facebook Login** | App ID, app secret; valid OAuth redirect URIs; privacy policy + **data deletion** URL; **app review** for extra permissions |
| Microsoft | Entra admin center → **App registrations** | Application (client) ID, client secret or certificate; redirect URIs; **supported account types** (one tenant, any org, + personal accounts) |
| LinkedIn | linkedin.com/developers → app → add **"Sign In with LinkedIn using OpenID Connect"** | Client ID, client secret, authorized redirect URLs |

Put secrets in environment variables / a secret store, never in Git (Level 7).

---

### Step 2: One flow for all of them

```js
app.get("/login/:provider", (req, res) => {
  const state = randomToken(16), nonce = randomToken(16), verifier = randomToken(32);
  session.pending.set(state, { provider: req.params.provider, nonce, verifier, expiresAt: ... });
  // + nonce if the provider is OIDC, + code_challenge if it supports PKCE
  res.redirect(`${provider.authorizeUrl}?${params}`);
});
```

- **One callback URL per provider** (`/callback/github`, `/callback/microsoft`, …).
- The pending login remembers **which provider** it was for. A callback for a different provider is refused: this blocks **mix-up attacks**, where a malicious provider tricks your app into sending another provider's code to it.
- Always `state`; `nonce` for OIDC providers; PKCE wherever the provider supports it (Microsoft does; check the others' current docs).

---

### Step 3: One adapter per provider

```js
github:    { async identify({ code }) { /* POST token (Accept: json!) → GET /user → GET /user/emails → primary && verified */ } },
facebook:  { async identify({ code }) { /* GET token → GET /me?fields=id,name,email → email may be missing */ } },
microsoft: { async identify({ code, pending }) { /* POST token + PKCE → verify ID token (JWKS, aud, iss with tid, nonce) */ } },
linkedin:  { async identify({ code, pending }) { /* POST token → verify ID token (JWKS, aud, iss, nonce) */ } },
```

Every adapter returns the **same shape**, so the rest of your app never says `if (provider === "github")`:

```json
{ "provider": "github", "providerUserId": "583231", "name": "Rahul Sharma", "email": "rahul@example.com", "emailVerified": true }
```

---

### Step 4: Pick the right permanent id

| Provider | ✅ Use | ❌ Don't use |
|---|---|---|
| GitHub | `String(user.id)` | `user.login` (renamable, reusable) |
| Facebook | `me.id` (app-scoped: store per app) | name, email |
| Microsoft | `tid` + `oid` (or `sub`, which is per app) | `email`, `preferred_username`, `upn`, `name` |
| LinkedIn | `sub` | name, email |

Store it in a `user_identities(provider, provider_user_id)` table with a **unique** index; one user can have several identities (topic 40).

---

### Step 5: Treat email as "maybe"

- **GitHub**: take the email that is `primary && verified` from `/user/emails`; otherwise **no email**.
- **Facebook**: may be missing; there's no "verified" flag → treat as **unverified**.
- **Microsoft**: the `email` claim is **not verified** for your purposes. Microsoft's own guidance: never use `email` or `upn` to authorize or link accounts.
- **LinkedIn**: use `email_verified`.
- An unverified email may be **shown** and used to **prefill** a form, but never to **find, merge or link** an account.

---

### Step 6: Microsoft specifics: tenants and issuers

```js
checkIssuer: (c) => c.iss === `https://login.microsoftonline.com/${c.tid}/v2.0` && (!ALLOWED_TENANTS.length || ALLOWED_TENANTS.includes(c.tid))
```

- `/common` = work, school **and** personal accounts; `/organizations` = work/school only; `/consumers` = personal only; `/{tenant-id}` = **one company only**.
- With `common`, the token's `iss` is `https://login.microsoftonline.com/{tid}/v2.0`. Check that `iss` matches **the token's own `tid`**.
- An internal tool for one company should **allow-list tenant ids** (or use the tenant-specific endpoint). Otherwise, anyone who can create a free tenant can log in.

---

### 🤔 Tricky parts

**1. The nOAuth attack (Microsoft, and any provider with unverified emails).**
Vikram creates his own Microsoft tenant, sets his user's email to `rahul@example.com`, and clicks "Log in with Microsoft" on an app that finds users **by email**. The app logs him in as Rahul. The fix is keying by `tid` + `oid` and never linking on unverified emails. The demo shows Vikram's token arriving with `email: rahul@example.com`; PrintKaro gives him his **own** account.

**2. GitHub email games.**
Vikram can add `rahul@example.com` to his GitHub account; it stays **unverified**. The demo's GitHub adapter only takes `primary && verified`, so Vikram's identity has **no email**.

**3. Facebook app-scoped ids.**
If you have two Facebook apps (say web and a separate partner app), the same person has **two different ids**. Use Facebook's Business Manager "token for business" mapping if you need to connect them.

**4. Plain OAuth providers can't give you `aud` checks.**
With GitHub and Facebook you trust the **access token you just got from the token endpoint over HTTPS**, using your client secret. Never accept a GitHub/Facebook access token **from the browser** as proof of login (token substitution, topic 36).

**5. Token lifetimes differ.**
GitHub OAuth app tokens don't expire by default; Facebook user tokens are long-lived (about 60 days, no refresh token); Microsoft gives short access tokens + refresh tokens; LinkedIn tokens last about 60 days. After login you usually **don't need** the provider's token at all: drop it and use your own session.

**6. Use a library in production.**
Passport strategies, Auth.js providers or `openid-client` (topic 41) already know these quirks. This demo shows what they do inside.

---

### Common beginner mistakes

1. **Keying accounts by email or username.**
   Use the provider's permanent id, together with the provider name.

2. **Trusting Microsoft's `email` / `preferred_username` claim.**
   nOAuth account takeover. Use `tid` + `oid`.

3. **Taking any email from GitHub's `/user/emails`.**
   Only `primary && verified`.

4. **Requiring an email from Facebook.**
   Some users don't have one. Ask for it in your own signup step, and verify it yourself (topic 12).

5. **Checking only `res.ok` for GitHub's token endpoint.**
   Errors come as 200 + `error`. Send `Accept: application/json` and check for `access_token`.

6. **A fixed issuer check for Microsoft `common`.**
   Validate `iss` against the token's `tid`, and allow-list tenants for internal apps.

7. **One callback URL for all providers, no provider in the state.**
   Mix-up attacks. One callback per provider, and check the pending login's provider.

8. **Auto-linking accounts across providers by email.**
   Topic 40.

9. **Hard-coding client secrets.**
   Environment / secret store, rotated (Level 7).

---

### Interview questions

1. **How do you support several social logins without spaghetti code?**
   One generic flow (state, nonce, PKCE, per-provider callback) plus an adapter per provider that returns a normalized identity; accounts keyed by (provider, providerUserId).

2. **Which GitHub field identifies a user?**
   The numeric `id`. The `login` can be renamed and later reused by someone else.

3. **Is "Log in with GitHub" OpenID Connect?**
   No. It's OAuth 2.0; you call `/user` (and `/user/emails`) with the access token. There's no ID token.

4. **What is the nOAuth vulnerability?**
   Apps that identify Microsoft Entra users by the mutable, unverified `email` claim can be taken over by an attacker who sets that email in their own tenant. Use `oid` + `tid` (or `sub`).

5. **What's special about Facebook user ids?**
   They're app-scoped: the same person has a different id in each app.

6. **How do you validate the issuer of a Microsoft token from the `common` endpoint?**
   Check `iss` equals `https://login.microsoftonline.com/{tid}/v2.0` using the token's own `tid`, and allow-list tenants if the app is for specific organizations.

7. **When can you trust an email from a social provider?**
   Only when the provider marks it verified (and is authoritative for it). Otherwise treat it as unverified: display only, never for matching or linking.

8. **What is an IdP mix-up attack?**
   When a client supports several providers, a malicious provider tricks it into sending another provider's code or token to the attacker. Prevented by per-provider redirect URIs and remembering which provider each login started with (plus the `iss` response parameter, RFC 9207).

9. **What do you need to register before going live?**
   Client id/secret, exact redirect URIs, scopes; Facebook needs app review, privacy policy and data deletion URLs; Microsoft needs the supported account types.

---

### Quick recap

- **Same flow, different adapters**: normalize to `{ provider, providerUserId, name, email, emailVerified }`
- **GitHub**: OAuth only, `id` not `login`, `primary && verified` email from `/user/emails`, 200-with-error
- **Facebook**: OAuth only, **app-scoped** `id`, email may be missing, own error shape
- **Microsoft**: OIDC, **`tid` + `oid`**, issuer contains the tenant, **never trust `email`** (nOAuth), allow-list tenants when needed
- **LinkedIn**: OIDC (the old API is retired), `sub`, `email_verified`
- Accounts keyed by **(provider, permanent id)**; unverified email never links accounts
- One callback per provider; the pending login remembers its provider (mix-up)
- Next: Apple Sign-In (topic 39), linking several identities to one account (topic 40)

## Code

One **Express** file, two apps:

| Port | App |
|---|---|
| `3000` | 🖨️ **PrintKaro**: four "Log in with …" buttons, one flow, four adapters |
| `3001` | 🧪 **Mock GitHub, Facebook, Microsoft and LinkedIn**: small fakes that behave like the real ones, quirks included |

Real providers need real app registrations, so the demo runs against **mocks**. Instead of a real login page, each mock shows **"Continue as rahul / vikram / priya"**. The test users:

| Provider | User | What's interesting |
|---|---|---|
| GitHub | `rahul` | id 583231, verified email |
| GitHub | `vikram` | added **Rahul's** email to his account, **unverified** |
| Facebook | `rahul` | app-scoped id, email (no "verified" flag) |
| Facebook | `priya` | signed up with a phone: **no email** |
| Microsoft | `rahul` | work account in the Contoso tenant |
| Microsoft | `vikram` | **his own** tenant, email claim set to **rahul@example.com** (nOAuth) |
| LinkedIn | `rahul` | OIDC, `email_verified: true` |

📄 **Full code: [server.js](server.js)**. Part 1 is the mocks, Part 2 is PrintKaro. Read the comments, which follow the same steps as the notes above.

Install the dependencies once (from this folder), then start the server:

```bash
npm install
```

```bash
node server.js
```

> Port 3000 busy? Run it on other ports: `PORT=3038 node server.js` (Git Bash) uses **3038** and **3039**. The outputs below were recorded that way, so they show those ports.

### Try it in the browser

Open **http://localhost:3000** → click **LinkedIn** → the mock page offers **Continue as rahul** → click it → `/me` shows:

```json
{"id":"acct_WA3rpA","createdAt":"2026-11-05T05:54:58.034Z","provider":"linkedin","providerUserId":"yW3Lk9ZqP0","name":"Rahul Sharma","email":"rahul@example.com","emailVerified":true}
```

Try the other buttons and users the same way.

### Try it with curl (Git Bash)

```bash
APP=http://localhost:3000; MOCK=http://localhost:3001
red() { curl -s -o /dev/null -w "%{redirect_url}" "$@"; }
login() {   # login <cookie-jar> <provider> <mock user>
  L=$(red -c $1.jar -b $1.jar "$APP/login/$2"); CB=$(red "$L&mock_user=$3")
  curl -s -c $1.jar -b $1.jar -o /dev/null "$CB"; curl -s -b $1.jar $APP/me; echo
}
```

✅ **Every provider, every test user:**

```bash
login gh_r github rahul;     login gh_v github vikram
login fb_r facebook rahul;   login fb_p facebook priya
login ms_r microsoft rahul;  login ms_v microsoft vikram
login li_r linkedin rahul
```
→
```
{"id":"acct_n6tuKg",...,"provider":"github","providerUserId":"583231","name":"Rahul Sharma","email":"rahul@example.com","emailVerified":true}
{"id":"acct_4CqsDw",...,"provider":"github","providerUserId":"990017","name":"Vikram","email":null,"emailVerified":false}       ← his unverified copy of Rahul's email is ignored
{"id":"acct_1hJbOA",...,"provider":"facebook","providerUserId":"10229384756","name":"Rahul Sharma","email":"rahul@example.com","emailVerified":false}
{"id":"acct_frurAA",...,"provider":"facebook","providerUserId":"10229380001","name":"Priya Nair","email":null,"emailVerified":false}   ← no email at all, still works
{"id":"acct_yp5CLg",...,"provider":"microsoft","providerUserId":"72f988bf-86f1-41af-91ab-2d7cd011db47:0f1e2d3c-aaaa-4bbb-8ccc-000000000001","name":"Rahul Sharma","email":"rahul@contoso.example","emailVerified":false}
{"id":"acct_TLFzwg",...,"provider":"microsoft","providerUserId":"f00dcafe-1111-4222-8333-444455556666:0f1e2d3c-aaaa-4bbb-8ccc-000000000666","name":"Vikram","email":"rahul@example.com","emailVerified":false}   ← nOAuth: Rahul's email, but Vikram's OWN account
{"id":"acct_Zjn3VQ",...,"provider":"linkedin","providerUserId":"yW3Lk9ZqP0","name":"Rahul Sharma","email":"rahul@example.com","emailVerified":true}
```

Logging in with GitHub as `rahul` again gives the **same** `acct_n6tuKg`. Notice: `rahul@example.com` appears in **four** identities (one of them is Vikram's), and they are **four separate accounts**. Merging them safely is topic 40.

The terminal explains each one:

```
🆕 GitHub: Rahul Sharma → acct_n6tuKg (id 583231), email rahul@example.com ✅ verified
🆕 GitHub: Vikram → acct_4CqsDw (id 990017), no email
🆕 Facebook: Rahul Sharma → acct_1hJbOA (id 10229384756), email rahul@example.com ⚠️ NOT verified: never use it to match accounts
🆕 Facebook: Priya Nair → acct_frurAA (id 10229380001), no email
🆕 Microsoft: Rahul Sharma → acct_yp5CLg (id 72f988bf-...:0f1e2d3c-...0001), email rahul@contoso.example ⚠️ NOT verified: never use it to match accounts
🆕 Microsoft: Vikram → acct_TLFzwg (id f00dcafe-...:0f1e2d3c-...0666), email rahul@example.com ⚠️ NOT verified: never use it to match accounts
🆕 LinkedIn: Rahul Sharma → acct_Zjn3VQ (id yW3Lk9ZqP0), email rahul@example.com ✅ verified
👋 GitHub: Rahul Sharma → acct_n6tuKg (id 583231), email rahul@example.com ✅ verified
```

🔒 **Only Rahul's company may use Microsoft login:** restart with a tenant allow-list:

```bash
ALLOWED_MS_TENANTS=72f988bf-86f1-41af-91ab-2d7cd011db47 node server.js
```
Then `login ms_r microsoft rahul` works, and Vikram's tenant is refused:
```
{"error":"Microsoft login failed"} 400
```
Terminal: `🚨 Microsoft login failed: unexpected issuer http://localhost:3039/microsoft/f00dcafe-1111-4222-8333-444455556666/v2.0`

🔀 **Mix-up protection:** a GitHub login's `state` used on the Facebook callback:

```bash
L=$(red -c m.jar -b m.jar "$APP/login/github"); ST=$(echo "$L" | sed 's/.*state=\([^&]*\).*/\1/')
curl -s -b m.jar "$APP/callback/facebook?code=x&state=$ST"
```
→ `400 {"error":"This login didn't start here (state mismatch)"}`

🧪 **The quirks, straight from the mocks:**

```bash
curl -s $MOCK/github/login/oauth/access_token -d client_id=gh-printkaro -d client_secret=gh-demo-secret -d code=bogus -d redirect_uri=$APP/callback/github -w " %{http_code}\n"
curl -s "$MOCK/facebook/graph/oauth/access_token?client_id=1234567890&client_secret=fb-demo-secret&code=bogus&redirect_uri=$APP/callback/facebook" -w " %{http_code}\n"
```
→
```
{"error":"bad_verification_code","error_description":"bad or expired code"} 200       ← GitHub: an error with status 200
{"error":{"message":"bad or expired code","type":"OAuthException","code":100}} 400    ← Facebook's own error shape
```

And a **successful** GitHub exchange **without** `Accept: application/json` comes back form-encoded:
```
access_token=tbastvvvjXVtlHQY0zlS4kPA3sCGjL64Z_7UM9DonjQ&token_type=bearer&scope=read%3Auser%2Cuser%3Aemail
```

### Going live

Replace the mock URLs in `PROVIDERS` with the real ones, register the app at each provider (Step 1), and load the client ids and secrets from environment variables:

| Provider | Authorize | Token | Who is the user |
|---|---|---|---|
| GitHub | `https://github.com/login/oauth/authorize` | `https://github.com/login/oauth/access_token` | `https://api.github.com/user`, `https://api.github.com/user/emails` |
| Facebook | `https://www.facebook.com/v{version}/dialog/oauth` | `https://graph.facebook.com/v{version}/oauth/access_token` | `https://graph.facebook.com/v{version}/me?fields=id,name,email` |
| Microsoft | `https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize` | `https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token` | ID token; keys at `https://login.microsoftonline.com/{tenant}/discovery/v2.0/keys` |
| LinkedIn | `https://www.linkedin.com/oauth/v2/authorization` | `https://www.linkedin.com/oauth/v2/accessToken` | ID token; keys at `https://www.linkedin.com/oauth/openid/jwks`, issuer `https://www.linkedin.com/oauth` |

`{tenant}` is `common`, `organizations`, `consumers` or your tenant id. Prefer each provider's **discovery document** for OIDC providers (topic 36). This demo is only tested against the mocks, so check each provider's current docs for details like API versions, PKCE support and scopes.

> **Windows PowerShell users:** the variables, `red()` / `login()` functions, cookie jars and `PORT=... node ...` work in Git Bash. In PowerShell, use the browser, Git Bash, or `$env:PORT=3038; node server.js`.
