# 60. OIDC SSO: Okta / Entra ID / Auth0 / Keycloak

## Notes

### What is OIDC SSO with an enterprise IdP?

In topics 37–38, **your users** picked "Log in with Google". In B2B software it's the other way round: a **customer company** says "our 5,000 employees must log in with **our** Okta (or Microsoft Entra ID, Auth0, Keycloak…), and when we disable someone there, they must lose access to your app too."

So your app (the **relying party**, the "SP" from topic 57) keeps one **SSO connection per customer**: that customer's **issuer URL**, a **client id + secret** they created for you, and which **group** means "admin". When someone types `rahul@acme.example`, you look up Acme's connection and run a normal OpenID Connect login (topic 36) against **Acme's** IdP.

> **One-line answer:** Enterprise OIDC SSO = the same OIDC code flow (state + nonce + PKCE, ID token checks) run against **a different IdP per customer org**. You store a **connection** per org (issuer, client id/secret, claim mapping), pick it by **email domain** (home realm discovery), read endpoints and keys from the issuer's **discovery** document, validate the ID token against **that connection's** `iss` and `aud`, then apply the trust rule: **an org's IdP may only log in users of the domains that org has proved it owns**. Identify users by **(org, `sub`)** (Entra: `oid`), create them on first login (**JIT**), sync roles from groups on every login, and **enforce SSO** so passwords stop working.

---

### Why it matters

| Problem without proper SSO | What goes wrong |
|---|---|
| Employees have separate passwords for your app | The customer's IT can't enforce MFA, password rules or "log in only from company laptops" |
| Someone leaves the company | They're disabled in Okta, but their **old password** for your app still works |
| Every customer's IdP is a little different | Code written for Okta breaks on Entra ID (issuer with tenant id), Auth0 (trailing slash), Keycloak (roles in a nested claim) |
| You trust whatever email the IdP says | Any customer can connect **their own** IdP and assert `ceo@your-other-customer.com` |
| One callback URL, many IdPs | A code or token from IdP A gets accepted as if it came from IdP B (mix-up) |

"SSO with Okta / Entra ID" is often the **first thing** an enterprise buyer asks for. Many SaaS companies charge for it in the "Enterprise" plan.

---

### Real-life example: the co-working space 🏢

**KaamKaro** is a big co-working building in Bengaluru. Many companies rent floors: Acme, Contoso, Globex, Initech.

- The building doesn't print its own ID cards. Each company **issues its own** (that's the company's **IdP**).
- At the gate, Rahul says "I'm from Acme". The guard checks the **register** (the **connection**): "Acme's cards are verified by calling Acme's HR desk at this number". The guard calls **that** number, not a number printed on the card (**discovery from the configured issuer**).
- Acme's HR can vouch for **Acme employees only**. If Shady Ltd's HR calls and says "Rahul from Acme is with us, let him in", the guard refuses: Shady can only vouch for Shady people (**verified domains**).
- When Acme fires someone, Acme stops their card. Because the building **only** accepts company cards (no separate building passes, **enforce SSO**), that person can't get in any more.
- The first time a new Acme employee shows a valid card, the building creates their visitor profile on the spot (**JIT provisioning**), and puts them on the "floor manager" list if Acme's card says so (**group → role**).

---

### The big picture

#### 📊 Diagrams

Open **[diagrams.html](diagrams.html)** in your browser (just double-click the file) to see:

- **Flow diagram**: every decision from "type your email" to "logged in", with each attack stopped
- **Data flow**: Rahul's whole Okta login with real URLs and claims, and Vikram's Shady Ltd attack
- **The four IdPs side by side**: where the issuer, user id and groups live in each

In short: `email → domain → org → connection → discovery (issuer must match) → /authorize (state + nonce + PKCE + login_hint) → IdP login → code → /token (client_secret_basic + verifier) → verify ID token against THIS connection (RS256, kid, iss, aud, exp, nonce) → map claims → email domain ∈ org's verified domains? → find by (org, sub) or link or JIT-create → role from groups → new session`.

#### The vocabulary

| Word | Meaning |
|---|---|
| **IdP** (OpenID Provider) | The customer's login system: Okta, Microsoft Entra ID (formerly Azure AD), Auth0, Keycloak, Google Workspace, PingOne, OneLogin… |
| **RP / SP** | Your app. It relies on the IdP's answer |
| **Org / tenant** | One customer company inside your app |
| **Connection** | One org's IdP settings stored in your app: issuer, client id, client secret, claim mapping |
| **Home realm discovery (HRD)** | Finding the right IdP for a user, usually from the email domain (`@acme.example` → Acme's Okta) |
| **Verified domain** | A domain the org proved it owns (DNS TXT record). Its IdP may log in users of that domain only |
| **JIT provisioning** | Creating the user's account on their **first** SSO login, from the ID token's claims |
| **Enforce SSO** | Password login is switched off for the org's domains |
| **SP-initiated** | The login starts at your app (our demo). **IdP-initiated** = the user clicks your tile in the Okta dashboard |

#### The four big IdPs, side by side

All four speak standard OpenID Connect. The **differences** are what break code:

| | Okta | Microsoft Entra ID | Auth0 | Keycloak |
|---|---|---|---|---|
| **Issuer** | `https://acme.okta.com/oauth2/default` (custom auth server) or `https://acme.okta.com` (org auth server) | `https://login.microsoftonline.com/{tenant-id}/v2.0` | `https://globex.auth0.com/` (**trailing slash!**) | `https://sso.initech.com/realms/initech` (old versions: `/auth/realms/…`) |
| **Endpoints** | `…/v1/authorize`, `…/v1/token`, `…/v1/keys` | `/{tenant}/oauth2/v2.0/authorize`, `/token`, `/{tenant}/discovery/v2.0/keys` (**not** under the issuer path) | `/authorize`, `/oauth/token`, `/.well-known/jwks.json` | `…/protocol/openid-connect/auth`, `/token`, `/certs` |
| **Stable user id** | `sub` | `oid` (+ `tid`). `sub` is different per app | `sub` like `auth0\|65a1…` or `samlp\|acme\|rahul` | `sub` (a UUID) |
| **Email** | `email`, `email_verified` | Often **no** `email` claim (optional claim), never `email_verified`. `preferred_username` is the UPN | `email`, `email_verified` | `email`, `email_verified` (an admin checkbox) |
| **Groups / roles** | `groups` (admin must add a groups claim + filter) | `roles` (app roles) or `groups` as **GUIDs**; over 200 groups → "overage", call Graph | Custom claim, **must be namespaced**: `https://kaamkaro.example/roles` (set in an Action) | `realm_access.roles` / `resource_access.<client>.roles` (turn on "Add to ID token" on the mapper) |

Rule of thumb: **one OIDC code path**, plus a tiny **claim profile** per IdP type that says where `subject`, `email` and `groups` are.

---

### Step 1: Store one SSO connection per org

```js
acme: { name: "Acme Corp", domains: ["acme.example"], enforceSso: true,
        sso: { profile: "okta", issuer: "https://acme.okta.com/oauth2/default",
               clientId: "0oa4kaamkaro8x7", clientSecret: "…", adminGroup: "KaamKaro-Admins" } },
```

The customer's IT admin creates an "OIDC Web App" in **their** IdP, enters your redirect URI (`https://app.kaamkaro.example/sso/callback`), and pastes the issuer, client id and secret into your settings page.

| ✅ Do | ❌ Don't |
|---|---|
| Store only the **issuer**; discover the rest | Ask admins to paste five endpoint URLs (they will mix them up) |
| Encrypt the client secret, or keep it in a vault (topic 54) | Store secrets in plain text next to the org row |
| One redirect URI for all orgs, the state says which connection | Build the redirect URI from the `Host` header |
| Test the connection when the admin saves it (run discovery) | Find out it's broken when 5,000 employees try on Monday |

---

### Step 2: Discovery, and the issuer must match EXACTLY

```js
const doc = await (await fetch(`${issuer.replace(/\/$/, "")}/.well-known/openid-configuration`)).json();
if (doc.issuer !== issuer) throw new Error(`issuer mismatch`);   // OIDC Discovery 1.0, section 4.3
```

The discovery document gives you `authorization_endpoint`, `token_endpoint`, `jwks_uri`. Its `issuer` must be **character for character** what you configured, and later every ID token's `iss` must be that too.

The famous trap is **Auth0's trailing slash**: the issuer is `https://globex.auth0.com/`. In our demo, Umbrella's admin pasted it without the `/`, and KaamKaro refuses at the very first step instead of failing on every login later:

```
🚨 Umbrella: SSO misconfigured: issuer mismatch: configured "http://localhost:3061/auth0", IdP says "http://localhost:3061/auth0/"
```

---

### Step 3: Home realm discovery: email domain → org → IdP

```js
const orgId = orgIdForEmail(email);                 // "rahul@acme.example" → "acme"
if (!orgId) return res.json({ next: "password" });  // no SSO for this domain
s.pending.set(state, { orgId, nonce, verifier, expiresAt });
res.redirect(303, `${doc.authorization_endpoint}?${params}`);   // + login_hint=rahul@acme.example
```

- The **pending login remembers the org**. The callback will use **only** this to pick the connection.
- `login_hint` pre-fills the email on the IdP's page, so the user types it once.
- Other HRD options: a company-specific URL (`acme.kaamkaro.example`, `?org=acme`) or an "org slug" box. Useful when one person belongs to several orgs, or the email domain is shared (`gmail.com` can never be an SSO domain).

---

### Step 4: Claim profiles: same protocol, different claims

```js
const CLAIM_PROFILES = {
  okta:     (c) => ({ subject: c.sub, email: c.email, groups: c.groups }),
  entra:    (c) => ({ subject: c.oid, email: c.email ?? c.preferred_username, groups: c.roles }),
  auth0:    (c) => ({ subject: c.sub, email: c.email, groups: c["https://kaamkaro.example/roles"] }),
  keycloak: (c) => ({ subject: c.sub, email: c.email, groups: c.realm_access?.roles }),
};
```

That's the whole "per-IdP code". Everything else is the same.

---

### Step 5: Validate the ID token against THIS connection

```js
if (header.alg !== "RS256") throw ...;                        // pinned (topic 53)
// key by kid from the connection's jwks_uri; unknown kid → refetch once (key rotation)
if (c.iss !== conn.issuer) throw ...;                         // the CONFIGURED issuer, not "whatever iss says"
if (!aud.includes(conn.clientId) || (aud.length > 1 && c.azp !== conn.clientId)) throw ...;
if (!(c.exp > now - 30) || c.iat > now + 30) throw ...;
if (!c.nonce || !safeEqual(c.nonce, nonce)) throw ...;        // topic 35
```

Exactly topic 36's checks. The one new rule: the expected `iss`, `aud`, token endpoint and keys all come from the **connection the login started with** (from `state`). Never pick the connection by reading `iss` from the token: then any IdP could choose which customer it speaks for.

This also stops the **IdP mix-up**: in our demo Vikram takes a code issued by Shady's Keycloak and sends it to the callback with an Acme `state`. KaamKaro redeems it at **Acme's** Okta token endpoint, which has never heard of it: `invalid_grant`. (RFC 9207 adds an `iss` parameter to the callback for the same reason; check it when the IdP sends it.)

---

### Step 6: One callback for everyone

`GET /sso/callback?code=…&state=…`: look up `state` in **this browser's** session (one use, 10-minute expiry), get the org, exchange the code at **that org's** token endpoint with `client_secret_basic` + the PKCE verifier, then step 5.

---

### Step 7: The trust boundary: verified domains

This is the most important enterprise rule, and the one beginners miss.

```js
if (!org.domains.includes(emailDomain(email))) return 403;   // Shady's IdP can't speak for acme.example
```

A **valid** ID token only proves "**Shady's** IdP said so". Shady's admin controls every claim in it, including `email: "rahul@acme.example"` and `email_verified: true` (in Keycloak that's one checkbox). If you look users up by email across orgs, Vikram now **is** Acme's admin.

| ✅ Do | ❌ Don't |
|---|---|
| Accept an IdP's users only in the domains its org **verified** | Trust `email_verified` from a customer-controlled IdP |
| Verify domains with a **DNS TXT record** (`kaamkaro-verification=abc123`) before they count | Let an admin type "acme.example" into settings and use it immediately |
| Key SSO identities by **(org, subject)** | Key them by email, or by `sub` alone (two IdPs can issue the same `sub`) |
| Refuse public domains (`gmail.com`, `outlook.com`) as SSO domains | Let one customer "claim" gmail.com |

---

### Step 8: Find, link or create (JIT), then sync the role

```js
let user = users.get(ssoIdentities.get(`${orgId}|${subject}`));
if (!user) {
  const existing = users.get(usersByEmail.get(email));
  if (existing && existing.orgId === orgId) user = existing;         // pre-SSO account of THIS org: link
  else if (existing) return 409;                                     // someone else's account: never auto-link
  else user = addUser({ orgId, email, name });                       // JIT
}
user.role = groups.includes(conn.adminGroup) ? "admin" : "member";  // every login, not just the first
```

- **Linking** a pre-SSO password account is safe **here** because the email's domain is verified **and** the IdP is that org's own. That's different from social login (topic 40), where you need the user to prove both sides.
- **Role sync on every login**: if IT removes Rahul from `KaamKaro-Admins`, he's a member at his next login.
- **JIT's weak spot**: it only runs at login. A fired employee who **never logs in again** keeps an account (and existing sessions keep working). That's what **SCIM** fixes (topic 62): the IdP pushes "user disabled" to you. Keep sessions short for SSO users.

---

### Step 9: Enforce SSO

```js
if (orgId && ORGS[orgId].enforceSso) return res.status(403).json({ error: "Acme Corp requires single sign-on" });
```

Until you do this, every offboarded employee still has a working password. Typical rollout: turn SSO on → let both work for a week → enforce. Keep a **break-glass** path (one owner account with password + MFA, or support-assisted recovery) for the day the customer's IdP is down or misconfigured.

---

### Setting it up for real (what the customer's admin does)

| IdP | In the IdP console | What they give you |
|---|---|---|
| **Okta** | Applications → Create App Integration → **OIDC – Web Application**. Sign-in redirect URI = your callback. Assign groups. Add a **groups claim** (filter "starts with KaamKaro") | Okta domain + `/oauth2/default` (or org auth server), client id, secret |
| **Entra ID** | App registrations → New → redirect URI (Web). Certificates & secrets → new secret. **App roles** (e.g. `KaamKaro.Admin`) + assign users. Token configuration → add optional claim `email` | Tenant id → issuer `https://login.microsoftonline.com/{tid}/v2.0`, client id, secret |
| **Auth0** | Applications → Regular Web App → Allowed Callback URLs. Roles via an **Action** that sets a namespaced claim. For B2B: **Organizations** + enterprise connections | `https://{tenant}.auth0.com/`, client id, secret |
| **Keycloak** | Realm → Clients → Create (OpenID Connect, client authentication ON). Valid redirect URIs. Client scope **roles** → realm roles mapper → "Add to ID token" | `https://host/realms/{realm}`, client id, secret |

Two architectures you'll meet:

1. **Direct** (our demo): your app talks to each customer's IdP.
2. **Broker**: your app talks to **one** IdP you own (Auth0 Organizations, Keycloak identity brokering, WorkOS, Okta Customer Identity…), and **it** federates to each customer's IdP over OIDC or SAML (topic 58). Less code, but you pay per connection, and the trust rules above still apply inside the broker.

---

### 🤔 Tricky parts

**1. Entra ID: `sub` vs `oid`.** `sub` is unique **per app** (pairwise). `oid` is the user's id in the tenant and is the same in every app (and in SCIM and Microsoft Graph). Key on `tid` + `oid`. Never on `email` or `preferred_username`: Microsoft documents both as mutable, and multi-tenant apps that used them were hit by "nOAuth" (topic 38).

**2. Entra ID multi-tenant (`/common`).** One registration for every Microsoft customer means the issuer has the **tenant id inside it**, and the discovery doc literally says `{tenantid}`. Then you must check the token's `tid` is a tenant that belongs to the org. In B2B, configure each org with its **own tenant's** issuer (like our demo) and this problem disappears.

**3. Groups overage.** With more than 200 groups, Entra puts a pointer (`_claim_names`) in the token instead of the list. Use **app roles** (`roles` claim) or a groups filter so the token stays small.

**4. Group ids, not names.** Entra sends groups as GUIDs. Map `9f3c…` → "admin" in the connection settings; names can be renamed anyway.

**5. Keycloak roles missing from the ID token.** The default roles mapper adds them to the **access token**. Turn on "Add to ID token", or read them from `/userinfo`.

**6. IdP-initiated login.** The user clicks your tile in the Okta dashboard and the IdP sends them to you with **no** state you created. OIDC handles this with "third-party initiated login": the IdP calls your `initiate_login_uri` with `iss` (+ `login_hint`), and **you** start a normal SP-initiated flow with fresh state, nonce, PKCE. Never accept an unsolicited code or token.

**7. Clock skew and key rotation.** Allow about 30 seconds of skew. Cache JWKS, refetch when you see an unknown `kid` (rate-limited), never refetch on every request.

**8. Logout.** Ending your session doesn't end the Okta session, so the next "Log in" is instant. That's usually wanted. Ending **both**, and getting told when the IdP session ends, is Single Logout (topic 61).

**9. The same person in two orgs.** A consultant may be `meera@freelance.example` in Acme (guest) and Globex. Key users by (org, subject), and let HRD ask "which organization?" when it's ambiguous.

---

### Common beginner mistakes

1. **Looking users up by email across all orgs.**
   Any customer's IdP can assert any email. Scope by org and verified domains.

2. **Trusting `email_verified` from a customer IdP.**
   It means "this IdP's admin says so".

3. **Choosing the connection from the token's `iss`.**
   Choose it from the `state` you stored, then check `iss` equals it.

4. **Hard-coding one IdP's quirks into the core flow.**
   Keep one OIDC path and a small claim profile per IdP type.

5. **Comparing issuers loosely** (trimming slashes, ignoring case).
   Exact string match. Fix the configuration instead.

6. **Using `sub` alone as a global key.**
   `sub` is only unique **within one issuer**. Use (org/issuer, `sub`).

7. **Not enforcing SSO after setting it up.**
   Fired employees keep their passwords.

8. **Setting the role only at the first login.**
   Sync it on every login, and use SCIM for real deprovisioning.

9. **Accepting domains without verification**, or public domains like `gmail.com`.

10. **Skipping state, nonce or PKCE** because "it's enterprise, it's trusted".
    Every rule from topics 33–36 still applies.

---

### Interview questions

1. **How do you add "Log in with Okta / Azure AD" for enterprise customers?**
   Store an OIDC connection per customer org (issuer, client id, secret, claim mapping). Pick it by email domain (home realm discovery), run the authorization code flow with state, nonce and PKCE, validate the ID token against that connection's issuer and client id, map claims, JIT-provision, and optionally enforce SSO for the org's domains.

2. **What is home realm discovery?**
   Deciding which IdP a user should log in with, usually from the email domain, sometimes from a subdomain, a URL parameter or an org picker.

3. **Why must a customer verify its domain?**
   The domain is what links "this IdP" to "these users". Without proof (a DNS TXT record), a customer could claim another company's domain and its IdP could log in as that company's users.

4. **A customer's IdP sends `email: ceo@other-customer.com, email_verified: true`. What do you do?**
   Refuse. Each IdP may only assert identities in its own org's verified domains. `email_verified` from a customer-controlled IdP proves nothing.

5. **Which claim identifies the user?**
   `iss` + `sub` in general; in practice (org/connection, `sub`). For Entra ID use `tid` + `oid`. Never the email.

6. **What's the difference between JIT provisioning and SCIM?**
   JIT creates/updates the user when they log in; it can't deprovision someone who never logs in again. SCIM is the IdP pushing create/update/disable events to your API (topic 62).

7. **What is the Auth0 trailing slash problem?**
   Auth0's issuer is `https://tenant.auth0.com/` with a slash. Configs without it fail the exact `iss` comparison. The fix is correct configuration, not a loose comparison.

8. **How do you map IdP groups to app roles?**
   Configure per connection which group (Okta name, Entra app role or group GUID, Auth0 namespaced claim, Keycloak realm role) means which app role, and recompute the role on every login.

9. **SP-initiated vs IdP-initiated login?**
   SP-initiated starts at your app with your state/nonce. IdP-initiated starts from the IdP dashboard; with OIDC, the IdP hits your `initiate_login_uri` and you start a fresh SP-initiated flow. Unsolicited responses are a classic attack surface (very common in SAML, topic 59).

10. **What is an IdP mix-up attack and how is it prevented?**
    An attacker gets a code/token from one IdP accepted as if it came from another. Bind the login to a connection via `state`, use that connection's token endpoint and expected `iss`, and check RFC 9207's `iss` response parameter when present.

---

### Quick recap

- Enterprise SSO = **topic 36's OIDC flow**, once **per customer org**, each with its own **connection**
- **HRD**: email domain → org → connection. The pending login stores the **org**; the callback trusts only that
- **Discovery** from the configured issuer; `doc.issuer` and every token's `iss` must match **exactly** (Auth0's `/`)
- **Claim profiles** absorb the differences: Okta `groups`, Entra `oid` + `roles`, Auth0 namespaced claims, Keycloak `realm_access.roles`
- **Trust boundary**: an org's IdP may log in users of its **DNS-verified domains only**; ignore `email_verified` from it
- Users keyed by **(org, subject)**; link pre-SSO accounts of the same org; **JIT** otherwise; **re-sync roles** every login
- **Enforce SSO** + a break-glass account; **SCIM** (topic 62) for real deprovisioning; **SLO** next (topic 61)

## Code

A small B2B SaaS app, **KaamKaro**, where five customer orgs each bring their own IdP. One process starts two servers:

| Port | Server | What it is |
|---|---|---|
| `3000` | 🗂️ **KaamKaro** | The relying party: HRD, discovery, one callback, ID token checks, verified-domain rule, JIT, role sync, enforce SSO, password login |
| `3001` | 🧪 **Mock IdPs** | Okta (Acme), Entra ID (Contoso), Auth0 (Globex), Keycloak realm `initech`, Keycloak realm `shady`: each with its real issuer shape, discovery, JWKS (RS256, a fresh key on every start) and claim quirks |

| Org | Domain | IdP | Enforce SSO | Test users |
|---|---|---|---|---|
| Acme Corp | `acme.example` | Okta | ✅ | `rahul` (in `KaamKaro-Admins`), `amit` |
| Contoso | `contoso.example` | Entra ID | ✅ | `priya` (app role `KaamKaro.Admin`) |
| Globex | `globex.example` | Auth0 | ✅ | `sneha` |
| Initech | `initech.example` | Keycloak | ❌ | `arjun` (realm role `kaamkaro-admin`) |
| Shady Ltd | `shady.example` | Keycloak (attacker-run) | ❌ | `vikram`, whose token says `rahul@acme.example` |
| Umbrella | `umbrella.example` | Auth0, issuer pasted without `/` | ✅ | (never gets that far) |

Rahul also has an old **password** account from before Acme switched to SSO (`old-acme-pass-1`), and Meera (`meera@freelance.example` / `meera-chai-2026`) has no SSO at all. Only built-in `crypto` is used for RS256 signing and checking; no JWT library. Everything is in memory, so a restart resets it.

📄 **Full code: [server.js](server.js)**. Open it and read the comments, which follow the same steps as the notes above.

Install Express once (from this folder), then start the server:

```bash
npm install
```

```bash
node server.js
```

> Port 3000 busy? Run it on another port: `PORT=3060 node server.js` (Git Bash). The IdPs then run on 3061. The outputs below were recorded on 3060/3061.

### Try it in the browser

Open **http://localhost:3060**, type `rahul@acme.example`, click **Continue**. You land on the mock Okta page → **Continue as rahul** → `/me` shows you as an Acme admin. Try the other emails from the table.

### Try it with curl (Git Bash)

```bash
APP=http://localhost:3060; IDP=http://localhost:3061; J="Content-Type: application/json"
red() { curl -s -o /dev/null -w "%{redirect_url}" "$@"; }
sso() {   # sso <cookie-jar> <email> <mock user>
  L=$(red -c $1.jar -b $1.jar -H "$J" -d "{\"email\":\"$2\"}" $APP/sso/start)
  CB=$(red "$L&mock_user=$3")
  curl -s -L -c $1.jar -b $1.jar "$CB"; echo
}
```

`red` prints where a response redirects to. `sso` does a whole login: KaamKaro → the org's IdP → back to the callback → `/me`.

#### 1️⃣ Discovery: each IdP describes itself

```bash
curl -s $IDP/okta/oauth2/default/.well-known/openid-configuration
```
→
```json
{"issuer":"http://localhost:3061/okta/oauth2/default","authorization_endpoint":"http://localhost:3061/okta/oauth2/default/v1/authorize","token_endpoint":"http://localhost:3061/okta/oauth2/default/v1/token","jwks_uri":"http://localhost:3061/okta/oauth2/default/v1/keys","response_types_supported":["code"],"id_token_signing_alg_values_supported":["RS256"],"code_challenge_methods_supported":["S256"],"token_endpoint_auth_methods_supported":["client_secret_basic"],"scopes_supported":["openid","profile","email"]}
```

Also try `$IDP/entra/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0/.well-known/openid-configuration`, `$IDP/auth0/.well-known/openid-configuration` (note `"issuer":"http://localhost:3061/auth0/"`) and `$IDP/keycloak/realms/initech/.well-known/openid-configuration`.

#### 2️⃣ Home realm discovery: the email picks the IdP

```bash
red -c x.jar -b x.jar -H "$J" -d '{"email":"rahul@acme.example"}' $APP/sso/start; echo
curl -s -H "$J" -d '{"email":"meera@freelance.example"}' $APP/sso/start; echo
curl -s -H "$J" -d '{"email":"ceo@umbrella.example"}' $APP/sso/start -w " %{http_code}\n"
```
→
```
http://localhost:3061/okta/oauth2/default/v1/authorize?response_type=code&client_id=0oa4kaamkaro8x7&redirect_uri=http%3A%2F%2Flocalhost%3A3060%2Fsso%2Fcallback&scope=openid+profile+email&state=smtoJzQMuSVfZPu397pzRA&nonce=2nPnmEwz7Sk4cRpL9WT6ng&code_challenge=mknEz4EvoWu6-okww3yOQOShn6s5wR_WsxMCNNJJQd0&code_challenge_method=S256&login_hint=rahul%40acme.example
{"next":"password","message":"No SSO set up for freelance.example. Log in with your password."}
{"error":"Single sign-on for Umbrella is misconfigured. Ask your IT admin."} 502
```

Acme → Okta with state, nonce, PKCE and `login_hint`. Meera's domain has no SSO. Umbrella's trailing-slash mistake is caught by discovery, and the terminal says exactly why:

```
🚨 Umbrella: SSO misconfigured: issuer mismatch: configured "http://localhost:3061/auth0", IdP says "http://localhost:3061/auth0/"
```

#### 3️⃣ Enforce SSO: Rahul's old password stops working

```bash
curl -s -H "$J" -d '{"email":"rahul@acme.example","password":"old-acme-pass-1"}' $APP/login/password -w " %{http_code}\n"
curl -s -H "$J" -d '{"email":"meera@freelance.example","password":"meera-chai-2026"}' $APP/login/password -w " %{http_code}\n"
```
→
```
{"error":"Acme Corp requires single sign-on","next":"/sso/start"} 403
{"message":"Logged in as meera@freelance.example"} 200
```

#### 4️⃣ One login per IdP

```bash
sso rahul  rahul@acme.example     rahul
sso amit   amit@acme.example      amit
sso priya  priya@contoso.example  priya
sso sneha  sneha@globex.example   sneha
sso arjun  arjun@initech.example  arjun
sso rahul2 rahul@acme.example     rahul
```
→
```
{"id":"usr_kYuCMw","orgId":"acme","email":"rahul@acme.example","name":"Rahul Sharma","role":"admin","org":"Acme Corp","loggedInVia":"sso:okta"}
{"id":"usr_1wD4bg","orgId":"acme","email":"amit@acme.example","name":"Amit Verma","role":"member","org":"Acme Corp","loggedInVia":"sso:okta"}
{"id":"usr_r885kw","orgId":"contoso","email":"priya@contoso.example","name":"Priya Nair","role":"admin","org":"Contoso","loggedInVia":"sso:entra"}
{"id":"usr__5LcLQ","orgId":"globex","email":"sneha@globex.example","name":"Sneha Iyer","role":"member","org":"Globex","loggedInVia":"sso:auth0"}
{"id":"usr_SZF-xQ","orgId":"initech","email":"arjun@initech.example","name":"Arjun Mehta","role":"admin","org":"Initech","loggedInVia":"sso:keycloak"}
{"id":"usr_kYuCMw","orgId":"acme","email":"rahul@acme.example","name":"Rahul Sharma","role":"admin","org":"Acme Corp","loggedInVia":"sso:okta"}
```

The roles come from four different claims (`groups`, `roles`, `https://kaamkaro.example/roles`, `realm_access.roles`), and Priya's email comes from `preferred_username` because Entra sent no `email` claim. The terminal shows what happened to each account:

```
🔗 linked to existing account: rahul@acme.example → usr_kYuCMw in Acme Corp via okta, subject 00u8rahul1a2b3c4d5, role admin
🆕 created (JIT): amit@acme.example → usr_1wD4bg in Acme Corp via okta, subject 00u8amit9z8y7x6w5, role member
🆕 created (JIT): priya@contoso.example → usr_r885kw in Contoso via entra, subject 6f1c2e3d-4b5a-4c6d-8e7f-000000000101, role admin
🆕 created (JIT): sneha@globex.example → usr__5LcLQ in Globex via auth0, subject auth0|65a1f0c2b3d4sneha, role member
🆕 created (JIT): arjun@initech.example → usr_SZF-xQ in Initech via keycloak, subject f3b9c1d2-4e5f-4a6b-8c7d-0000000a7c01, role admin
👋 returning: rahul@acme.example → usr_kYuCMw in Acme Corp via okta, subject 00u8rahul1a2b3c4d5, role admin
```

Rahul's first SSO login **linked** his old password account (same `usr_kYuCMw`), and the second one found him by (org, subject).

#### 5️⃣ 😈 Shady Ltd's IdP claims to be Acme's admin

Vikram's company is a real KaamKaro customer with its own Keycloak. He creates a user there with `email: rahul@acme.example`, ticks "email verified", and logs in through **Shady's** connection:

```bash
sso vik vikram@shady.example vikram
```
→
```
{"error":"Shady Ltd's sign-in can't be used for acme.example accounts"}
```

The ID token was **perfectly valid** (Shady's key, Shady's issuer, right audience, right nonce). The verified-domain rule is what stopped it:

```
🚨 Shady Ltd's IdP asserted rahul@acme.example: acme.example is not one of its verified domains. Refused.
```

#### 6️⃣ 😈 IdP mix-up: a Shady code inside an Acme login

```bash
L=$(red -c v.jar -b v.jar -H "$J" -d '{"email":"vikram@shady.example"}' $APP/sso/start)
SHADY_CODE=$(red "$L&mock_user=vikram" | sed 's/.*code=\([^&]*\).*/\1/')
L=$(red -c v.jar -b v.jar -H "$J" -d '{"email":"rahul@acme.example"}' $APP/sso/start)
ACME_STATE=$(echo "$L" | sed 's/.*state=\([^&]*\).*/\1/')
curl -s -b v.jar "$APP/sso/callback?code=$SHADY_CODE&state=$ACME_STATE" -w " %{http_code}\n"
```
→ `{"error":"Sign-in with Acme Corp failed"} 400`, and the terminal: `🚨 Acme Corp login failed: token exchange: invalid_grant`. The state said "Acme", so the code went to **Acme's** token endpoint, which never issued it.

#### 7️⃣ State: wrong browser, or used twice

```bash
L=$(red -c m.jar -b m.jar -H "$J" -d '{"email":"amit@acme.example"}' $APP/sso/start); CB=$(red "$L&mock_user=amit")
curl -s -b other.jar "$CB" -w " %{http_code}\n"
curl -s -L -c m.jar -b m.jar "$CB"; echo
curl -s -L -c m.jar -b m.jar "$CB" -w " %{http_code}\n"
```
→
```
{"error":"This login didn't start here (state mismatch)"} 400
{"id":"usr_1wD4bg","orgId":"acme","email":"amit@acme.example","name":"Amit Verma","role":"member","org":"Acme Corp","loggedInVia":"sso:okta"}
{"error":"This login didn't start here (state mismatch)"} 400
```

A different browser (no matching session) is refused, the right one works, and replaying the same callback fails because each state is single-use.

#### 8️⃣ The IdP side checks too

```bash
curl -s $IDP/okta/oauth2/default/v1/token -u 0oa4kaamkaro8x7:wrong -d grant_type=authorization_code -d code=x -w " %{http_code}\n"
curl -s "$IDP/okta/oauth2/default/v1/authorize?client_id=0oa4kaamkaro8x7&redirect_uri=https://evil.example/cb" -w " %{http_code}\n"
```
→
```
{"error":"invalid_client"} 401
Unknown client_id or redirect_uri. Not redirecting. 400
```

> **Windows PowerShell users:** the shell functions, `$(…)`, single quotes in `-d '...'` and `PORT=3060 node server.js` work in Git Bash. In PowerShell, use Git Bash or the browser, or set the port with `$env:PORT=3060; node server.js`. Restart the server to reset users, sessions and the IdPs' signing keys.
