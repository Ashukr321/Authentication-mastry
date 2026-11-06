# 57. SSO Concepts: IdP vs SP

## Notes

### What is SSO?

**Single Sign-On (SSO)** means you log in **once**, at one central place, and then every app you use at work lets you in **without asking for a password again**.

Two roles make it work:

- **IdP (Identity Provider):** the one place that checks who you are. It has the passwords, MFA and user directory. Examples: Okta, Microsoft Entra ID (Azure AD), Google Workspace, Keycloak, Auth0, OneLogin.
- **SP (Service Provider):** an app that **trusts** the IdP instead of checking passwords itself. Examples: Slack, Salesforce, Jira, your company's HR portal. In OpenID Connect the SP is called the **Relying Party (RP)**.

> **One-line answer:** In SSO the **IdP** authenticates the user once and hands each app (**SP**) a short-lived, **signed statement** ("this is Rahul, for *your* app, answering *your* request, valid for 2 minutes"). The SP checks the signature with the IdP's public key, checks issuer, audience, destination, expiry and replay, then creates its **own** session. The SP never sees the password.

---

### Why it matters

| Without SSO | With SSO |
|---|---|
| 40 apps × 1 password each. People reuse them, write them down | One strong password + MFA, at one place |
| Every app stores password hashes and has its own login bugs | Apps store **no passwords**. Login security lives in one hardened system |
| MFA added app by app (or never) | MFA once, at the IdP, for every app |
| Employee leaves → someone must remember 40 accounts | Disable them **once** at the IdP → no new logins anywhere |
| Helpdesk drowning in "forgot password" tickets | One reset, at the IdP |
| Auditors ask "who logged in to what?" | One log (topic 55) |

This is why every company buying B2B software asks: **"Do you support SSO?"** Supporting SAML and OIDC is often what unlocks enterprise customers.

---

### Real-life example: the office security desk 🏢

Rahul works at ChaiCorp in Bengaluru. The building has many departments: HR, Payroll, the canteen.

1. In the morning Rahul shows his ID card and fingerprint **once** at the **security desk** → logs in at the **IdP**
2. He walks to HR. HR doesn't check his ID. It sends him to the desk: "get a pass for HR" → the SP **redirects** to the IdP
3. The desk already knows him today, so no fingerprint again. It writes a pass: "Rahul Sharma, Engineering, **for HR only**, valid **2 minutes**", and **stamps it with the company seal** → a **signed assertion**
4. HR checks the seal (they got a sample of the real seal on day one), checks that the pass says "HR", and checks the time. Then HR gives Rahul its **own** visitor token for the day → the SP checks the assertion and creates its **own session**
5. Payroll: same thing, and still no fingerprint → **that's single sign-on**
6. Vikram picks up Rahul's used HR pass from the bin and shows it at Payroll: "this pass says HR" → refused. Shows it at HR again: "already used" → refused

---

### The big picture

#### 📊 Diagrams

Open **[diagrams.html](diagrams.html)** in your browser (just double-click the file) to see:

- **Flow diagram**: every decision from "Rahul opens HR Portal" to "he's in", including the checks the app runs on the assertion
- **Data flow**: the real messages for the first app (password typed) and the second app (no password: SSO)
- **Three separate sessions**: the IdP's and each app's, and why logging out of one doesn't log you out of the others

In short: `open app → no app session → redirect to IdP with a request id → IdP login (or IdP session already there) → signed assertion → browser POSTs it to the app's ACS → app checks it → app's own session`

#### Words you'll hear

| Concept | Generic / SAML (topic 58) | OpenID Connect (topic 60) |
|---|---|---|
| Who checks the password | IdP | OpenID Provider (OP) |
| The app | SP (Service Provider) | RP (Relying Party) / client |
| App's id at the IdP | Entity ID | `client_id` |
| The signed "who this is" | Assertion (XML) | ID token (JWT, topic 36) |
| Where the IdP sends it | ACS (Assertion Consumer Service) URL | `redirect_uri` |
| Trust setup document | Metadata XML | Discovery `/.well-known/openid-configuration` + JWKS |
| "Where to go after login" | RelayState | `state` (topic 35) |
| "Which request is this the answer to" | `InResponseTo` | `nonce` + `state` |

---

### Step 1: Set up the trust, once, before any login

SSO is not magic: an admin connects the app and the IdP **in advance**:

- The **SP gets the IdP's public key** (and its issuer name and SSO URL), from the IdP's **metadata**
- The **IdP registers the SP**: its id (`hr-portal`) and its **fixed ACS URL**

```js
const serviceProviders = new Map([
  ["hr-portal", { name: "HR Portal", acs: "http://localhost:3058/acs" }],
  ["payroll",   { name: "Payroll",   acs: "http://localhost:3059/acs" }],
]);
```

| ✅ Do | ❌ Don't |
|---|---|
| Pin the IdP's key from metadata at setup | Use a key or URL that comes **inside** the assertion |
| Send assertions only to the **registered** ACS URL | Send them to a URL from the request (an attacker's) |
| Plan for key rotation: accept old + new key for a while (topic 54) | Hard-code one key forever |

---

### Step 2: The app redirects to the IdP (SP-initiated SSO)

Rahul opens HR Portal. No HR session, so:

```
302 Location: http://localhost:3057/sso?sp=hr-portal&request_id=2LRxiT5D…&relay_state=%2F
Set-Cookie: hr_req=2LRxiT5D…; HttpOnly; SameSite=Lax; Max-Age=300
```

- `request_id` is random, remembered by the app **and** tied to this browser with a cookie. The answer must quote it.
- `relay_state` is where Rahul was going, so he lands there after login.

---

### Step 3: The IdP authenticates (or doesn't need to)

- **No IdP session:** show the IdP's login page. Password (+ MFA) is typed **only here**, on the IdP's domain. That's also great anti-phishing training: "the password box is only ever on `login.chaicorp.com`".
- **IdP session already exists:** skip the login. **This is the "single" in single sign-on.**

---

### Step 4: The IdP issues a signed assertion

```js
{
  "id": "008d03e7-…",                  // unique → replay protection
  "iss": "http://localhost:3057",      // who says this
  "sub": "3b33e979-…",                 // stable user id (emails change!)
  "email": "rahul@chaicorp.com", "name": "Rahul Sharma", "department": "Engineering",
  "aud": "hr-portal",                  // which app it's for
  "acs": "http://localhost:3058/acs",  // where it may be delivered
  "inResponseTo": "2LRxiT5D…",         // which request it answers
  "authAt": 1793932515, "iat": 1793932515, "exp": 1793932635   // 2 minutes
}
```

The IdP signs it with its **private** key and the **browser** carries it to the app with an auto-submitting form (the **HTTP-POST binding**). The IdP and the app never talk directly during login.

---

### Step 5: The app checks EVERYTHING (the ACS)

| Check | Attack it stops |
|---|---|
| **Signature** with the pinned IdP key, **first** | Forged or edited assertion ("make me admin", change the email) |
| `iss` = our IdP | An assertion from another IdP the app also trusts |
| `aud` = this app | An assertion for HR Portal replayed at Payroll |
| `acs` = this ACS URL | An assertion meant for another endpoint |
| `iat` / `exp` (with about 30 s clock skew) | An old assertion found in logs or browser history |
| `id` not seen before | The same assertion used twice |
| `inResponseTo` = the request **this browser** started | Unsolicited assertions; **login CSRF** (logging the victim into the attacker's account) |
| `relay_state` is a local path | Open redirect after login |

Skipping any one of these is a real vulnerability that has been found in real SAML/OIDC libraries. The SAML attack topic (59) goes deeper (XML signature wrapping).

---

### Step 6: The app creates its own user and its own session

- **Key users by `iss` + `sub`** (SAML: `NameID`), not by email. Emails get renamed; ids don't.
- **Just-in-time (JIT) provisioning:** first login creates the local account from the assertion's attributes. SCIM (topic 62) creates/disables accounts **before** login instead.
- **New session id** (topic 50), `HttpOnly` cookie. From now on the app **doesn't ask the IdP** on every request.

---

### Three sessions, not one

| Session | Lives at | Our demo | Ends when |
|---|---|---|---|
| IdP session | IdP's domain (`idp_sid`) | 8 h | IdP logout / timeout |
| HR Portal session | HR's domain (`hr_sid`) | 1 h | HR logout / timeout |
| Payroll session | Payroll's domain (`payroll_sid`) | 1 h | Payroll logout / timeout |

Consequences you'll see in the demo:

- **Log out of HR only** → open HR again → instantly back in (the IdP session is still there)
- **Log out of the IdP** → Payroll **still works** until its own session ends. Ending all of them together is **Single Logout** (topic 61)
- **Disable a user at the IdP** → no **new** logins, but existing app sessions live on. Keep app sessions short, or use SCIM / back-channel logout to kill them

---

### SP-initiated vs IdP-initiated

| | SP-initiated | IdP-initiated |
|---|---|---|
| Starts at | The app ("Log in with SSO") | The IdP's app dashboard (click the Payroll tile) |
| `InResponseTo` | Yes | **None**: nobody asked |
| Risk | Low | Higher: an assertion with no request can be **planted** (login CSRF) or replayed |
| Our demo | ✅ Allowed | ⛔ Refused |

Many enterprise customers want IdP dashboards to work. The safe way: the tile opens the **app's** login URL, which then does a normal SP-initiated login (OIDC calls this "initiate login URI").

---

### SSO vs OAuth vs social login

| | What it answers |
|---|---|
| **SSO** | "Log in once, use many apps." An **architecture**, built with SAML or OIDC |
| **OAuth 2.0** (topic 33) | "May this app **access** my data?" **Authorization**, not login |
| **OpenID Connect** (topic 36) | Login on top of OAuth. The modern SSO protocol |
| **Social login** (topics 37–38) | SSO where Google/GitHub is the IdP, for **consumers** |
| **Enterprise SSO** | SSO where the **customer's** IdP (their Okta / Entra ID) is the IdP, for their **employees** |

---

### 🤔 Tricky parts

**1. Which IdP?** A SaaS app has many customers, each with their own IdP. The usual answer is **home realm discovery**: ask for the email first, look up the domain (`@chaicorp.com` → ChaiCorp's IdP), then redirect.

**2. Don't trust the `email` blindly.** If Customer A's IdP can send `email: ceo@customer-b.com`, it can log into B's accounts. Only accept emails for domains **that customer has verified**, and key accounts by issuer + subject.

**3. `SameSite` and the POST binding.** The IdP POSTs to your ACS from **another site**, and a `SameSite=Lax` cookie is not sent on cross-site POSTs. Your request-tracking cookie needs `SameSite=None; Secure` (our demo works with `Lax` only because all three run on `localhost`).

**4. The IdP is the crown jewel.** One IdP account = every app. Phishing-resistant MFA (passkeys, topic 46), short IdP sessions, and alerts (topic 55) matter much more here.

**5. Keep a break-glass account.** If the IdP is down or misconfigured, nobody can log in to anything, including the admins who need to fix it. Keep one emergency local admin, locked away, with MFA.

**6. Clock skew.** Two-minute assertions fail if a server's clock is off. Allow a small skew (30–60 s) and run NTP.

**7. `authAt` matters for step-up.** An SSO login may be **hours** after the password was typed. For sensitive actions, ask the IdP for a fresh login (SAML `ForceAuthn`, OIDC `prompt=login` / `max_age`), topic 45.

---

### Common beginner mistakes

1. **Not verifying the signature** (or verifying it after reading fields).
2. **Not checking audience**: any assertion from the IdP, for any app, logs you in.
3. **Accepting assertions with no expiry check or no replay check.**
4. **Taking the IdP key or URL from the assertion** instead of the pinned metadata.
5. **Matching users by email** instead of issuer + subject, or trusting any email from any customer's IdP.
6. **Accepting unsolicited (IdP-initiated) assertions** without a plan for login CSRF.
7. **Open redirect through RelayState / `state`.**
8. **Thinking IdP logout logs you out everywhere.** It doesn't, without Single Logout.
9. **Long app sessions with no deprovisioning**: a fired employee keeps access for days.
10. **Writing your own SAML parser.** Use a well-maintained library (topic 58).

---

### Interview questions

1. **What's the difference between an IdP and an SP?**
   The IdP authenticates users and issues signed assertions/tokens. The SP is an application that trusts those assertions instead of handling passwords.

2. **Walk me through an SP-initiated SSO login.**
   User opens the app → no session → redirect to the IdP with a request id → IdP authenticates (or reuses its session) → IdP signs an assertion for that app and request → browser POSTs it to the app's ACS → app validates signature, issuer, audience, destination, expiry, replay and request id → app creates its own session.

3. **Why doesn't the user type a password the second time?**
   The IdP has its own session cookie on its domain. When the second app redirects there, the IdP sees the session and issues an assertion right away.

4. **What must an SP validate in an assertion?**
   Signature (with the pinned key), issuer, audience, destination/ACS, time window, one-time use, and that it answers a request this browser started.

5. **SP-initiated vs IdP-initiated SSO?**
   SP-initiated starts at the app and the answer references the request. IdP-initiated starts at the IdP with no request, so it's open to login CSRF and replay. Prefer SP-initiated, or have the IdP tile kick off an SP-initiated login.

6. **SAML vs OIDC?**
   Both do SSO. SAML: XML assertions, older, everywhere in enterprises. OIDC: JSON/JWT on OAuth 2.0, simpler, better for mobile and SPAs. New apps usually prefer OIDC and support SAML for enterprise customers.

7. **If I log out of the IdP, am I logged out of all apps?**
   No. Each app has its own session. You need Single Logout (topic 61) or short app sessions.

8. **How do you remove a user's access everywhere when they leave?**
   Disable them at the IdP (no new logins), and deprovision app accounts with SCIM (topic 62) or end their app sessions; keep app sessions short.

---

### Quick recap

- **IdP** checks who you are; **SP** trusts the IdP. Passwords and MFA live **only** at the IdP
- Trust is set up **once**: SP pins the IdP's key; IdP registers the SP's id and **fixed ACS URL**
- Login: **redirect** with a request id → IdP login (or existing IdP session = SSO) → **signed assertion** → POSTed to the **ACS**
- The SP checks **signature, issuer, audience, destination, expiry, one-time use, request id**, then creates its **own** user (by `sub`) and **own** session
- **Three sessions**: logging out of one doesn't end the others (Single Logout, topic 61)
- Prefer **SP-initiated**; SAML (topic 58) and OIDC (topic 60) are two ways to build the same thing

## Code

**Three servers in one file**, all made with Express:

| Server | Port | Role |
|---|---|---|
| 🔐 **ChaiCorp Login** | `PORT` | The **IdP**: users, passwords, signing key, `/metadata`, `/sso` |
| 👥 **HR Portal** | `PORT + 1` | An **SP**: `/` (redirects to the IdP), `/acs`, `/api/me`, `/logout` |
| 💰 **Payroll** | `PORT + 2` | Another **SP**, same code, different id |

The assertion is a small signed JSON document (`base64url(JSON).base64url(RSA-SHA256 signature)`), so you can read it. SAML (topic 58) uses XML and OIDC (topic 60) a JWT, but the steps and checks are the same. Everything is in memory and the signing key is new on every start, so a restart resets it.

📄 **Full code: [server.js](server.js)**. Open it and read the comments, which follow the same steps as the notes above.

Install Express once (from this folder), then start the servers:

```bash
npm install
```

```bash
node server.js
```

> Port 3000 busy? Run it on another port: `PORT=3057 node server.js` (Git Bash). HR Portal then runs on 3058 and Payroll on 3059. The outputs below were recorded on port 3057.

### Try it in the browser

1. Open **http://localhost:3058** (HR Portal). You land on **ChaiCorp Login** (port 3057).
2. Log in as **rahul@chaicorp.com** / **chai-and-code-42**. A "Signing you in…" page flashes and you're on HR Portal: *"Welcome, Rahul Sharma… You never typed a password here."*
3. Open **http://localhost:3059** (Payroll). **No login page**: you're straight in. That's SSO.

### Try it with curl (Git Bash)

curl doesn't run the auto-submit JavaScript, so we do the browser's job by hand: follow the redirect, take the assertion out of the form, and POST it.

```bash
IDP=http://localhost:3057
HR=http://localhost:3058
PAY=http://localhost:3059
grab() { grep -o 'name="assertion" value="[^"]*"' | cut -d'"' -f4; }
```

`rahul.jar` is Rahul's browser. All three servers are on `localhost`, so they share it, which is why each uses its own cookie name.

#### The first app: Rahul types his password once

🚪 **① Open HR Portal.** No session, so it redirects to the IdP with a request id (and remembers it in a cookie):

```bash
LOC=$(curl -s -o /dev/null -w "%{redirect_url}" -c rahul.jar $HR/)
echo "$LOC"
```
→ `http://localhost:3057/sso?sp=hr-portal&request_id=2LRxiT5DU7emhJwYOv9oKTX0WJpdDP4LlujrKUzh8XA&relay_state=%2F`

🔐 **② The IdP has no session for Rahul**, so it shows its login page:

```bash
curl -s -b rahul.jar "$LOC" | grep -o "<p><b>.*</p>"
```
→ `<p><b>HR Portal</b> wants to know who you are.</p>`

🎫 **③ Rahul logs in at the IdP.** The reply is an auto-submitting form to HR's ACS, carrying the signed assertion. Decode its first half to read it:

```bash
A=$(curl -s -b rahul.jar -c rahul.jar "$LOC" -d "email=rahul@chaicorp.com" -d "password=chai-and-code-42" | grab)
node -e "console.log(Buffer.from(process.argv[1].split('.')[0],'base64url').toString())" "$A"
```
→
```json
{"id":"008d03e7-00d5-46c8-92ca-71f5297ccd2b","iss":"http://localhost:3057","sub":"3b33e979-f9df-4ae7-8ab7-313f70e304e3","email":"rahul@chaicorp.com","name":"Rahul Sharma","department":"Engineering","aud":"hr-portal","acs":"http://localhost:3058/acs","inResponseTo":"2LRxiT5DU7emhJwYOv9oKTX0WJpdDP4LlujrKUzh8XA","authAt":1793932515,"iat":1793932515,"exp":1793932635}
```
`inResponseTo` matches the `request_id` from ①, and `exp` is 120 seconds after `iat`.

✅ **④ The browser POSTs it to HR's ACS.** HR checks it, creates Rahul's local account and its **own** session:

```bash
curl -s -i -b rahul.jar -c rahul.jar $HR/acs --data-urlencode "assertion=$A" -d "relay_state=/"
curl -s -b rahul.jar $HR/api/me
```
→
```
HTTP/1.1 303 See Other
Set-Cookie: hr_sid=ma6CsqngKB_E6rsIQCNuc8xZstspudSOSqin38Ec0sw; Max-Age=3600; Path=/; Expires=Fri, 06 Nov 2026 03:35:16 GMT; HttpOnly; SameSite=Lax
Location: /
{"app":"HR Portal","email":"rahul@chaicorp.com","name":"Rahul Sharma","sub":"3b33e979-f9df-4ae7-8ab7-313f70e304e3","localAccountCreatedAt":"2026-11-06T02:35:16.518Z"}
```

#### The second app: no password (this is SSO)

💰 **⑤ Open Payroll.** It redirects to the IdP, the IdP already knows Rahul, and answers **straight away** with an assertion for Payroll:

```bash
LOC=$(curl -s -o /dev/null -w "%{redirect_url}" -b rahul.jar -c rahul.jar $PAY/)
A2=$(curl -s -b rahul.jar -c rahul.jar "$LOC" | grab)
curl -s -b rahul.jar -c rahul.jar $PAY/acs --data-urlencode "assertion=$A2" -d "relay_state=/" -o /dev/null
curl -s -b rahul.jar $PAY/api/me
curl -s -b rahul.jar $IDP/me
```
→
```
{"app":"Payroll","email":"rahul@chaicorp.com","name":"Rahul Sharma","sub":"3b33e979-f9df-4ae7-8ab7-313f70e304e3","localAccountCreatedAt":"2026-11-06T02:35:17.280Z"}
{"email":"rahul@chaicorp.com","loggedInAt":"2026-11-06T02:35:15.539Z","apps":["hr-portal","payroll"]}
```
Same `sub` in both apps. The IdP remembers which apps Rahul is in (Single Logout needs that, topic 61).

Server terminal so far:
```
🔐 IdP: rahul@chaicorp.com typed the password
🎫 IdP → HR Portal: assertion for rahul@chaicorp.com
👤 HR Portal: new local account for rahul@chaicorp.com (just-in-time)
✅ HR Portal: rahul@chaicorp.com signed in via SSO
🎫 IdP → Payroll: assertion for rahul@chaicorp.com
👤 Payroll: new local account for rahul@chaicorp.com (just-in-time)
✅ Payroll: rahul@chaicorp.com signed in via SSO
```

#### Vikram attacks the ACS 😈

🔁 **⑥ Replay** the HR assertion at HR:

```bash
curl -s -b rahul.jar $HR/acs --data-urlencode "assertion=$A"
```
→ `{"error":"Assertion already used (replay)"}`

🔀 **⑦ Use the HR assertion at Payroll:**

```bash
curl -s -b rahul.jar $PAY/acs --data-urlencode "assertion=$A"
```
→ `{"error":"This assertion is for \"hr-portal\", not \"payroll\""}`

✏️ **⑧ Change the email** in the assertion (and keep the old signature):

```bash
T=$(node -e "const [b,s]=process.argv[1].split('.');const p=JSON.parse(Buffer.from(b,'base64url'));p.email='vikram@chaicorp.com';p.department='Finance';console.log(Buffer.from(JSON.stringify(p)).toString('base64url')+'.'+s)" "$A")
curl -s $HR/acs --data-urlencode "assertion=$T"
```
→ `{"error":"Bad signature: not from our IdP, or changed on the way"}`

📨 **⑨ An unsolicited (IdP-initiated) assertion**, with no `request_id`:

```bash
U=$(curl -s -b rahul.jar "$IDP/sso?sp=payroll" | grab)
curl -s -b rahul.jar $PAY/acs --data-urlencode "assertion=$U"
```
→ `{"error":"Unsolicited assertion refused: start the login from the app"}`

🚫 **⑩ Ask the IdP for an assertion for an app it doesn't know:**

```bash
curl -s "$IDP/sso?sp=evil-app"
```
→ `{"error":"Unknown app: it must be registered with the IdP first"}`

#### Three sessions

👋 **⑪ Log out of HR only**, then open HR again. The IdP still has a session, so it signs Rahul straight back in (no login page):

```bash
curl -s -b rahul.jar -c rahul.jar -X POST $HR/logout
LOC=$(curl -s -o /dev/null -w "%{redirect_url}" -b rahul.jar -c rahul.jar $HR/)
curl -s -b rahul.jar "$LOC" | grep -o "<title>.*</title>"
```
→ `{"message":"Logged out of HR Portal only"}` then `<title>Signing you in…</title>`

🔐 **⑫ Log out of the IdP.** Payroll **still** works (its own session), but the next new login needs the password again:

```bash
curl -s -b rahul.jar -c rahul.jar -X POST $IDP/logout
curl -s -b rahul.jar $PAY/api/me
LOC=$(curl -s -o /dev/null -w "%{redirect_url}" -b rahul.jar -c rahul.jar $HR/)
curl -s -b rahul.jar "$LOC" | grep -o "<title>.*</title>"
```
→
```
{"message":"Logged out of ChaiCorp Login (the apps still have their own sessions)"}
{"app":"Payroll","email":"rahul@chaicorp.com","name":"Rahul Sharma","sub":"3b33e979-f9df-4ae7-8ab7-313f70e304e3","localAccountCreatedAt":"2026-11-06T02:35:17.280Z"}
<title>ChaiCorp Login</title>
```
Ending all of them at once is **Single Logout** (topic 61).

> **Windows PowerShell users:** the single quotes, `$(…)`, the `grab()` function and `VAR=value node ...` work in Git Bash. In PowerShell, use Git Bash or just the browser steps, or set the port with `$env:PORT=3057; node server.js`. Restart the server to reset everything (it also makes a new signing key).
