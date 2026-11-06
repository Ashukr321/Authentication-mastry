# 64. Kerberos

## Notes

### What is Kerberos?

Kerberos is the login system inside almost every company network. When you log in to a Windows laptop at office, open the intranet in Chrome and it **just knows who you are** without asking for a password, that's Kerberos. Active Directory (topic 63) uses it by default.

> **One-line answer:** Kerberos is a **ticket-based** single sign-on protocol: you prove your password **once** to a trusted server (the **KDC**) and get a **TGT**; with the TGT you ask the KDC for a **service ticket** for each service; the service checks that ticket **with its own key**, without asking the KDC, and **your password never travels over the network**.

Three words to learn first:

| Word | Meaning |
|---|---|
| **Principal** | Any identity in Kerberos: a user (`rahul@CHAIWALA.CORP`) or a service (`HTTP/payroll.chaiwala.corp`, called an **SPN**, Service Principal Name) |
| **Realm** | The Kerberos "domain", written in CAPITALS: `CHAIWALA.CORP`. In AD it's the domain name |
| **KDC** | Key Distribution Center. Knows **every** key in the realm. Has two parts: the **AS** (Authentication Service, checks your password) and the **TGS** (Ticket Granting Service, gives out service tickets). In AD, every domain controller is a KDC |

---

### Why it matters

| Problem without Kerberos | What Kerberos does |
|---|---|
| Every app asks for the password, so 20 apps = 20 chances to steal it | Password is used **once** at logon; apps only see tickets |
| Apps must call a central server to check every login | The service checks the ticket **by itself**, with its own key (fast, works if the KDC is busy) |
| Password sent to the server (even hashed, a hash can be replayed) | Only **encrypted timestamps** travel; the password-derived key never leaves the machine |
| Fake server stealing passwords | **Mutual authentication**: the server proves itself to the client too |
| A captured login message replayed later | Timestamps + 5-minute window + **replay cache** |

You meet it in interviews for enterprise / backend roles ("how does Windows SSO work?", "what is a golden ticket?") and in real work when an intranet app must support **"Integrated Windows Authentication"** (`Authorization: Negotiate`).

---

### Real-life example: the office canteen 🍛

Rahul works at Chaiwala Corp in Bengaluru.

1. **Morning, at the front desk (AS):** Rahul shows his ID card. The desk gives him a **day pass** (the **TGT**) in a sealed envelope that only the desk itself can open. He can't read or change it, he just carries it.
2. **Lunch (TGS):** Rahul goes to the **coupon counter**, shows his day pass and says "one canteen coupon, please". He doesn't show his ID again. He gets a **canteen coupon** (the **service ticket**) sealed with the **canteen's** stamp.
3. **At the canteen (the service):** the canteen checks its own stamp on the coupon and serves him. It **never phones the front desk**.
4. Coupons are **valid only for today** (ticket lifetime), and the canteen remembers coupons already used today (replay cache).

The danger: if someone steals the **front desk's stamp** (the krbtgt key), he can print day passes for anyone. That's a **golden ticket**.

---

### The big picture

#### 📊 Diagrams

Open **[diagrams.html](diagrams.html)** in your browser (just double-click the file) to see:

- **Flow diagram**: every check the KDC and the payroll service do, and where each attack fails or wins
- **Data flow**: the three exchanges (AS, TGS, AP) with the real messages from our demo
- **Who knows which key**: why the client, the KDC and the service can each open only their own envelopes

In short: `password → key → AS-REQ (encrypted timestamp) → TGT` · `TGT + authenticator → TGS-REQ → service ticket` · `service ticket + authenticator → service (checks with its own key) → mutual auth reply`.

The three exchanges:

| Exchange | Client sends | Gets back | Locked with |
|---|---|---|---|
| **AS** (once per logon) | "I'm rahul" + **time encrypted with rahul's key** (pre-auth) | **TGT** + TGS session key | TGT: **krbtgt key**. Session key: **rahul's key** |
| **TGS** (once per service) | TGT + **authenticator** + "I want `HTTP/payroll`" | **Service ticket** + service session key | Ticket: **payroll's key**. Session key: **TGS session key** |
| **AP** (every connection) | Service ticket + **authenticator** | Data + **AP-REP** (mutual auth) | Authenticator & AP-REP: **service session key** |

---

### Step 1: The password becomes a key

```js
const stringToKey = (password, principal) => crypto.pbkdf2Sync(password, REALM + principal, 4096, 32, "sha256");
```

- The KDC stores this **key** for every user (not the password). The client computes the same key from what you type, then forgets the password.
- Salt = realm + name, so two users with the same password still get different keys.
- Real AES Kerberos (RFC 3962) uses PBKDF2-HMAC-SHA1, 4096 rounds. Old **RC4-HMAC** used the plain NT hash: no salt, no rounds. That's why attackers love RC4 (Step 6).

---

### Step 2: AS exchange: log in once, get a TGT

```js
// Client: prove you know the password WITHOUT sending it (pre-authentication)
padata: seal(rahulKey, USAGE.PA_TIMESTAMP, { ts: Date.now() })
```

The KDC opens `padata` with rahul's stored key. If it opens and the time is fresh, the password was right. Then it returns:

- the **TGT**, locked with the **krbtgt** key (only the KDC can open it). Inside: rahul's name, a new **session key**, expiry, his groups (in AD: the **PAC**, Privilege Attribute Certificate)
- the same **session key**, locked with **rahul's** key (only the real rahul can open it)

| ✅ Do | ❌ Don't |
|---|---|
| Require pre-authentication for every account | Tick "Do not require Kerberos preauthentication" in AD (→ **AS-REP roasting**) |
| Check the client's `nonce` comes back in the reply | Trust any reply that arrives |
| Keep TGT lifetime short-ish (10 h, renew up to 7 days) | Make tickets valid for weeks |

---

### Step 3: TGS exchange: get a service ticket (no password needed)

The client sends the TGT + an **authenticator** = `{ cname: "rahul", ctime: now }` encrypted with the TGT session key. The authenticator proves "I'm the one who **has** the session key, **right now**", so a copied TGT alone isn't enough without the key.

```js
const tgt = unseal(krbtgtKey, USAGE.TICKET, tgtBlob);                       // only the KDC can open it
const { err } = checkAuthenticator(tgt, USAGE.TGS_AUTHENTICATOR, authBlob, kdcReplayCache);
const ticket = seal(service.key, USAGE.TICKET, { cname, sessionKey, endtime, groups }); // for payroll's eyes only
```

⚠️ The KDC **doesn't check** whether rahul is **allowed** to use payroll. Any user gets a ticket for any service. Kerberos does **authentication**; **authorization** is the service's job (topic 01).

---

### Step 4: AP exchange: the service checks the ticket by itself

On the web, the browser sends it in a header (SPNEGO, RFC 4559):

```
GET /payroll/me
Authorization: Negotiate <ticket + authenticator>
```

The service checks, in order:

| Check | Error if it fails |
|---|---|
| Ticket opens with **my keytab key** (so it's for me, from my KDC, untouched) | `KRB_AP_ERR_MODIFIED` |
| Ticket not expired | `KRB_AP_ERR_TKT_EXPIRED` |
| Authenticator opens with the ticket's session key | `KRB_AP_ERR_MODIFIED` |
| Same name in ticket and authenticator | `KRB_AP_ERR_BADMATCH` |
| Authenticator time within **5 minutes** of mine | `KRB_AP_ERR_SKEW` |
| Authenticator not seen before | `KRB_AP_ERR_REPEAT` |

Then it reads the **groups** from the ticket to decide what rahul may see (our `/payroll/all` needs `HR`).

The **keytab** is a file with the service's own key, given once by the admin (`ktpass` on Windows, `msktutil` / `kadmin` on Linux). Protect it like a private key.

---

### Step 5: Mutual authentication

The service replies with `WWW-Authenticate: Negotiate <AP-REP>`: the client's time, sealed with the session key. Only the real payroll server could open the ticket and learn that key, so this proves the **server** is genuine too. A fake server can't produce it.

---

### Step 6: Attacks every interviewer asks about

| Attack | What the attacker does | Defense |
|---|---|---|
| **Kerberoasting** | Any domain user asks for a ticket for an SPN whose account has a **human password**, then guesses passwords **offline** (hashcat) until one opens the ticket | Service accounts with **random** keys: **gMSA** (120-char, auto-rotated) or 25+ char passwords; disable **RC4**, use AES only; alert on many TGS-REQs |
| **AS-REP roasting** | For accounts **without pre-auth**, asks for an AS-REP and cracks it offline | Require pre-auth for everyone |
| **Pass-the-ticket** | Copies tickets + session keys out of memory (Mimikatz, Rubeus) or a `/tmp/krb5cc_*` file, uses them elsewhere | Credential Guard, protect the cache (`600` permissions), short lifetimes, Protected Users group |
| **Golden ticket** | Steals the **krbtgt** key (needs domain admin), forges a TGT for anyone, any groups, 10 years | Protect DCs, tier admin accounts, **reset krbtgt twice** after a breach, watch for odd TGT lifetimes |
| **Silver ticket** | Steals a **service's** key (e.g. via kerberoasting), forges service tickets for that service only. KDC never sees it | Random service keys, PAC validation |
| **Overpass-the-hash** | Uses a stolen NT hash (= RC4 key) to get a TGT without knowing the password | Disable RC4, Credential Guard |
| **User enumeration** | `KDC_ERR_C_PRINCIPAL_UNKNOWN` vs `KDC_ERR_PREAUTH_REQUIRED` reveals which usernames exist (kerbrute) | Monitoring; it's in the protocol |

---

### Kerberos vs the web logins you know

| | Kerberos | OIDC / SAML (topics 58, 60) |
|---|---|---|
| Where | Inside the company network (LAN, VPN) | Internet, cloud apps |
| Token | Binary ticket, encrypted with the **service's** key | JWT / XML assertion, **signed** by the IdP |
| Service checks with | Its **shared secret key** (keytab) | IdP's **public key** |
| Needs line of sight to the KDC | Yes (port 88) | No, just a browser redirect |
| Typical today | Windows logon, file shares, SQL Server, intranet sites | Okta / Entra ID / Google SSO |

Companies often bridge them: Kerberos at the laptop, then **Entra ID / ADFS / Keycloak** turns that into SAML/OIDC for cloud apps (topic 57).

---

### 🤔 Tricky parts

**1. Clocks must agree.** The 5-minute skew rule is why domain machines sync time with the DC (NTP). "Clock skew too great" is the first thing to check when Kerberos breaks.

**2. DNS and SPNs must match exactly.** The browser builds the SPN from the hostname: `HTTP/payroll.chaiwala.corp`. Open `http://10.0.0.5` or a CNAME alias and the SPN is different → no ticket → silent fallback to NTLM or a password box. Duplicate SPNs on two accounts also break it.

**3. Kerberos is authentication only.** The KDC hands out tickets for any service. Your app must still decide access (groups / PAC → roles, topic 28).

**4. Browsers only send tickets to trusted sites.** Chrome/Edge use the "Local intranet" zone or the `AuthServerAllowlist` policy; Firefox needs `network.negotiate-auth.trusted-uris`. Otherwise they won't send your ticket to random sites (good).

**5. The ticket cache is a password-equivalent.** It has tickets **and** session keys. Our demo's `.ccache` file shows it: copy it and you are rahul until it expires.

**6. Revocation is slow.** Disabling rahul in AD stops **new** TGTs, but tickets already issued work until they expire (up to 10 h). Same trade-off as JWTs (topic 24).

**7. Delegation.** When the payroll web app must call the payroll database **as rahul**, it uses delegation. **Unconstrained** delegation lets the server use rahul's TGT anywhere (dangerous); use **constrained** or **resource-based constrained delegation** (RBCD) instead. Same idea as token exchange (topic 67).

**8. Node.js in production.** Node has no built-in Kerberos. Use the `kerberos` npm package (MongoDB's GSSAPI binding) or `passport-negotiate`, or let IIS / nginx with SPNEGO / a reverse proxy do it and pass the user on. Never hand-roll the crypto like this demo does.

---

### Common beginner mistakes

1. **Thinking Kerberos sends the password (or its hash) to the server.**
   Only encrypted timestamps and tickets travel.

2. **Confusing the TGT and the service ticket.**
   TGT = locked with **krbtgt**, used only with the KDC. Service ticket = locked with the **service's** key, shown to the service.

3. **Thinking the service calls the KDC to check a ticket.**
   It checks with its own key, offline.

4. **Running services under user accounts with weak passwords.**
   Kerberoasting cracks them. Use gMSA.

5. **Leaving RC4 enabled.**
   Faster to crack, and the RC4 key **is** the NT hash.

6. **Accessing intranet apps by IP or a wrong alias.**
   Wrong SPN, no Kerberos.

7. **Ignoring time sync.**
   More than 5 minutes off and every ticket fails.

8. **Using Kerberos as authorization.**
   Getting a ticket ≠ being allowed.

9. **Turning off pre-authentication "to fix a legacy app".**
   Opens AS-REP roasting.

---

### Interview questions

1. **Explain the Kerberos flow.**
   AS-REQ: the client sends a timestamp encrypted with its password key; the KDC returns a TGT (encrypted with the krbtgt key) and a session key (encrypted with the user's key). TGS-REQ: the client sends the TGT + an authenticator and the SPN; the KDC returns a service ticket (encrypted with the service's key) and a new session key. AP-REQ: the client sends the service ticket + authenticator to the service, which decrypts with its keytab, checks time and replay, and optionally replies with an AP-REP for mutual auth.

2. **Why doesn't the password travel over the network?**
   Both sides derive the same key from it. The client proves it has the key by encrypting a timestamp; the KDC proves itself by sending a reply only that key can open.

3. **What's an authenticator and why is it needed?**
   The client name + current time, encrypted with the session key. It proves the sender **holds** the session key right now, so a sniffed ticket alone is useless and a replayed message is caught by the time window + replay cache.

4. **What is the krbtgt account?**
   The KDC's own account. Its key encrypts every TGT. If stolen → golden tickets. Reset it twice (because the previous key is also accepted) after a compromise.

5. **What is Kerberoasting and how do you prevent it?**
   Any authenticated user can request a service ticket for any SPN; it's encrypted with the service account's key; if that comes from a weak password, it can be cracked offline. Prevent with gMSA / long random passwords, AES only, and monitoring of TGS requests (especially RC4).

6. **Golden vs silver ticket?**
   Golden = forged TGT using the krbtgt key, works for any service. Silver = forged service ticket using one service's key, works only for that service and never touches the KDC (harder to detect).

7. **Why does Kerberos need synchronized clocks?**
   Authenticators are only valid within a skew window (5 min) so the replay cache only needs to remember a few minutes of history.

8. **How does Kerberos work with a web app?**
   SPNEGO: the server answers `401` with `WWW-Authenticate: Negotiate`; the browser gets a ticket for `HTTP/<hostname>` and retries with `Authorization: Negotiate <token>`; the server validates it with its keytab.

9. **Kerberos vs NTLM?**
   NTLM is challenge-response with the server asking the DC every time, no mutual auth, vulnerable to relay and pass-the-hash. Kerberos uses tickets, mutual auth, and is the default; NTLM is the fallback (and being phased out by Microsoft).

10. **Kerberos vs OAuth/OIDC?**
    Both issue tokens after one login. Kerberos uses symmetric keys inside a network and needs the KDC reachable; OIDC uses signed JWTs over HTTPS redirects and works across the internet.

---

### Quick recap

- **KDC** (AS + TGS) knows every key. Users and services are **principals**; services have **SPNs**
- **AS**: password → key → encrypted timestamp → **TGT** (locked with krbtgt) + session key
- **TGS**: TGT + authenticator → **service ticket** (locked with the service's key)
- **AP**: service ticket + authenticator → service checks **with its own keytab**, no KDC call → **AP-REP** for mutual auth
- Authenticators + **5-minute skew** + **replay cache** stop replays; clocks must be in sync
- Kerberos = **authentication**; the service still does authorization (groups / PAC)
- Attacks: **kerberoasting** (weak service passwords), **AS-REP roasting** (no pre-auth), **pass-the-ticket**, **golden / silver tickets**
- Defenses: gMSA, AES only, pre-auth on, protect krbtgt and DCs, Credential Guard
- Next: multi-tenant auth (topic 65)

## Code

A tiny **Kerberos realm** for **Chaiwala Corp** (`CHAIWALA.CORP`) in one Express file. One process plays three machines so you can see every message:

| Part | Plays | Routes / commands |
|---|---|---|
| KDC | the domain controller | `POST /kdc/as` (AS-REQ), `POST /kdc/tgs` (TGS-REQ) |
| Payroll service | an intranet web app with a keytab | `GET /payroll/me`, `GET /payroll/all` (HR group only), `Authorization: Negotiate …` |
| Client tools | Windows/MIT `kinit`, `klist`, `kvno` | `node server.js kinit / klist / kvno / ap-req / roast` |

Users: `rahul` (password `chai-and-code-42`, group Employees) and `priya` (`priya-hr-2026!`, Employees + HR). Services: `HTTP/payroll.chaiwala.corp` (random key) and `MSSQLSvc/db.chaiwala.corp` (key from the weak password `Chai@2024`, for the kerberoasting demo).

The client tools keep tickets in a **`.ccache` file**, like Linux's `/tmp/krb5cc_1000`. The encryption is real (AES-256-GCM with Kerberos key-usage numbers), but the messages are JSON over HTTP instead of binary ASN.1 on port 88.

📄 **Full code: [server.js](server.js)**. Open it and read the comments, which follow the same steps as the notes above.

Install Express once (from this folder), then start the server:

```bash
npm install
```

```bash
node server.js
```

> Port 3000 busy? Run it on another port: `PORT=3064 node server.js` (Git Bash). The outputs below were recorded on port 3064.

### Try it (Git Bash)

In a **second** terminal, in this folder. The client tools read `PORT` too, so export it:

```bash
export PORT=3064
APP=http://localhost:3064
J="Content-Type: application/json"
PAY=HTTP/payroll.chaiwala.corp
```

🚪 **① No ticket, no entry.** The service asks for Kerberos:

```bash
curl -s -i $APP/payroll/me
```
→
```
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Negotiate
{"error":"Kerberos ticket required (Authorization: Negotiate …)"}
```

🔑 **② The KDC wants proof of the password (pre-auth).** Asking without it, asking for a user who doesn't exist, and a wrong password:

```bash
curl -s $APP/kdc/as -H "$J" -d '{"cname":"rahul","nonce":"abc"}'
curl -s $APP/kdc/as -H "$J" -d '{"cname":"ghost","nonce":"abc"}'
node server.js kinit rahul.ccache rahul wrong-password
```
→
```
{"error":"KDC_ERR_PREAUTH_REQUIRED","message":"Send PA-ENC-TIMESTAMP: the current time encrypted with your password's key"}
{"error":"KDC_ERR_C_PRINCIPAL_UNKNOWN","message":"No user ghost@CHAIWALA.CORP"}
❌ KDC_ERR_PREAUTH_FAILED: Pre-authentication failed (wrong password)
```
The first two answers differ: that's the user-enumeration leak kerbrute uses.

🎫 **③ `kinit`: log in once, get a TGT.** The password is turned into a key, the key encrypts the time, and the password is gone:

```bash
node server.js kinit rahul.ccache rahul chai-and-code-42
node server.js klist rahul.ccache
```
→
```
✅ TGT for rahul@CHAIWALA.CORP saved in rahul.ccache
Ticket cache: rahul.ccache
Default principal: rahul@CHAIWALA.CORP

Valid until               Service principal
2026-11-06T12:40:47.278Z  krbtgt/CHAIWALA.CORP@CHAIWALA.CORP
```
Server terminal: `🎫 KDC  AS-REQ: rahul pre-auth OK → TGT until 2026-11-06T12:40:47.278Z`

Open `rahul.ccache`: the `ticket` is an opaque blob (locked with the krbtgt key), next to the `sessionKey` rahul could open.

🎟️ **④ `kvno`: get a service ticket with the TGT.** No password asked:

```bash
node server.js kvno rahul.ccache $PAY
node server.js klist rahul.ccache
```
→
```
✅ service ticket for HTTP/payroll.chaiwala.corp@CHAIWALA.CORP saved in rahul.ccache
...
Valid until               Service principal
2026-11-06T12:40:47.278Z  krbtgt/CHAIWALA.CORP@CHAIWALA.CORP
2026-11-06T12:40:47.278Z  HTTP/payroll.chaiwala.corp@CHAIWALA.CORP
```
The service ticket ends when the TGT ends. Server terminal: `🎟️  KDC  TGS-REQ: rahul → service ticket for HTTP/payroll.chaiwala.corp`

✅ **⑤ Call payroll with `Authorization: Negotiate`.** `ap-req` builds a fresh authenticator and prints the token; curl sends it:

```bash
H=$(node server.js ap-req rahul.ccache $PAY)
curl -s -i $APP/payroll/me -H "Authorization: Negotiate $H"
```
→
```
HTTP/1.1 200 OK
WWW-Authenticate: Negotiate VYU8J24IzObu1cvDGR5VN7jblt9r6_WaTL5lSPAnaI7h3NGaokW-gtrECFCz2OHU21e6
{"service":"HTTP/payroll.chaiwala.corp","user":"rahul@CHAIWALA.CORP","groups":["Employees"],"salary":"₹18,00,000"}
```
Server terminal: `🔐 PAYROLL: rahul@CHAIWALA.CORP verified with the keytab alone (no call to the KDC)`. The `WWW-Authenticate` value in the reply is the **AP-REP** (mutual authentication).

🚫 **⑥ Authenticated is not authorized.** Rahul isn't in HR:

```bash
curl -s $APP/payroll/all -H "Authorization: Negotiate $(node server.js ap-req rahul.ccache $PAY)"
```
→ `{"error":"Only the HR group can see everyone's salary"}`

🔁 **⑦ Replay: send the same header again** (as if sniffed from the network):

```bash
curl -s $APP/payroll/me -H "Authorization: Negotiate $H"
```
→ `{"error":"KRB_AP_ERR_REPEAT","message":"This authenticator was already used (replay)"}`

⏰ **⑧ Clock 10 minutes off.** The last argument moves the client's clock:

```bash
curl -s $APP/payroll/me -H "Authorization: Negotiate $(node server.js ap-req rahul.ccache $PAY 10)"
```
→ `{"error":"KRB_AP_ERR_SKEW","message":"Clock skew too great (more than 5 minutes)"}`

🎯 **⑨ A ticket for another service doesn't work here.** Rahul gets a database ticket and shows it to payroll:

```bash
node server.js kvno rahul.ccache MSSQLSvc/db.chaiwala.corp
curl -s $APP/payroll/me -H "Authorization: Negotiate $(node server.js ap-req rahul.ccache MSSQLSvc/db.chaiwala.corp)"
```
→
```
✅ service ticket for MSSQLSvc/db.chaiwala.corp@CHAIWALA.CORP saved in rahul.ccache
{"error":"KRB_AP_ERR_MODIFIED","message":"Ticket isn't for this service, or was tampered with"}
```

👩‍💼 **⑩ Priya is in HR:**

```bash
node server.js kinit priya.ccache priya 'priya-hr-2026!'
curl -s $APP/payroll/all -H "Authorization: Negotiate $(node server.js ap-req priya.ccache $PAY)"
```
→
```
✅ TGT for priya@CHAIWALA.CORP saved in priya.ccache
{"salaries":{"rahul":"₹18,00,000","priya":"₹21,00,000"}}
```

😈 **⑪ Pass-the-ticket.** Vikram copies Rahul's ticket cache (malware, a readable `/tmp/krb5cc_*`). No password needed:

```bash
cp rahul.ccache stolen.ccache
curl -s $APP/payroll/me -H "Authorization: Negotiate $(node server.js ap-req stolen.ccache $PAY)"
```
→ `{"service":"HTTP/payroll.chaiwala.corp","user":"rahul@CHAIWALA.CORP","groups":["Employees"],"salary":"₹18,00,000"}`

💥 **⑫ Kerberoasting.** Rahul (any user!) gets a ticket for the SQL service and guesses its password **offline**. Then tries the same on payroll, whose key is random:

```bash
node server.js roast rahul.ccache MSSQLSvc/db.chaiwala.corp
node server.js roast rahul.ccache $PAY
```
→
```
💥 Cracked MSSQLSvc/db.chaiwala.corp: its password is "Chai@2024"
   Inside the ticket: {"cname":"rahul","groups":["Employees"]}
   With this key I can forge tickets for this service as ANY user ("silver ticket").
🛡️  6 guesses, none opened the ticket for HTTP/payroll.chaiwala.corp: its key is random, not a password
```
The KDC saw two normal TGS requests. Nothing else touched the network.

🧹 Clean up the ticket caches: `rm -f *.ccache` (that's `kdestroy`).

> **Windows PowerShell users:** `export`, `$(…)` and the single quotes work in Git Bash. In PowerShell, set the port with `$env:PORT=3064` (in **both** terminals), run the `node server.js …` tools as they are, and build the header with `$H = node server.js ap-req rahul.ccache HTTP/payroll.chaiwala.corp; curl.exe -s http://localhost:3064/payroll/me -H "Authorization: Negotiate $H"`. Restart the server to get new keys (old `.ccache` files then stop working: run `kinit` again).
