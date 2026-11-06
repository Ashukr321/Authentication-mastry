# 63. LDAP / Active Directory

## Notes

### What is LDAP? What is Active Directory?

**Active Directory (AD)** is Microsoft's **company user directory**. Almost every big Indian company (banks, IT services, manufacturing) has one. It holds every employee, their password, their department, their manager, and the **groups** they belong to. The same AD password opens your Windows laptop, Outlook, the VPN and the Wi-Fi.

**LDAP** (Lightweight Directory Access Protocol) is the **language** apps use to talk to a directory like AD (or OpenLDAP, FreeIPA). With LDAP an app can **search** ("find the user rahul") and **bind** ("log in as this user with this password").

So "LDAP login" for a web app means: **don't keep your own passwords, ask the company's AD whether the password is right**.

> **One-line answer:** LDAP login = **search, then bind**. A service account **searches** AD for the user's DN (with the input **escaped**), then the app **binds as that user** with their password on a **new TLS connection** (`ldaps://`, port 636). Reject **empty passwords** first (an empty password "succeeds" as anonymous), map **AD groups (by full DN, nested)** to app roles, key the local user by **objectGUID**, and keep your own failure limit **below** AD's lockout.

---

### Why it matters

| Problem without AD login | What AD gives you |
|---|---|
| Every internal app has its own passwords, people reuse them | One password, managed (and expired, and reset) by IT |
| An employee leaves; HR forgets to remove them from 20 apps | IT disables **one** account, every AD-connected app stops working for them |
| "Who can open the payroll app?" lives in each app's database | Access is an **AD group**; IT adds or removes people in one place |
| Each app builds password reset, complexity rules, lockout | AD already does all of it |

You'll meet LDAP in **enterprise and on-prem** jobs: internal portals, Jenkins, Grafana, GitLab, Jira, VPNs, Keycloak "user federation". New SaaS apps usually use **SSO** instead (SAML/OIDC, topics 57-60), but the IdP behind that SSO is very often… AD.

---

### Real-life example: the company ID-card office 🏢

ChaiCorp has 5,000 employees in Bengaluru and Pune. Rahul joins as a backend developer.

1. HR and IT create **one** entry for Rahul in AD: name, department, groups, password → **one directory entry**
2. Rahul opens the internal portal **ChaiPortal** and types `rahul` + his Windows password
3. ChaiPortal has a **reception desk login** of its own (`svc-chaiportal`). The receptionist looks Rahul up in the register: "Rahul Verma, Engineering, floor 3" → **search with the service account**
4. Then the receptionist calls security: "Rahul is here, he says the code is ____. Correct?" Security checks; the receptionist never learns the real code → **bind as Rahul**
5. Rahul is in the Engineering team, which is allowed in → **groups → roles**
6. Priya is an IT Lead. IT-Leads are inside Portal-Admins, and Portal-Admins are inside Portal-Users → **nested groups**
7. Amit resigned last week. IT disabled his card once; it stops working at every door → **disable in AD, every app follows**
8. Vikram, an outsider, keeps guessing Neha's code at the reception desk. After 5 wrong tries security **locks Neha's card everywhere**, even her laptop → **lockout DoS**, so the desk must stop him earlier

---

### The building blocks

#### 📊 Diagrams

Open **[diagrams.html](diagrams.html)** in your browser (just double-click the file) to see:

- **Flow diagram**: the safe login, step by step, and where each attack is stopped
- **Data flow**: the real search and bind messages between the browser, ChaiPortal and AD
- **Nested groups**: how Priya becomes an admin
- **LDAP injection**: how one search box leaks a salary, digit by digit

In short: `username + password → service account searches AD for the user's DN (escaped) → bind as that DN with the password → groups → roles → local user (JIT) → app session`

#### The directory is a tree

```
DC=chaicorp,DC=local                         ← the domain chaicorp.local
├── OU=People                                ← an Organizational Unit (a folder)
│   ├── CN=Rahul Verma                       ← a user
│   └── CN=Priya Sharma
├── OU=Groups
│   ├── CN=Portal-Users
│   └── CN=Portal-Admins
└── OU=Service Accounts
    └── CN=svc-chaiportal                    ← the app's own AD account
```

Every entry has a **DN** (Distinguished Name), its full path from the leaf up: `CN=Rahul Verma,OU=People,DC=chaicorp,DC=local`. It's like a postal address read from the flat number up to the country.

| Term | Meaning | Example |
|---|---|---|
| **DN** | Full unique path of an entry | `CN=Rahul Verma,OU=People,DC=chaicorp,DC=local` |
| `CN` / `OU` / `DC` | Common Name / Organizational Unit / Domain Component | `CN=Rahul Verma` |
| **Attribute** | A field on an entry (can have many values) | `mail`, `department`, `memberOf` |
| `sAMAccountName` | The old-style login name | `rahul` (you type `CHAICORP\rahul` on Windows) |
| `userPrincipalName` (UPN) | Email-style login name | `rahul@chaicorp.local` |
| `objectGUID` | ID that **never changes**, even after a rename | `f683f423-…` |
| `memberOf` | Groups the user is directly in | `CN=Engineering,OU=Groups,…` |
| `userAccountControl` | Bit flags; bit `0x2` = **disabled** | `512` normal, `514` disabled |

#### The two LDAP operations you need

| Operation | What it does | Analogy |
|---|---|---|
| **Bind** | "Log in to the directory as this DN with this password" | Showing your ID card at the gate |
| **Search** | "Under this DN, find entries matching this filter, return these attributes" | Looking someone up in the register |

**Search filters** use prefix notation in brackets (RFC 4515):

```
(sAMAccountName=rahul)                           equal
(cn=Pri*)                                        starts with (* is a wildcard)
(&(objectClass=user)(department=IT))             AND
(|(sAMAccountName=rahul)(mail=rahul@chaicorp.in)) OR
(!(userAccountControl=514))                      NOT
```

#### Ports

| Port | What | Use it? |
|---|---|---|
| 389 | Plain LDAP | ❌ the password travels in **clear text**, unless you upgrade with StartTLS |
| **636** | **LDAPS** (LDAP over TLS) | ✅ |
| 3268 / 3269 | Global Catalog (searches the whole AD forest) | For multi-domain companies, 3269 = TLS |

---

### Step 1: Connect over TLS, with a service account

The app needs its **own AD account** to search, because AD doesn't allow anonymous searches (and you shouldn't enable them).

```js
// Real code, with the ldapts library (npm i ldapts)
const { Client } = require("ldapts");
const svc = new Client({
  url: "ldaps://dc1.chaicorp.local:636",
  tlsOptions: { ca: [fs.readFileSync("chaicorp-root-ca.pem")] }, // the company CA that signed the DC's certificate
});
await svc.bind(process.env.LDAP_BIND_DN, process.env.LDAP_BIND_PASSWORD);
```

| ✅ Do | ❌ Don't |
|---|---|
| `ldaps://` on 636 (or StartTLS on 389) | Plain `ldap://`: our demo's "sniffer" prints every password |
| Trust the company CA with `ca: [...]` | `rejectUnauthorized: false` "because the certificate failed" |
| A **read-only** service account that can read only the attributes you need | Bind as a Domain Admin "because it works" |
| Service account password in a secrets manager, rotated (topic 54) | Password in `config.js` in Git |

---

### Step 2: Validate input, and never send an empty password

This is the **most famous LDAP bug**. The LDAP spec (RFC 4513) has an "unauthenticated bind": a DN with an **empty password** is not an error. AD answers **success**, and the connection is just anonymous.

```js
// ❌ "bind didn't throw, so the password was right"
await client.bind(userDn, req.body.password);   // password "" → success!
```

In our demo, `{"username":"*","password":""}` logs the attacker in as **Priya, the IT Lead**.

```js
// ✅ check before you bind
if (typeof password !== "string" || password.length === 0) return res.status(400).json({ error: "Password is required" });
```

Also allowlist the username format (`/^[a-zA-Z0-9._-]{1,64}$/`) and keep a **failure limit per username that is lower than AD's lockout threshold** (we use 3, AD uses 5). Every wrong password your form sends counts towards AD lockout, so without your own limit, anyone on the internet can lock any employee out of their **laptop, email and VPN**.

---

### Step 3: Search for the user, with the input escaped

```js
// ❌ LDAP injection: the input becomes part of the filter
const filter = `(&(objectClass=user)(sAMAccountName=${username}))`;

// ✅ escape the 5 special characters: \ * ( ) NUL  →  \5c \2a \28 \29 \00
const escapeFilter = (v) => String(v).replace(/[\\*()\0]/g, (c) => "\\" + c.charCodeAt(0).toString(16).padStart(2, "0"));
const filter = `(&(objectClass=user)(sAMAccountName=${escapeFilter(username)}))`;
```

| Input | ❌ Unescaped filter | Result |
|---|---|---|
| `*` | `(sAMAccountName=*)` | Matches **everyone**; the code takes the first one |
| `Priya*)(salary=2*` | `(&(objectClass=user)(cn=Priya*)(salary=2*))` | 1 result if Priya's salary starts with 2, else 0. Repeat per digit → **the whole salary** |
| `(` | `(cn=()` | Broken filter, server error |

With `escapeFilter`, `*` becomes `\2a`, a **real** star character, and matches nobody. It's the same idea as SQL parameters (topic 56): **input is data, never code**. In `ldapts` you can also build filters with `new EqualityFilter({ attribute, value })`, which escapes for you.

Ask for exactly the attributes you need and `sizeLimit: 2`. You need **exactly one** match: 0 = no user, 2 = something is wrong, fail both.

> DNs have their **own** escaping rules (RFC 4514: `,` `+` `"` `\` `<` `>` `;`). Never build a DN from user input; take it from the search result.

---

### Step 4: Bind as the user, on a new connection

```js
const userClient = new Client({ url: LDAP_URL, tlsOptions });
try {
  await userClient.bind(entry.dn, password);       // AD checks the password
} catch (e) {
  // AD error 49 says WHY in "data XXX". Log it, don't show it.
  return fail();                                    // always "Wrong username or password"
} finally {
  await userClient.unbind();
}
```

| AD `data` code | Meaning | Show the user? |
|---|---|---|
| `52e` | Wrong password | ❌ generic message |
| `525` | User not found | ❌ generic message |
| `533` | Account **disabled** | ❌ AD sends it only if the password was right, so it confirms the password |
| `775` | Account **locked** | ❌ |
| `532` / `773` | Password expired / must change | Maybe: "please change your password in Windows first" (the password was right) |

**Why a new connection?** If you bind the shared service connection as the user, it **becomes** the user (or anonymous, after an empty password), and the next search of some other request runs with the wrong identity.

---

### Step 5: AD groups → app roles (nested!)

```js
const GROUP_ROLES = {
  "CN=Portal-Users,OU=Groups,DC=chaicorp,DC=local": "user",
  "CN=Portal-Admins,OU=Groups,DC=chaicorp,DC=local": "admin",
};
```

- Match on the **full DN**, not on the name. Anyone who can create a group in some other OU could name it `Portal-Admins`.
- `memberOf` lists only **direct** groups. Priya is in IT-Leads → which is in Portal-Admins → which is in Portal-Users. Either walk the chain (our demo) or let AD do it with the "in chain" matching rule:
  ```
  (&(objectClass=user)(sAMAccountName=priya)(memberOf:1.2.840.113556.1.4.1941:=CN=Portal-Admins,OU=Groups,DC=chaicorp,DC=local))
  ```
- A correct password is **not** permission. Neha from Finance has a valid AD account but no Portal-Users group → `403`.

---

### Step 6: Just-in-time (JIT) local user

Your app still needs a local `users` row (for foreign keys, preferences, audit logs). Create it on **first login**:

| ✅ Key by | ❌ Not by |
|---|---|
| `objectGUID` (never changes) | `sAMAccountName` (renamed after marriage, reused when someone new joins with the same name) |
| Refresh name, email, roles from AD on every login | Copy once and never update |
| **No password column** | Caching the AD password "for offline login" |

---

### Step 7 and 8: Your own session, and follow AD when it changes

After login the app gives its **own** session cookie (topic 09, 10). Don't send the AD password again on every request.

But when IT disables Amit, his **already open** session must die too:

- Re-check the account (`userAccountControl`, still exists) every few minutes, **or**
- Get a push from IT's system with **SCIM** (topic 62), **or**
- Keep sessions short (a working day)

Our demo re-checks on every request; disabling Priya in AD kills her live session on the next click.

---

### LDAP login vs SSO

| | LDAP bind (this topic) | SSO with SAML / OIDC (topics 57-60) |
|---|---|---|
| Who sees the password? | **Your app** (then forwards it to AD) | Only the IdP (ADFS, Entra ID, Okta, Keycloak) |
| MFA | Not built in | Built in at the IdP |
| Network | App must reach the Domain Controller | Only browser redirects |
| Where it fits | Internal tools on the company network, legacy apps | New apps, SaaS, anything on the internet |

Modern advice: if the company has an IdP, use **OIDC/SAML**, and let the IdP talk LDAP/Kerberos (topic 64) to AD. Use direct LDAP bind for internal tools when SSO isn't available.

---

### 🤔 Tricky parts

**1. Empty password = success.** Already covered, but it's in real CVEs for real products. Test it.

**2. Lockout is a weapon.** No rate limit on your login form = anyone can lock the CEO out of their laptop. Keep your limit **below** AD's threshold.

**3. 533 means "right password".** AD returns disabled/expired/locked codes only after the password check, so showing them confirms a guessed password. Log them, show the generic message.

**4. Escaping is for filters, not DNs.** Filter escaping (`\2a`) and DN escaping (`\,`) are different. Use the DN from the search result instead of building one.

**5. Search base and scope.** Search `OU=People`, not the whole domain, or service accounts and admins can be found and logged in as.

**6. Enabled vs locked vs expired** are separate states in AD. A disabled account still exists in search results, so don't treat "found" as "allowed".

**7. Referrals and multiple domains.** Big companies have several domains; you may need the Global Catalog (3269) and `userPrincipalName` instead of `sAMAccountName`.

**8. Timing (topic 51).** "No such user" skips the bind and answers faster. A careful app binds against a dummy DN too.

---

### Common beginner mistakes

1. **Letting an empty password reach `bind()`.** Unauthenticated bind succeeds as anonymous. Reject it first.

2. **Building filters with template strings.** Escape with `escapeFilter` / `EqualityFilter`.

3. **Plain `ldap://` on 389.** Use `ldaps://` (636) and trust the company CA. Never `rejectUnauthorized: false`.

4. **Binding the shared service connection as the user.** Use a new connection per login.

5. **Service account is a Domain Admin.** Give it read-only access to the attributes you need.

6. **Showing raw AD errors** ("data 52e", "data 533"). Log them, show "Wrong username or password".

7. **No app-level failure limit**, so your form locks employees out of everything.

8. **Matching groups by name, or ignoring nested groups.** Use full DNs, resolve the chain.

9. **Keying local users by username.** Use `objectGUID`.

10. **Never re-checking AD after login**, so a fired employee keeps a working session for days.

---

### Interview questions

1. **What's the difference between LDAP and Active Directory?**
   AD is Microsoft's directory service (users, groups, computers, policies, plus Kerberos and DNS). LDAP is the protocol used to read and authenticate against a directory, AD included. OpenLDAP and FreeIPA are other LDAP directories.

2. **How does an app authenticate a user with LDAP?**
   Search, then bind: bind with a service account, search for the user's DN with an escaped filter (exactly one result), then bind as that DN with the user's password on a new connection. Success means the password is correct.

3. **Why not build the DN directly from the username and bind?**
   Usernames don't map cleanly to DNs (the CN is usually the full name, users live in different OUs), and building DNs from input invites injection. Searching also lets you check groups and account state.

4. **What is an unauthenticated bind and why is it dangerous?**
   A simple bind with a DN and an empty password. Servers treat it as anonymous and return success, so an app that treats "bind succeeded" as "password correct" logs anyone in with a blank password.

5. **What is LDAP injection and how do you prevent it?**
   User input changes the meaning of a search filter, for example `*` matching everyone or `)(attr=x*` adding conditions to leak data. Escape `\ * ( ) NUL` as `\5c \2a \28 \29 \00` (RFC 4515), allowlist input, and limit search base and attributes.

6. **How do you map AD groups to roles?**
   Map full group DNs to roles, resolve nested groups (walk `memberOf` or use the matching rule `1.2.840.113556.1.4.1941`), and require a specific group to use the app at all.

7. **How do you make sure a disabled employee loses access?**
   AD refuses their bind at the next login; for open sessions, re-check the account periodically, receive SCIM deprovisioning events, and keep sessions short.

8. **Why does your app need its own rate limit when AD has lockout?**
   Every failed bind counts toward AD lockout, which locks the account everywhere. An attacker can use your form to lock people out. Your limit must trigger before AD's.

9. **LDAP bind or SAML/OIDC for a new app?**
   SAML/OIDC: the app never sees the password, MFA and SSO come for free, and it works over the internet. Direct LDAP is for internal or legacy apps.

---

### Quick recap

- AD = the company's directory; LDAP = how apps **search** and **bind** against it
- Login = service account **searches** (escaped filter, exactly one result) → **bind as the user** on a new connection
- **Reject empty passwords**; use **`ldaps://`**; least-privilege service account
- Generic error to the user, AD `data` code to the logs; app limit **below** AD lockout
- **Groups by full DN, nested** → roles; no Portal-Users group → 403
- JIT local user keyed by **`objectGUID`**, own session, re-check AD or use **SCIM** (topic 62)
- Prefer **SSO** (topics 57-60) when there is an IdP; Kerberos is next (topic 64)

## Code

A small **Express** app, **ChaiPortal**, the internal portal of ChaiCorp. Its users live in a **fake Active Directory** inside the same file (Part A), with real DNs, search filters, bind results, AD error codes and lockout, so the app code (Part B) looks like real LDAP code. A real app talks to a real Domain Controller with `ldapts` instead.

| ❌ Vulnerable | Bug | ✅ Safe |
|---|---|---|
| `POST /vulnerable/login` | Plain `ldap://`, unescaped filter, empty password accepted, raw AD errors, no failure limit | `POST /login` |
| `GET /vulnerable/people?q=` | Unescaped filter (blind injection), whole domain, no login | `GET /people?q=` |

Plus `GET /me`, `GET /admin` (needs AD group Portal-Admins) and a demo-only `POST /demo/ad/disable/:username` that pretends IT disabled an account in AD.

| AD user | Password | Groups | Notes |
|---|---|---|---|
| `priya` | `masala-dosa-77` | IT-Leads → Portal-Admins → Portal-Users | admin through **nested** groups |
| `rahul` | `chai-and-code-42` | Engineering → Portal-Users | normal user |
| `amit` | `old-pass-123` | Engineering | **disabled** (left the company) |
| `neha` | `ledger-and-tea-9` | Finance | valid AD account, **not** allowed in ChaiPortal |

Everything is in memory, so a restart resets it (including lockouts and the app's failure counters). A self-check of the filter parser and escaping runs on every start.

📄 **Full code: [server.js](server.js)**. Open it and read the comments, which follow the same steps as the notes above.

Install Express once (from this folder), then start the server:

```bash
npm install
```

```bash
node server.js
```

> Port 3000 busy? Run it on another port: `PORT=3063 node server.js` (Git Bash). The outputs below were recorded on port 3063.

On start the terminal already shows why `ldap://` is a problem: the vulnerable side's service account bind is printed by the "sniffer".

```
🔒 ldaps://dc1.chaicorp.local:636: bind for "CN=svc-chaiportal,OU=Service Accounts,DC=chaicorp,DC=local" travels inside TLS, a sniffer sees only encrypted bytes
👀 Sniffer on the network (ldap://dc1.chaicorp.local:389) sees: BindRequest dn="CN=svc-chaiportal,OU=Service Accounts,DC=chaicorp,DC=local" password="N41P31iMtpxfRUsC61jPAgc8"
🏢 ChaiPortal on http://localhost:3063, users come from the (fake) AD domain chaicorp.local
```

### Try it with curl (Git Bash)

```bash
APP=http://localhost:3063
```

❌ **① The vulnerable login works for Rahul**, and the sniffer in the server terminal prints his password:

```bash
curl -s $APP/vulnerable/login -H "Content-Type: application/json" -d '{"username":"rahul","password":"chai-and-code-42"}'
```
→ `{"message":"Welcome, Rahul Verma","groups":["CN=Engineering,OU=Groups,DC=chaicorp,DC=local"]}`
```
👀 Sniffer on the network (ldap://dc1.chaicorp.local:389) sees: BindRequest dn="CN=Rahul Verma,OU=People,DC=chaicorp,DC=local" password="chai-and-code-42"
```

😱 **② Empty password = unauthenticated bind = "success".** Then `*` picks the first user in the directory, the IT Lead:

```bash
curl -s $APP/vulnerable/login -H "Content-Type: application/json" -d '{"username":"rahul","password":""}'
curl -s $APP/vulnerable/login -H "Content-Type: application/json" -d '{"username":"*","password":""}'
```
→
```
{"message":"Welcome, Rahul Verma","groups":["CN=Engineering,OU=Groups,DC=chaicorp,DC=local"]}
{"message":"Welcome, Priya Sharma","groups":["CN=IT-Leads,OU=Groups,DC=chaicorp,DC=local"]}
```

❌ **③ Raw AD errors tell the attacker everything:** no such user, wrong password, and "account disabled" (which also means **the password was right**):

```bash
curl -s $APP/vulnerable/login -H "Content-Type: application/json" -d '{"username":"ghost","password":"x"}'
curl -s $APP/vulnerable/login -H "Content-Type: application/json" -d '{"username":"rahul","password":"x"}'
curl -s $APP/vulnerable/login -H "Content-Type: application/json" -d '{"username":"amit","password":"old-pass-123"}'
```
→
```
{"error":"No such user"}
{"error":"80090308: LdapErr: DSID-0C09044E, comment: AcceptSecurityContext error, data 52e, v4563"}
{"error":"80090308: LdapErr: DSID-0C09044E, comment: AcceptSecurityContext error, data 533, v4563"}
```

❌ **④ The vulnerable people search**, no login needed. `*` lists the whole domain, including the service account and the ex-employee:

```bash
curl -s -G $APP/vulnerable/people --data-urlencode "q=Rahul Verma"
curl -s -G $APP/vulnerable/people --data-urlencode "q=*"
```
→
```
[{"dn":"CN=Rahul Verma,OU=People,DC=chaicorp,DC=local","cn":"Rahul Verma","mail":"rahul@chaicorp.in","department":"Engineering","title":"Backend Developer"}]
[{"dn":"CN=Priya Sharma,…","cn":"Priya Sharma",…},{"dn":"CN=Rahul Verma,…"},{"dn":"CN=Amit Patel,…","title":"Ex-employee"},{"dn":"CN=Neha Gupta,…"},{"dn":"CN=svc-chaiportal,OU=Service Accounts,DC=chaicorp,DC=local","cn":"svc-chaiportal",…,"title":"Service account"}]
```

😈 **⑤ Blind LDAP injection.** The search never returns `salary`, but Vikram can add his own condition and watch "1 result / 0 results":

```bash
curl -s -G $APP/vulnerable/people --data-urlencode "q=Priya*)(salary=2*"
curl -s -G $APP/vulnerable/people --data-urlencode "q=Priya*)(salary=1*"
```
→
```
[{"dn":"CN=Priya Sharma,OU=People,DC=chaicorp,DC=local","cn":"Priya Sharma","mail":"priya@chaicorp.in","department":"IT","title":"IT Lead"}]
[]
```

So the salary starts with 2. Automate it, one digit at a time:

```bash
KNOWN=""
while true; do
  FOUND=""
  for d in 0 1 2 3 4 5 6 7 8 9; do
    if curl -s -G $APP/vulnerable/people --data-urlencode "q=Priya*)(salary=$KNOWN$d*" | grep -q '"dn"'; then FOUND=$d; break; fi
  done
  [ -z "$FOUND" ] && break
  KNOWN="$KNOWN$FOUND"; echo "Priya's salary starts with $KNOWN"
done
```
→
```
Priya's salary starts with 2
Priya's salary starts with 24
Priya's salary starts with 247
Priya's salary starts with 2475
Priya's salary starts with 24750
Priya's salary starts with 247500
Priya's salary starts with 2475000
```
₹24,75,000 in about 45 requests.

✅ **⑥ The safe login blocks bad input and gives one generic error.** An empty password never reaches AD; `*` isn't a valid username; unknown user, wrong password and disabled account all look the same:

```bash
curl -s -w " %{http_code}\n" $APP/login -H "Content-Type: application/json" -d '{"username":"rahul","password":""}'
curl -s -w " %{http_code}\n" $APP/login -H "Content-Type: application/json" -d '{"username":"*","password":"x"}'
curl -s -w " %{http_code}\n" $APP/login -H "Content-Type: application/json" -d '{"username":"ghost","password":"x"}'
curl -s -w " %{http_code}\n" $APP/login -H "Content-Type: application/json" -d '{"username":"amit","password":"old-pass-123"}'
```
→
```
{"error":"Password is required"} 400
{"error":"Username can only use letters, digits, dot, dash and underscore"} 400
{"error":"Wrong username or password"} 401
{"error":"Wrong username or password"} 401
```
The real reason goes to the server log only, and the bind went over TLS:
```
🔐 login failed for "ghost": no such user (the user only sees "Wrong username or password")
🔒 ldaps://dc1.chaicorp.local:636: bind for "CN=Amit Patel,OU=People,DC=chaicorp,DC=local" travels inside TLS, a sniffer sees only encrypted bytes
🔐 login failed for "amit": AD said data 533 = account disabled (the user only sees "Wrong username or password")
```

✅ **⑦ Rahul logs in.** JIT creates his local user on first login (keyed by `objectGUID`); he's a `user`, not an `admin`:

```bash
curl -s -c rahul.txt $APP/login -H "Content-Type: application/json" -d '{"username":"rahul","password":"chai-and-code-42"}'
curl -s -b rahul.txt $APP/me
curl -s -b rahul.txt -w " %{http_code}\n" $APP/admin
```
→
```
{"message":"Welcome, Rahul Verma","roles":["user"]}
{"id":"7e82331e-4d44-4b32-8321-7d0f50e3d241","adGuid":"f683f423-6a9a-4aac-ae85-05efd63615c2","createdAt":"2026-11-06T06:33:04.321Z","username":"rahul","name":"Rahul Verma","roles":["user"],"lastLoginAt":"2026-11-06T06:33:04.322Z"}
{"error":"Admins only (AD group Portal-Admins)"} 403
```
Server terminal: `🆕 JIT: created local user 7e82331e-… for CN=Rahul Verma,OU=People,DC=chaicorp,DC=local`

✅ **⑧ Priya is an admin through nested groups** (IT-Leads → Portal-Admins → Portal-Users). Usernames are case-insensitive, like in AD:

```bash
curl -s -c priya.txt $APP/login -H "Content-Type: application/json" -d '{"username":"Priya","password":"masala-dosa-77"}'
curl -s -b priya.txt $APP/admin
```
→
```
{"message":"Welcome, Priya Sharma","roles":["user","admin"]}
{"message":"🛠️ Admin panel","localUsers":["rahul","priya"]}
```

🚫 **⑨ Right password, wrong group.** Neha from Finance isn't in Portal-Users:

```bash
curl -s -w " %{http_code}\n" $APP/login -H "Content-Type: application/json" -d '{"username":"neha","password":"ledger-and-tea-9"}'
```
→ `{"error":"Your account isn't allowed to use ChaiPortal. Ask IT to add you to Portal-Users."} 403`

✅ **⑩ The safe people search** needs a login, and the injection is now just text that matches nobody:

```bash
curl -s -w " %{http_code}\n" -G $APP/people --data-urlencode "q=Pri"
curl -s -b rahul.txt -G $APP/people --data-urlencode "q=Pri"
curl -s -b rahul.txt -G $APP/people --data-urlencode "q=Priya*)(salary=2*"
```
→
```
{"error":"Log in first"} 401
[{"name":"Priya Sharma","mail":"priya@chaicorp.in","title":"IT Lead","department":"IT"}]
[]
```

🧹 **⑪ IT disables Priya in AD.** Her open session dies on the next request, and she can't log in again:

```bash
curl -s -X POST $APP/demo/ad/disable/priya
curl -s -b priya.txt -w " %{http_code}\n" $APP/me
curl -s -w " %{http_code}\n" $APP/login -H "Content-Type: application/json" -d '{"username":"priya","password":"masala-dosa-77"}'
```
→
```
{"message":"AD: CN=Priya Sharma,OU=People,DC=chaicorp,DC=local is now disabled (userAccountControl=514)"}
{"error":"Your account was disabled or removed. Log in again."} 401
{"error":"Wrong username or password"} 401
```

😈 **⑫ Lockout as a weapon.** Vikram sends 5 wrong passwords for Neha through the vulnerable login. AD locks her account, so now even her **real** password fails (on her laptop and email too):

```bash
for i in 1 2 3 4 5; do curl -s $APP/vulnerable/login -H "Content-Type: application/json" -d "{\"username\":\"neha\",\"password\":\"guess$i\"}" | grep -o 'data [0-9a-f]*'; done
curl -s $APP/vulnerable/login -H "Content-Type: application/json" -d '{"username":"neha","password":"ledger-and-tea-9"}'
```
→
```
data 52e
data 52e
data 52e
data 52e
data 52e
{"error":"80090308: LdapErr: DSID-0C09044E, comment: AcceptSecurityContext error, data 775, v4563"}
```

✅ **⑬ The safe login stops at 3**, before AD's 5. Rahul is blocked from ChaiPortal for 15 minutes, but his AD account is **not** locked (the vulnerable login, standing in for his Windows login, still works):

```bash
for p in guess1 guess2 guess3 chai-and-code-42; do curl -s -w " %{http_code}\n" $APP/login -H "Content-Type: application/json" -d "{\"username\":\"rahul\",\"password\":\"$p\"}"; done
curl -s $APP/vulnerable/login -H "Content-Type: application/json" -d '{"username":"rahul","password":"chai-and-code-42"}'
```
→
```
{"error":"Wrong username or password"} 401
{"error":"Wrong username or password"} 401
{"error":"Wrong username or password"} 401
{"error":"Too many attempts. Try again in 15 minutes."} 429
{"message":"Welcome, Rahul Verma","groups":["CN=Engineering,OU=Groups,DC=chaicorp,DC=local"]}
```

> **Windows PowerShell users:** the single quotes in `-d '...'`, the loops and `VAR=value node ...` work in Git Bash. In PowerShell, use Git Bash or Postman, or set the port with `$env:PORT=3063; node server.js`. Restart the server to reset the directory, lockouts and failure counters. Delete `rahul.txt` and `priya.txt` (the cookie jars) when you're done.
