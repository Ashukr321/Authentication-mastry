# 65. Multi-Tenant Auth

## Notes

### What is multi-tenant auth?

A **multi-tenant** app is one app (one codebase, usually one database) that many **companies** use at the same time. Each company is a **tenant** (also called a workspace, organization, account or realm). Slack workspaces, Jira sites, Zoho organizations and Shopify stores are all tenants.

**Multi-tenant auth** answers two questions on every request, not one:

1. **Who are you?** (authentication, like every topic so far)
2. **Which company are you acting for, and are you allowed in it?** (tenant isolation)

> **One-line answer:** Work out the tenant from something the server trusts (the subdomain, or the tenant inside the token), make every token belong to **one** tenant, check on every request that the token's tenant **is** the request's tenant and that the user is **still a member** with a role **in that tenant**, and filter **every** database query by that tenant id. Never take the tenant id from the request body or a header the client controls.

---

### Why it matters

| Problem | What goes wrong |
|---|---|
| Tenant id taken from a header, query or body (`X-Tenant: acme`) | Change one word, read another company's data |
| A query forgets `WHERE tenant_id = ?` | **Cross-tenant IDOR**: `GET /invoices/inv_102` returns another company's invoice |
| Token doesn't say which tenant it's for | A valid Zenith token also works on Acme |
| Role stored on the user, not on the membership | Admin in **one** company = admin **everywhere** |
| Correct password = logged in, without a membership check | Anyone with an account can log in to any company |
| Switching workspaces skips the target's rules | A password session "switches" into a company that requires SSO or MFA |

One leak here isn't "one user's data". It's **another customer's whole company**. That's the incident that ends B2B contracts. It's in the OWASP Top 10 as *A01: Broken Access Control*.

---

### Real-life example: the office tower 🏢

Priya is a CA (chartered accountant) in Bengaluru. She works in an office tower where many companies rent floors.

- **One building, many companies.** The lifts, the guards and the building are shared (one app, one database). Each company's floor is a **tenant**.
- **One face, many badges.** Priya has **one** identity (her face, her Aadhaar), but a **separate badge** for each floor she works on: Acme Traders (she's their **finance head = admin**), Zenith Textiles (she's a visiting **consultant = member**).
- **The badge says the floor.** Her Acme badge doesn't open Zenith's door, even though it's a real badge (the token's tenant must match).
- **The guard checks the floor list every time**, not just the badge. If Acme removes Priya from the list today, her badge stops working today (look up the membership on every request).
- **Each floor has its own rules.** Nimbus Bank on floor 9 only lets you in through **their own security desk** (SSO only). Priya can't walk up from Acme's floor and say "I'm already inside the building".
- **The filing cabinets are labelled by company.** When the peon fetches "file 102", he first checks it's from **this** floor's cabinet (`WHERE tenant_id = ?`). Vikram from Zenith asking for "file 102" gets "no such file".

---

### The big picture

#### 📊 Diagrams

Open **[diagrams.html](diagrams.html)** in your browser (just double-click the file) to see:

- **Flow diagram**: every check a request goes through, from the subdomain to the database filter
- **Data flow (attacks)**: Vikram tries a cross-tenant token, a forged `X-Tenant` header and a cross-tenant IDOR
- **Data flow (switching)**: Priya logs in to Acme, lists her workspaces, switches to Zenith and is refused by Nimbus

In short: `subdomain → tenant` · `token → user + tenant` · `token tenant == request tenant?` · `still a member? which role here?` · `query WHERE tenant_id = this tenant`.

#### The three ways to model tenants

| Model | How it works | Used by | Trade-off |
|---|---|---|---|
| **Global user + memberships** (our demo) | One account per person, a `memberships(tenant_id, user_id, role)` table | Slack, GitHub orgs, Notion, Auth0 Organizations | One login for many companies; you **must** check the membership everywhere |
| **User pool per tenant** | Each tenant has its own users table/realm; the same email can be two unrelated accounts | Keycloak realms, AWS Cognito pool per tenant, Azure AD B2C | Strong separation; a person in 3 companies has 3 passwords |
| **Tenant from the IdP** | Each company brings its own Okta/Azure AD; the token's `tid`/`iss` says which company | Azure AD multi-tenant apps, B2B SaaS with SSO (topics 57–60) | Best for enterprises; you must map `iss`/`tid` to **your** tenant and never trust "any Azure AD tenant" |

#### How tenant info travels

| Where | Example | Trust it? |
|---|---|---|
| Subdomain | `acme.app.com` | ✅ As a **lookup key** (must match a known tenant), then checked against the token |
| Path | `app.com/t/acme/...` | ✅ Same as subdomain |
| Token claim | `tid` (Azure AD), `org_id` (Auth0), `tenant_id` (custom) | ✅ It's **signed** (JWT) or stored on the server (opaque token) |
| Header / query / body | `X-Tenant: acme`, `?tenantId=t_1` | ❌ Never on its own. The client writes it |

---

### Step 1: Give every tenant an id, and every row a `tenant_id`

```js
tenants:     { id: "t_1", slug: "acme", name: "Acme Traders", status: "active", policy: {...} }
memberships: "t_1:<priya's id>" -> "admin"
invoices:    { id: "inv_102", tenantId: "t_1", customer: "Gupta & Sons", amount: "₹1,20,000" }
```

- The **id** (`t_1`) never changes. The **slug** (`acme`) is for URLs and can be renamed.
- **Every** tenant-owned table gets a `tenant_id` column, part of indexes and unique keys (`UNIQUE(tenant_id, invoice_number)`).
- Roles live on the **membership**, not the user. Priya has one user row and two different roles.

---

### Step 2: Work out the tenant from something you trust

```js
const slug = host.endsWith(".localhost") ? host.slice(0, -".localhost".length) : null;
const tenant = slug && tenantBySlug(slug);
if (!tenant) return res.status(404).json({ error: "Unknown workspace" });
```

| ✅ Do | ❌ Don't |
|---|---|
| Treat the subdomain as a **lookup key**: unknown slug → 404 | Build links or emails from the raw `Host` header (host header injection) |
| Behind a proxy, trust `X-Forwarded-Host` **only** from your own proxy (`trust proxy`) | Read `X-Tenant` / `?tenant=` and use it as the answer |
| Reserve slugs like `www`, `api`, `admin`, `login` | Let a customer register the slug `admin` |

---

### Step 3: One token = one tenant, checked on every request

```js
if (s.tenantId !== req.tenant.id) return res.status(401).json({ error: "This token is for a different workspace" });
const role = roleIn(s.tenantId, s.userId);       // looked up NOW, not copied into the token
if (!role) return res.status(403).json({ error: "You are no longer a member of this workspace" });
```

- With JWTs the tenant is a **claim** (`"tid": "t_1"`) and the **audience** can be per tenant (topic 27). Check it the same way.
- Look the **role and membership up per request** (or keep the token very short-lived). A role copied into a 7-day JWT survives "remove from workspace" for 7 days.
- Cookies: use **host-only** cookies (no `Domain=`), so `acme.app.com`'s cookie is never sent to `zenith.app.com`. A `Domain=app.com` cookie is shared by **every** tenant, including a tenant controlled by an attacker (topic 10).

---

### Step 4: Login is per tenant

```js
if (!user || !roleIn(req.tenant.id, user.id)) return res.status(401).json({ error: "Wrong email or password" });
```

A correct password only proves **who** you are. Logging in to `acme` also needs a membership in `acme`. Use the **same** error as a wrong password so outsiders can't find out "Vikram works at Zenith, not Acme" (topic 51).

---

### Step 5: Per-tenant policy, and switching workspaces

Every tenant can have its **own** security rules. Big customers will demand it:

| Policy | Example |
|---|---|
| Login methods | "Password allowed" vs "SSO only through our Azure AD" (topic 60) |
| MFA | "Required for everyone" (topic 45) |
| Session length | Acme: 8 hours, Zenith: 30 minutes |
| Allowed email domains, IP ranges | Only `@acme.in`, only office IPs |
| Status | `active`, `suspended` (unpaid bill), `deleted` |

**Switching** (`POST /switch {"tenant":"zenith"}`) issues a **new token** for the other tenant. It must check **again**: is the user a member there, is that tenant active, and does **its** policy accept how the user signed in? A password session can't be switched into an SSO-only tenant.

```js
if (!target || !roleIn(target.id, req.user.id)) return res.status(404).json({ error: "Workspace not found" });
const blocked = tenantBlocks(target); // suspended? SSO only?
```

---

### Step 6: Filter every query by the tenant

```js
// ✅ the tenant comes from requireAuth, never from the request
const inv = invoices.get(req.params.id);
if (!inv || inv.tenantId !== req.tenant.id) return res.status(404).json({ error: "Invoice not found" });
```

In SQL: `SELECT * FROM invoices WHERE id = $1 AND tenant_id = $2`.

| ✅ Do | ❌ Don't |
|---|---|
| Put the tenant filter in **one** place: a repository / ORM scope / middleware | Remember to add `tenant_id` by hand in 200 queries |
| Add **Row-Level Security** in Postgres (`SET app.tenant_id`, a policy on every table) as a second lock | Rely on "the UI never shows other tenants' ids" |
| Return **404** for another tenant's row | Return 403 ("it exists, you just can't see it") |
| Use random ids (UUIDs) too, but as an extra, not the fix | Think UUIDs alone stop IDOR |
| Tag caches, queues, file paths and search indexes with the tenant (`cache:t_1:report`) | Cache `report:2026-11` for everyone |

---

### Step 7: Roles are per tenant

```js
app.get("/members", requireAuth, requireRole("admin"), ...); // admin of THIS tenant
```

Priya is admin in Acme and a member in Zenith. `requireRole` reads `req.role`, which came from the **current tenant's** membership. Also keep a separate idea of **platform staff** (your own support team): they act across tenants through a special, audited path (impersonation, topic 67), never by being "admin" in every tenant.

---

### 🤔 Tricky parts

**1. Background jobs have no request.** A cron job that sends invoices has no subdomain and no token. Pass the tenant id **explicitly** in every job and set it before running queries. "Forgot the tenant in a job" is a top cause of cross-tenant emails.

**2. Shared lookups.** "Find user by email" across tenants is fine for login (identity is global in our model), but "search customers by name" must be tenant-filtered.

**3. Unique constraints.** Invoice number `INV-001` exists in every tenant. The unique key is `(tenant_id, number)`, not `number`.

**4. Error messages leak.** "Invoice inv_102 belongs to another workspace" confirms it exists. "Not found" for both.

**5. Signing keys.** One signing key for all tenants is normal. If a tenant can bring its own IdP (topic 60), check that the token's issuer is **that tenant's** IdP. A token from Zenith's Azure AD must never log someone in to Acme. (A famous bug class: apps that accepted tokens from **any** Azure AD tenant.)

**6. Removal must work now.** Our demo deletes the removed user's tokens **and** checks the membership on every request, so Rahul's token dies immediately.

**7. Suspended tenants.** Check `status` on every request, not only at login. Otherwise tokens issued yesterday keep working after the account is suspended.

---

### Common beginner mistakes

1. **Trusting a tenant id from the client** (`X-Tenant`, `?tenantId`, a field in the JSON body).
2. **Forgetting `AND tenant_id = ?`** in one query. One is enough for a data breach.
3. **Tokens without a tenant**, or not comparing the token's tenant with the request's tenant.
4. **One global role** (`user.isAdmin`) instead of a role per membership.
5. **Not checking membership at login** (or at switch).
6. **Copying the role into a long-lived JWT** and never re-checking it.
7. **`Domain=.app.com` session cookies** shared by every tenant subdomain.
8. **Cache keys, file paths, S3 prefixes without the tenant id.**
9. **Background jobs and webhooks that forget the tenant.**
10. **Returning 403 for another tenant's object**, which confirms it exists.

---

### Interview questions

1. **What is multi-tenancy, and what's special about auth in it?**
   One app serves many customer organizations. Besides "who are you", every request must answer "which tenant, and are you a member of it with which role", and every data access must be scoped to that tenant.

2. **How do you identify the tenant on a request?**
   From the subdomain or path (as a lookup key validated against known tenants) and from the tenant inside the authenticated token. Then check they match. Never from a client-supplied header or body field alone.

3. **How do you prevent one tenant from seeing another's data?**
   A `tenant_id` on every tenant-owned row, filtered in every query through one central layer, with Postgres Row-Level Security (or separate schemas/databases) as defense in depth. Return 404 for other tenants' rows. Scope caches, files and jobs by tenant too.

4. **Shared database, schema per tenant, or database per tenant?**
   Shared tables with `tenant_id` are cheapest and scale to many small tenants but rely on correct filtering. Schema per tenant isolates better with more migration work. Database per tenant isolates best (and suits data-residency or big enterprise customers) but costs the most to run. Many SaaS apps mix: shared for small tenants, dedicated for large ones.

5. **A user belongs to several tenants. How do tokens work?**
   Global identity plus memberships. Each token is issued for one tenant (a `tid`/`org_id` claim). Switching tenants issues a new token after re-checking membership, tenant status and the target tenant's policy (SSO, MFA).

6. **Where do roles live?**
   On the membership (`tenant_id`, `user_id`, `role`), so a user can be admin in one tenant and member in another. Platform staff access is a separate, audited mechanism.

7. **What happens when an admin removes a user from a tenant?**
   The membership row is deleted, and because membership is checked on every request (or tokens are short-lived / revoked), the user's access to that tenant ends immediately. Their access to other tenants is untouched.

8. **How do enterprise SSO and multi-tenancy fit together?**
   Each tenant can configure its own IdP. Map the IdP's issuer (and `tid`) to your tenant, accept tokens only from that tenant's issuer, and enforce "SSO only" in that tenant's policy (topics 57–60, SCIM for provisioning in topic 62).

---

### Quick recap

- **Tenant** = a customer company. One app, many tenants, isolated from each other
- Tenant comes from the **subdomain/path** (as a lookup key) and the **token**; they must **match**
- **Never** trust `X-Tenant`, `?tenantId` or a body field
- **Login and switch** check membership, tenant status and the tenant's **own policy**
- **Roles per membership**, looked up on every request, so removal works instantly
- **Every query** has `AND tenant_id = ?`; other tenants' rows are **404**; add RLS as a second lock
- Scope **cookies, caches, files, jobs** by tenant too
- Next: build your own authorization server (topic 66)

## Code

A small B2B invoicing app with four tenants, each on its own subdomain:

| Tenant | URL | Policy |
|---|---|---|
| Acme Traders | `acme.localhost` | Password login, 8-hour tokens |
| Zenith Textiles | `zenith.localhost` | Password login, 30-minute tokens |
| Nimbus Bank | `nimbus.localhost` | **SSO only** (password login refused) |
| OldCo | `oldco.localhost` | **Suspended** |

People: **Priya** (admin in Acme, member in Zenith and Nimbus), **Rahul** (member in Acme), **Vikram** (admin in Zenith, our attacker), **Meera** (admin in OldCo).

| | ❌ Vulnerable | ✅ Safe |
|---|---|---|
| Which tenant's invoices? | `GET /vulnerable/invoices` trusts the `X-Tenant` header | `GET /invoices` uses the token's tenant, which must match the subdomain |
| One invoice by id | `GET /vulnerable/invoices/:id` looks up by id only | `GET /invoices/:id` also checks `tenantId`, 404 otherwise |

Plus `POST /login`, `GET /me`, `GET /workspaces`, `POST /switch`, `GET /members` and `DELETE /members/:email` (admins only), and `POST /logout`. Tokens are random opaque bearer tokens, stored as `sha256` with their tenant. Everything is in memory, so a restart resets it.

📄 **Full code: [server.js](server.js)**. Open it and read the comments, which follow the same steps as the notes above.

Install Express once (from this folder), then start the server:

```bash
npm install
```

```bash
node server.js
```

> Port 3000 busy? Run it on another port: `PORT=3065 node server.js` (Git Bash). The outputs below were recorded on port 3065.

`*.localhost` always points to your own machine (in curl and in browsers), so `acme.localhost:3065` works without editing any hosts file.

### Try it (Git Bash)

```bash
ACME=http://acme.localhost:3065
ZEN=http://zenith.localhost:3065
J="Content-Type: application/json"
tok() { grep -o '"token":"[^"]*"' | cut -d'"' -f4; }
```

`tok` pulls the token out of a login reply. `tee` shows the reply and saves it to a file at the same time.

#### Part A: logging in to a tenant

🏢 **① Unknown subdomains are refused.** The subdomain must be a tenant we know:

```bash
curl -s http://evil.localhost:3065/me
```
→ `{"error":"Unknown workspace"}`

🔑 **② Priya logs in to Acme.** The token is for Acme only, and lives 8 hours (Acme's policy):

```bash
curl -s $ACME/login -H "$J" -d '{"email":"priya@acme.in","password":"priya-pass-2026"}' | tee priya.json
PRIYA=$(tok < priya.json)
curl -s $ACME/me -H "Authorization: Bearer $PRIYA"
curl -s $ACME/invoices -H "Authorization: Bearer $PRIYA"
```
→
```
{"token":"nQ6hAWHNI32vcAnqEuU93yskw3C67nPfma97fyRqWu0","tenant":"acme","role":"admin","expiresAt":"2026-11-06T10:35:49.511Z"}
{"email":"priya@acme.in","tenant":"acme","tenantName":"Acme Traders","role":"admin"}
{"tenant":"acme","invoices":[{"id":"inv_101","tenantId":"t_1","customer":"Sharma Stores","amount":"₹45,000"},{"id":"inv_102","tenantId":"t_1","customer":"Gupta & Sons","amount":"₹1,20,000"}]}
```

🚫 **③ Vikram's password is correct, but he isn't an Acme member.** Same error as a wrong password:

```bash
curl -s $ACME/login -H "$J" -d '{"email":"vikram@zenith.in","password":"vikram-pass-2026"}'
```
→ `{"error":"Wrong email or password"}` (401)

#### Part B: Vikram attacks Acme from Zenith 😈

```bash
curl -s $ZEN/login -H "$J" -d '{"email":"vikram@zenith.in","password":"vikram-pass-2026"}' | tee vik.json
VIK=$(tok < vik.json)
```
→ `{"token":"twfpWfHpKICot_3NTfgTSCPy6ABaHnY3EcNBnnwDMdQ","tenant":"zenith","role":"admin","expiresAt":"2026-11-06T03:05:50.601Z"}` (30 minutes: Zenith's policy)

✅ **④ His real Zenith token on Acme's subdomain:** valid token, wrong tenant:

```bash
curl -s $ACME/invoices -H "Authorization: Bearer $VIK"
```
→ `{"error":"This token is for a different workspace"}` (401)

❌ **⑤ The vulnerable route trusts the `X-Tenant` header.** Vikram writes "acme" and reads Acme's invoices:

```bash
curl -s $ZEN/vulnerable/invoices -H "Authorization: Bearer $VIK" -H "X-Tenant: acme"
```
→ `{"tenant":"acme","invoices":[{"id":"inv_101","tenantId":"t_1","customer":"Sharma Stores","amount":"₹45,000"},{"id":"inv_102","tenantId":"t_1","customer":"Gupta & Sons","amount":"₹1,20,000"}]}`

❌ vs ✅ **⑥ Cross-tenant IDOR.** Vikram guesses Acme's invoice id `inv_102`. The vulnerable route looks it up by id alone; the safe route adds the tenant check and answers 404. His own invoice still works:

```bash
curl -s $ZEN/vulnerable/invoices/inv_102 -H "Authorization: Bearer $VIK"
curl -s $ZEN/invoices/inv_102 -H "Authorization: Bearer $VIK"
curl -s $ZEN/invoices/inv_201 -H "Authorization: Bearer $VIK"
```
→
```
{"id":"inv_102","tenantId":"t_1","customer":"Gupta & Sons","amount":"₹1,20,000"}
{"error":"Invoice not found"}
{"id":"inv_201","tenantId":"t_2","customer":"Mehta Fabrics","amount":"₹8,500"}
```

#### Part C: one person, many workspaces

📋 **⑦ Priya's workspace picker, then a switch to Zenith.** The new token is for Zenith, with her **Zenith** role:

```bash
curl -s $ACME/workspaces -H "Authorization: Bearer $PRIYA"
curl -s $ACME/switch -H "Authorization: Bearer $PRIYA" -H "$J" -d '{"tenant":"zenith"}' | tee pz.json
PZ=$(tok < pz.json)
```
→
```
{"workspaces":[{"tenant":"acme","name":"Acme Traders","role":"admin","url":"http://acme.localhost:3065"},{"tenant":"zenith","name":"Zenith Textiles","role":"member","url":"http://zenith.localhost:3065"},{"tenant":"nimbus","name":"Nimbus Bank","role":"member","url":"http://nimbus.localhost:3065"}]}
{"token":"yAPJrp2Y0JgJXXfSpVJsY6m_gFpNWZVyjoImjWfYjtk","tenant":"zenith","role":"member","expiresAt":"2026-11-06T03:05:51.777Z"}
```

👔 **⑧ Roles are per tenant.** Admin in Acme, plain member in Zenith:

```bash
curl -s $ACME/members -H "Authorization: Bearer $PRIYA"
curl -s $ZEN/members -H "Authorization: Bearer $PZ"
curl -s $ZEN/invoices -H "Authorization: Bearer $PZ"
```
→
```
{"tenant":"acme","members":[{"email":"priya@acme.in","role":"admin"},{"email":"rahul@acme.in","role":"member"}]}
{"error":"Only admins of Zenith Textiles can do this"}
{"tenant":"zenith","invoices":[{"id":"inv_201","tenantId":"t_2","customer":"Mehta Fabrics","amount":"₹8,500"}]}
```

🏦 **⑨ Each tenant's policy is enforced, at switch and login too.** Nimbus is SSO only, OldCo is suspended, and Rahul isn't in Zenith:

```bash
curl -s $ACME/switch -H "Authorization: Bearer $PRIYA" -H "$J" -d '{"tenant":"nimbus"}'
curl -s http://oldco.localhost:3065/login -H "$J" -d '{"email":"meera@oldco.in","password":"meera-pass-2026"}'
curl -s $ACME/login -H "$J" -d '{"email":"rahul@acme.in","password":"rahul-pass-2026"}' | tee rahul.json
RAHUL=$(tok < rahul.json)
curl -s $ACME/switch -H "Authorization: Bearer $RAHUL" -H "$J" -d '{"tenant":"zenith"}'
```
→
```
{"error":"Nimbus Bank requires sign-in through its company SSO (topic 60)"}
{"error":"OldCo is suspended. Contact your administrator"}
{"token":"HYRmwWTk29fCPfkw8ViwcdditLrtUFaCE4lmBU0g7Sw","tenant":"acme","role":"member","expiresAt":"2026-11-06T10:35:52.699Z"}
{"error":"Workspace not found"}
```
(403, 403, 200, 404)

🚪 **⑩ Priya removes Rahul from Acme.** His Acme token stops working at once:

```bash
curl -s -X DELETE $ACME/members/rahul@acme.in -H "Authorization: Bearer $PRIYA"
curl -s $ACME/me -H "Authorization: Bearer $RAHUL"
```
→
```
{"message":"rahul@acme.in removed from Acme Traders"}
{"error":"Not signed in"}
```

👋 **⑪ Logout is per tenant too.** Logging out of Zenith leaves Priya's Acme token alone:

```bash
curl -s -X POST $ZEN/logout -H "Authorization: Bearer $PZ"
curl -s $ZEN/me -H "Authorization: Bearer $PZ"
curl -s $ACME/me -H "Authorization: Bearer $PRIYA"
```
→
```
{"message":"Logged out"}
{"error":"Not signed in"}
{"email":"priya@acme.in","tenant":"acme","tenantName":"Acme Traders","role":"admin"}
```

> **Windows PowerShell users:** the single quotes in `-d '...'`, `$(…)`, `tok() {…}` and `VAR=value node ...` work in Git Bash. In PowerShell, use Git Bash or Postman (set the URL to `http://acme.localhost:3065/...`), or set the port with `$env:PORT=3065; node server.js`. Restart the server to reset everything (Rahul is back in Acme).
