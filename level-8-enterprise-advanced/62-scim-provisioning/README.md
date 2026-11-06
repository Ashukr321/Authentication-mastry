# 62. SCIM Provisioning

## Notes

### What is SCIM?

SSO (topics 57–60) answers **"who is this person?"** at login time. It doesn't tell your app **who should have an account**, **what their name and team are today**, or **that they left the company yesterday**. SCIM does.

**SCIM** (*System for Cross-domain Identity Management*, RFC 7643 + RFC 7644) is a small, standard **REST API for users and groups**. Your app exposes it; the customer's identity provider (Okta, Microsoft Entra ID, Google Workspace, OneLogin, JumpCloud) **calls** it whenever HR changes something:

```
New hire      → POST   /scim/v2/Users
Name change   → PATCH  /scim/v2/Users/{id}
Leaves        → PATCH  /scim/v2/Users/{id}  {"active": false}   (or DELETE)
Team change   → PATCH  /scim/v2/Groups/{id} add/remove members
```

> **One-line answer:** SCIM is the standard REST API (`/scim/v2/Users`, `/scim/v2/Groups`) that lets a company's identity provider **create, update and deactivate** user accounts in your app automatically, so a person who leaves loses access **the moment IT turns them off**, not whenever someone remembers.

In SCIM words, the IdP is the **client** and your app is the **service provider**.

---

### Why it matters

| Problem without SCIM | What goes wrong |
|---|---|
| Accounts made by hand (or by an admin uploading a CSV) | New hires wait days; typos; nobody owns it |
| An employee leaves, IT disables them in Okta | SSO stops **new** logins, but their **existing session** in your app (and their API tokens) keep working |
| Only "just-in-time" (JIT) creation at first SSO login | You don't know the user exists until they log in, can't assign them work, and are never told when they leave |
| Name, email, title, team change in HR | Your app shows stale data forever |
| Roles managed in two places | Someone removed from "Admins" in Okta is still admin in your app |

Enterprise customers put **"supports SCIM"** on their security checklist next to "supports SSO". Offboarding ("leavers") is an audit requirement under SOC 2 and ISO 27001.

---

### Real-life example: the office ID card 🪪

Priya joins **TechCorp** in Bengaluru. TechCorp uses many apps, including our helpdesk app **ChaiDesk**.

- **Without SCIM:** Priya's manager emails ChaiDesk's admin: "please add Priya". Three days later she gets an account. When Priya leaves, nobody remembers ChaiDesk. Six months later her login still works.
- **With SCIM:** HR adds Priya in Okta → Okta **immediately** calls `POST /scim/v2/Users` on ChaiDesk. HR moves her into the "ChaiDesk Admins" group → Okta calls `PATCH /Groups`. On her last day IT clicks *Deactivate* → Okta calls `PATCH /Users/{id} {"active": false}` → ChaiDesk **ends her sessions** right then.

It's like the office **ID card**: the security desk doesn't keep its own list. HR's system activates and deactivates the card, and the door checks the card on **every** swipe.

---

### The big picture

#### 📊 Diagrams

Open **[diagrams.html](diagrams.html)** in your browser (just double-click the file) to see:

- **Flow diagram**: every check a SCIM request goes through in ChaiDesk, and what each result does to the user and their sessions
- **Data flow**: Priya's whole life at TechCorp (joiner → mover → leaver) as real SCIM requests between Okta, ChaiDesk and Priya's browser

In short: `HR change in IdP → IdP calls our /scim/v2 with a per-tenant bearer token → we validate + scope to that tenant → create / update / deactivate → deactivation ends sessions → SSO login checks "provisioned and active?"`.

| | SSO (topics 58, 60) | SCIM (this topic) |
|---|---|---|
| Question | Who is logging in **right now**? | Who **should** have an account, with what data and groups? |
| Who starts it | The user, by logging in | The IdP, whenever something changes |
| Direction | Browser redirects (SAML / OIDC) | Server-to-server REST calls (IdP → your app) |
| Leaver | Can't log in **again** | Account deactivated, **sessions ended now** |

You almost always want **both**: SSO for login, SCIM for the account lifecycle.

---

### Step 1: Authenticate the IdP with a per-tenant token

Every customer (tenant) gets their **own** long random token. Their IT admin pastes it into Okta / Entra ID together with your SCIM base URL (`https://chaidesk.com/scim/v2`).

```js
const m = /^Bearer ([\w-]{10,200})$/.exec(req.get("authorization") ?? "");
const tenant = m && tenants.get(sha256(m[1])); // store only the hash
if (!tenant) return scimError(res, 401, "Missing or invalid SCIM bearer token");
req.tenant = tenant;                             // THE TOKEN picks the tenant, nothing else
```

| ✅ Do | ❌ Don't |
|---|---|
| One token **per tenant**, `randomBytes(32)`, shown once, stored hashed | One shared token for all customers |
| Let the token decide the tenant | Take the tenant from the URL, a header or the body |
| Allow rotation (two valid tokens during the switch) | Make the customer call support to change it |
| HTTPS only; optionally OAuth client credentials (topic 37) instead of a static token | Accept the token in a query string (it lands in logs) |
| Log every SCIM call (who, what, result), see topic 55 | Let users be created/deleted with no trace |

---

### Step 2: Scope everything to the tenant

The scariest SCIM bug is **TechCorp's IdP changing Chaiwala's users**. Every lookup filters by `req.tenant`:

```js
function findUser(req, id) {
  const u = users.get(id);
  if (!u || u.tenant !== req.tenant.id) throw new ScimError(404, `User ${id} not found`);
  return u;
}
```

- Another tenant's user gets the **same 404** as a missing one (don't confirm it exists).
- Group members must be users **of the same tenant**.
- `userName` is unique **per tenant** (and not case-sensitive), not globally. Two companies can both have `admin@…` style names. More on this in topic 65 (multi-tenant auth).

---

### Step 3: The Users endpoints (create, read, replace)

A SCIM user is JSON with fixed names:

```json
{
  "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
  "externalId": "00u1okta9priya",
  "userName": "priya@techcorp.com",
  "name": { "givenName": "Priya", "familyName": "Sharma" },
  "displayName": "Priya Sharma",
  "emails": [{ "value": "priya@techcorp.com", "type": "work", "primary": true }],
  "active": true
}
```

| Field | Meaning |
|---|---|
| `id` | **Your** id for the user (we use `randomUUID()`). The IdP stores it and uses it in every later URL |
| `externalId` | **The IdP's** id for the user. Handy for matching |
| `userName` | The unique login name, usually the work email |
| `active` | `false` = deactivated (left the company, on leave). The account stays, access stops |
| `meta` | `created`, `lastModified`, `location`, `version` (filled in by you) |

| Method + path | What the IdP wants | Our answer |
|---|---|---|
| `GET /Users?filter=userName eq "x"` | "Does this person already exist?" (sent **before** every create) | `ListResponse` with 0 or 1 users |
| `POST /Users` | Create | `201` + `Location` header + the user |
| `GET /Users/{id}` | Read one | `200` or `404` |
| `PUT /Users/{id}` | Replace **all** fields (missing ones are cleared) | `200` + the user |
| `PATCH /Users/{id}` | Change **some** fields (step 4) | `200` + the user |
| `DELETE /Users/{id}` | Remove | `204` |

Errors have their own shape. `status` is a **string**, and `scimType` tells the IdP what kind of problem it is:

```json
{ "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"], "status": "409", "scimType": "uniqueness", "detail": "userName Priya@TechCorp.com already exists" }
```

A `409 uniqueness` matters: Okta and Entra ID read it and **link** to the existing user instead of failing forever.

**Validate everything.** The IdP is a client like any other; a misconfigured mapping can send a 5 MB `title` or `"active": "maybe"`. Store only the attributes you use, and **never store a password** sent over SCIM (with SSO, your app doesn't need one).

---

### Step 4: PATCH, and the IdP quirks

PATCH sends a list of operations:

```json
{
  "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
  "Operations": [
    { "op": "replace", "path": "title", "value": "Team Lead" },
    { "op": "replace", "path": "emails[type eq \"work\"].value", "value": "priya.kapoor@techcorp.com" }
  ]
}
```

Real IdPs don't all speak it the same way. Things our demo handles:

| What arrives | Sent by | How we handle it |
|---|---|---|
| `{"op":"replace","value":{"active":false}}` (no `path`) | Okta | Each key in `value` is a path |
| `"op": "Replace"` (capital R) | Entra ID | Ops are case-insensitive |
| `"value": "False"` (a **string**) for `active` | Entra ID | Accept `true`/`false` booleans and `"True"`/`"False"` strings, reject anything else |
| `"path": "emails[type eq \"work\"].value"` | Entra ID | Replace the email of that type |
| `members[value eq "id"]` vs `"path":"members","value":[…]` for removal | Okta vs Entra ID | Both |

Our trick: apply the ops to a **copy** of the user, then run the copy through the **same validation** as POST. One validator, no way for PATCH to sneak in bad data.

---

### Step 5: Deactivation ends access **now**

This is the security payoff. When `active` goes from `true` to `false` (or the user is deleted):

```js
if (wasActive && !u.active) endSessions(u.id, `${u.userName} deactivated`);
```

And because sessions can be created in other ways too, **every request** re-checks the user:

```js
const u = s && users.get(s.userId);
if (!u?.active) { sessions.delete(...); return null; }
```

| ✅ Do | ❌ Don't |
|---|---|
| End sessions **and** revoke refresh tokens / API keys / personal access tokens of a deactivated user (topics 23, 70) | Only block the next SSO login |
| Re-check `active` on every request (or keep access tokens short-lived) | Trust a 30-day session made before the user left |
| Keep the account and its data (`active: false`); reactivation is just `active: true` | Hard-delete on deactivate and lose tickets, history, audit trail |
| Make SSO login check "provisioned **and** active" | Auto-create (JIT) an account for a user SCIM just deactivated |

---

### Step 6: Groups → roles

The IdP can push groups too (Okta "Push Groups", Entra ID "assigned groups"). You map **group names to roles** in your app:

```js
const roles = (u) => (groupsOf(u).some((g) => g.displayName === "ChaiDesk Admins") ? ["member", "admin"] : ["member"]);
```

Computed **per request**, so removing Priya from "ChaiDesk Admins" in Okta takes her admin rights away on her very next click. Let the customer's admin choose the mapping (group → role) in your settings page instead of hard-coding names. Roles and permissions themselves are Level 6 (topics 40–44).

---

### 🤔 Tricky parts

**1. SSO "deactivated" ≠ logged out.** Disabling a user in Okta stops new SSO logins. Your app's session cookie from yesterday is still valid until **you** end it. SCIM (or short sessions + re-checking) is what closes that gap.

**2. Entra ID is not instant.** Okta sends changes within seconds. Microsoft Entra ID's provisioning service runs in **cycles of about 40 minutes**. A leaver can keep access for that long, so pair SCIM with short sessions, and tell security-minded customers about "provision on demand".

**3. Matching existing users.** A customer who already has 200 users in your app turns SCIM on. The IdP first does `GET /Users?filter=userName eq "…"`. If your filter is broken (or case-sensitive), it creates **duplicates**. Match on `userName` case-insensitively, and store `externalId` once matched.

**4. Who can claim which email?** TechCorp's IT admin controls what `userName` their IdP sends. If your app links SCIM users to **global** accounts by email, a malicious tenant could provision `ceo@othercompany.com` and take over that person's account. Keep SCIM users inside the tenant, and only allow email domains the tenant has **verified** (DNS TXT record).

**5. PUT clears what it doesn't mention.** PUT is a full replace: if the IdP sends no `title`, the title is gone. That's correct per the spec; don't "merge" on PUT.

**6. The full filter language is big.** SCIM filters support `and`, `or`, `co`, `sw`, `gt`, `pr`, `[...]`. IdPs mostly send `userName eq "…"`, `externalId eq "…"` and `displayName eq "…"`. Support those well and return `400 invalidFilter` for the rest (never "ignore the filter and return everyone").

**7. Unsupported attributes.** Entra ID loves the enterprise extension (`urn:…:enterprise:2.0:User:department`). Either support it or tell the customer to remove the mapping; a silent `200` that drops data confuses everyone.

---

### Common beginner mistakes

1. **Thinking SSO alone handles offboarding.**
   It doesn't end existing sessions or tokens.

2. **One SCIM token for all customers** (or the tenant taken from the URL).
   One leak = every customer's users.

3. **Forgetting the tenant filter** on even one query.
   Cross-tenant data leak.

4. **Not accepting `application/scim+json`.**
   `express.json()` ignores that content type by default, `req.body` is `undefined`, and every request fails. Add `type: ["application/json", "application/scim+json"]`.

5. **Case-sensitive `userName` matching.**
   Duplicates, and a "user already exists" loop.

6. **Returning `200` for a duplicate create** instead of `409 uniqueness`.

7. **Hard-deleting on deactivate.**
   Data and audit history gone; reactivation impossible.

8. **Trusting `"active": "False"` as truthy.**
   In JavaScript `"False"` is a truthy string. Parse it.

9. **Not logging SCIM calls.**
   When a user asks "why was my account disabled?", you need the answer.

10. **Storing passwords sent over SCIM.**

---

### Interview questions

1. **What is SCIM and why do enterprises want it?**
   A standard REST API (RFC 7643/7644) for users and groups. The customer's IdP calls it to create, update and deactivate accounts in your app automatically, so joiners get access on day one and leavers lose it immediately.

2. **How is SCIM different from SSO?**
   SSO (SAML/OIDC) authenticates a user at login. SCIM manages the account lifecycle server-to-server, even when the user never logs in. You use both.

3. **What's JIT provisioning, and why isn't it enough?**
   Creating the account at the user's first SSO login from the assertion's claims. It can't create users before they log in, can't update them between logins, and is never told when they leave.

4. **What happens when a user is deactivated in Okta?**
   Okta sends `PATCH /Users/{id}` with `active: false` (or `PUT` with the full user). The app marks the user inactive, ends their sessions, revokes their tokens, and blocks future logins, while keeping their data.

5. **How do you secure a SCIM endpoint?**
   HTTPS, a per-tenant bearer token (or OAuth client credentials) stored hashed, the token determines the tenant, every query scoped to that tenant, strict input validation, rate limits, and an audit log.

6. **Deactivate vs delete?**
   Deactivate (`active: false`) keeps the account and data and is reversible. Delete removes it. Most IdPs deactivate by default; many apps soft-delete even on `DELETE`.

7. **How do IdP groups become app permissions?**
   The IdP pushes groups and memberships via `/Groups`; the app maps group names to roles (ideally configurable per tenant) and computes roles at request time.

8. **What's the difference between `id` and `externalId`?**
   `id` is assigned by the service provider (your app) and used in URLs. `externalId` is the client's (IdP's) own identifier for the same user.

9. **Why does PATCH need careful handling?**
   IdPs differ: Okta sends no-path value objects, Entra ID uses capitalized ops, string booleans and filtered paths like `emails[type eq "work"].value`. Apply the ops to a copy and re-validate.

---

### Quick recap

- **SCIM** = standard Users/Groups REST API your app exposes; the **IdP calls it** on every HR change
- **SSO** says who is logging in; **SCIM** says who should exist. Use both
- **Per-tenant bearer token**, stored hashed; the **token decides the tenant**; every query scoped to it
- `POST` create (`409 uniqueness` for duplicates), `GET ?filter=userName eq "…"` lookups, `PUT` full replace, `PATCH` ops, `DELETE`
- Handle IdP quirks: no-path PATCH (Okta), `"Replace"` and `"False"` (Entra ID), `application/scim+json`
- **Deactivate = end sessions and revoke tokens now**; re-check `active` on every request; keep the data
- Map **groups → roles**, computed per request
- Next: LDAP and Active Directory (topic 63)

## Code

**ChaiDesk**, a small multi-tenant SaaS helpdesk in **Express**, with a SCIM 2.0 API that Okta / Entra ID would call. You play the IdP with curl.

| Part | Routes |
|---|---|
| SCIM discovery (public) | `GET /scim/v2/ServiceProviderConfig` |
| SCIM Users (bearer token) | `GET /scim/v2/Users` (with `filter`, `startIndex`, `count`), `POST`, `GET /:id`, `PUT /:id`, `PATCH /:id`, `DELETE /:id` |
| SCIM Groups (bearer token) | `GET /scim/v2/Groups`, `POST`, `GET /:id`, `PATCH /:id` (add/remove members), `DELETE /:id` |
| The app (employees) | `POST /sso/login` (a stand-in for real SSO), `GET /me`, `GET /admin/reports` (needs the "ChaiDesk Admins" group) |

Two tenants are built in, each with its own demo token: **TechCorp** (Okta) `scim-techcorp-demo-token-7f3a` and **Chaiwala Inc** (Entra ID) `scim-chaiwala-demo-token-91bc`. Every SCIM call is written to the terminal (`🧾`), and so are provisioning (`👤`) and ended sessions (`🔒`). Everything is in memory, so a restart resets it.

📄 **Full code: [server.js](server.js)**. Open it and read the comments, which follow the same steps as the notes above.

Install Express once (from this folder), then start the server:

```bash
npm install
```

```bash
node server.js
```

> Port 3000 busy? Run it on another port: `PORT=3062 node server.js` (Git Bash). The outputs below were recorded on port 3062. Your ids will be different (they're random UUIDs).

### Try it (Git Bash)

```bash
APP=http://localhost:3062
S=$APP/scim/v2
T="Authorization: Bearer scim-techcorp-demo-token-7f3a"
C="Authorization: Bearer scim-chaiwala-demo-token-91bc"
J="Content-Type: application/scim+json"
scimid() { grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4; }
```

`$T` is TechCorp's Okta, `$C` is Chaiwala's Entra ID. `scimid` pulls the first `"id"` out of a response. `--get --data-urlencode` puts the filter into the URL with the spaces and quotes encoded.

#### Part A: Okta provisions Priya (joiner)

🔑 **① A wrong token gets nothing:**

```bash
curl -s -i -H "Authorization: Bearer wrong-token-123" $S/Users
```
→
```
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer realm="scim"
{"schemas":["urn:ietf:params:scim:api:messages:2.0:Error"],"status":"401","detail":"Missing or invalid SCIM bearer token"}
```

🔎 **② Okta first asks "does Priya exist?"**

```bash
curl -s -H "$T" $S/Users --get --data-urlencode 'filter=userName eq "priya@techcorp.com"'
```
→ `{"schemas":["urn:ietf:params:scim:api:messages:2.0:ListResponse"],"totalResults":0,"startIndex":1,"itemsPerPage":0,"Resources":[]}`

👤 **③ No, so it creates her.** Note the `password` Okta sometimes sends: it is not stored or returned.

```bash
curl -s -i -H "$T" -H "$J" $S/Users -d '{
  "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
  "externalId": "00u1okta9priya",
  "userName": "priya@techcorp.com",
  "name": { "givenName": "Priya", "familyName": "Sharma" },
  "displayName": "Priya Sharma",
  "title": "Support Agent",
  "emails": [{ "value": "priya@techcorp.com", "type": "work", "primary": true }],
  "active": true,
  "password": "Okta-sends-this-sometimes-1"
}'
PRIYA=$(curl -s -H "$T" $S/Users --get --data-urlencode 'filter=userName eq "priya@techcorp.com"' | scimid)
```
→
```
HTTP/1.1 201 Created
Content-Type: application/scim+json; charset=utf-8
Location: http://localhost:3062/scim/v2/Users/85f6d03d-d694-4d27-9926-fc87cfd15494
{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"id":"85f6d03d-d694-4d27-9926-fc87cfd15494","externalId":"00u1okta9priya","userName":"priya@techcorp.com","name":{"givenName":"Priya","familyName":"Sharma"},"displayName":"Priya Sharma","title":"Support Agent","emails":[{"value":"priya@techcorp.com","type":"work","primary":true}],"active":true,"groups":[],"meta":{"resourceType":"User","created":"2026-11-06T02:39:58.151Z","lastModified":"2026-11-06T02:39:58.151Z","location":"http://localhost:3062/scim/v2/Users/85f6d03d-d694-4d27-9926-fc87cfd15494","version":"W/\"1\""}}
```

♻️ **④ A duplicate (different case) is a `409 uniqueness`,** which tells Okta to link instead of retrying:

```bash
curl -s -H "$T" -H "$J" $S/Users -d '{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"Priya@TechCorp.com"}'
```
→ `{"schemas":["urn:ietf:params:scim:api:messages:2.0:Error"],"status":"409","scimType":"uniqueness","detail":"userName Priya@TechCorp.com already exists"}`

📄 **⑤ Rahul joins too. Listing is paged** (`startIndex` counts from 1):

```bash
curl -s -H "$T" -H "$J" $S/Users -d '{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"externalId":"00u1okta9rahul","userName":"rahul@techcorp.com","displayName":"Rahul Verma"}' > /dev/null
RAHUL=$(curl -s -H "$T" $S/Users --get --data-urlencode 'filter=userName eq "rahul@techcorp.com"' | scimid)
curl -s -H "$T" "$S/Users?startIndex=1&count=1"
```
→ `{"schemas":[…ListResponse],"totalResults":2,"startIndex":1,"itemsPerPage":1,"Resources":[{… "userName":"priya@techcorp.com" …}]}`

#### Part B: Priya uses the app, groups become roles (mover)

🔐 **⑥ Priya signs in** (pretend Okta SSO already proved who she is). She's a member, not an admin. Amit was never assigned the app:

```bash
curl -s -c priya.jar $APP/sso/login -H "Content-Type: application/json" -d '{"tenant":"techcorp","userName":"priya@techcorp.com"}'
curl -s -b priya.jar $APP/me
curl -s -b priya.jar $APP/admin/reports
curl -s $APP/sso/login -H "Content-Type: application/json" -d '{"tenant":"techcorp","userName":"amit@techcorp.com"}'
```
→
```
{"message":"Welcome Priya Sharma"}
{"tenant":"techcorp","userName":"priya@techcorp.com","displayName":"Priya Sharma","title":"Support Agent","roles":["member"]}
{"error":"Only members of \"ChaiDesk Admins\" can see reports"}
{"error":"No ChaiDesk account. Ask your IT admin to assign you the app."}
```

👑 **⑦ Okta pushes the "ChaiDesk Admins" group with Priya in it.** Her very next request is an admin request:

```bash
curl -s -H "$T" -H "$J" $S/Groups -d "{\"schemas\":[\"urn:ietf:params:scim:schemas:core:2.0:Group\"],\"displayName\":\"ChaiDesk Admins\",\"members\":[{\"value\":\"$PRIYA\"}]}"
GROUP=$(curl -s -H "$T" $S/Groups --get --data-urlencode 'filter=displayName eq "ChaiDesk Admins"' | scimid)
curl -s -b priya.jar $APP/me
curl -s -b priya.jar $APP/admin/reports
```
→
```
{… "displayName":"ChaiDesk Admins","members":[{"value":"85f6d03d-d694-4d27-9926-fc87cfd15494","display":"priya@techcorp.com"}] …}
{"tenant":"techcorp","userName":"priya@techcorp.com","displayName":"Priya Sharma","title":"Support Agent","roles":["member","admin"]}
{"tenant":"techcorp","activeUsers":2}
```

➖ **⑧ Removed from the group (Okta's PATCH style), admin is gone:**

```bash
curl -s -X PATCH -H "$T" -H "$J" $S/Groups/$GROUP -d "{\"schemas\":[\"urn:ietf:params:scim:api:messages:2.0:PatchOp\"],\"Operations\":[{\"op\":\"remove\",\"path\":\"members[value eq \\\"$PRIYA\\\"]\"}]}"
curl -s -b priya.jar $APP/admin/reports
```
→ `{… "members":[] …}` then `{"error":"Only members of \"ChaiDesk Admins\" can see reports"}`

✏️ **⑨ Priya is promoted and changes her surname.** A PATCH with Entra ID-style ops (capital `Replace`, an `emails[type eq "work"]` path):

```bash
curl -s -X PATCH -H "$T" -H "$J" $S/Users/$PRIYA -d '{
  "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
  "Operations": [
    { "op": "Replace", "path": "title", "value": "Team Lead" },
    { "op": "replace", "path": "name.familyName", "value": "Kapoor" },
    { "op": "replace", "path": "displayName", "value": "Priya Kapoor" },
    { "op": "replace", "path": "emails[type eq \"work\"].value", "value": "priya.kapoor@techcorp.com" }
  ]
}'
```
→ `{… "name":{"givenName":"Priya","familyName":"Kapoor"},"displayName":"Priya Kapoor","title":"Team Lead","emails":[{"value":"priya.kapoor@techcorp.com","type":"work","primary":true}], … "version":"W/\"2\"" …}`

#### Part C: Priya leaves (leaver)

🚪 **⑩ IT clicks "Deactivate" in Okta.** Her open session dies on the spot, and she can't sign in again:

```bash
curl -s -X PATCH -H "$T" -H "$J" $S/Users/$PRIYA -d '{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","value":{"active":false}}]}'
curl -s -b priya.jar $APP/me
curl -s $APP/sso/login -H "Content-Type: application/json" -d '{"tenant":"techcorp","userName":"priya@techcorp.com"}'
```
→
```
{… "active":false …}
{"error":"Not signed in"}
{"error":"Your ChaiDesk account is deactivated"}
```
Server terminal:
```
🔒 [techcorp] priya@techcorp.com deactivated: ended 1 session(s)
🧾 SCIM [techcorp] PATCH /scim/v2/Users/85f6d03d-d694-4d27-9926-fc87cfd15494 → 200
```

🪟 **⑪ Entra ID's version (Chaiwala tenant):** `"Replace"` with the **string** `"False"` works; junk is rejected:

```bash
curl -s -H "$C" -H "$J" $S/Users -d '{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"externalId":"6f1e-entra-vikram","userName":"vikram@chaiwala.in"}' > /dev/null
VIKRAM=$(curl -s -H "$C" $S/Users --get --data-urlencode 'filter=userName eq "vikram@chaiwala.in"' | scimid)
curl -s -X PATCH -H "$C" -H "$J" $S/Users/$VIKRAM -d '{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"Replace","path":"active","value":"False"}]}'
curl -s -X PATCH -H "$C" -H "$J" $S/Users/$VIKRAM -d '{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"active","value":"nope"}]}'
```
→ `{… "active":false …}` then `{"schemas":["urn:ietf:params:scim:api:messages:2.0:Error"],"status":"400","scimType":"invalidValue","detail":"active must be true or false"}`

#### Part D: tenant isolation and bad input

🏢 **⑫ Chaiwala's token can't see or touch TechCorp,** and TechCorp can't add Chaiwala's user to its group:

```bash
curl -s -H "$C" $S/Users/$PRIYA
curl -s -H "$C" $S/Users --get --data-urlencode 'filter=userName eq "priya@techcorp.com"'
curl -s -X PATCH -H "$C" -H "$J" $S/Groups/$GROUP -d "{\"schemas\":[\"urn:ietf:params:scim:api:messages:2.0:PatchOp\"],\"Operations\":[{\"op\":\"add\",\"path\":\"members\",\"value\":[{\"value\":\"$VIKRAM\"}]}]}"
curl -s -X PATCH -H "$T" -H "$J" $S/Groups/$GROUP -d "{\"schemas\":[\"urn:ietf:params:scim:api:messages:2.0:PatchOp\"],\"Operations\":[{\"op\":\"add\",\"path\":\"members\",\"value\":[{\"value\":\"$VIKRAM\"}]}]}"
```
→
```
{"schemas":["urn:ietf:params:scim:api:messages:2.0:Error"],"status":"404","detail":"User 85f6d03d-d694-4d27-9926-fc87cfd15494 not found"}
{"schemas":["urn:ietf:params:scim:api:messages:2.0:ListResponse"],"totalResults":0,"startIndex":1,"itemsPerPage":0,"Resources":[]}
{"schemas":["urn:ietf:params:scim:api:messages:2.0:Error"],"status":"404","detail":"Group 3f7c0029-a413-43fd-93bc-2ba1084a63a1 not found"}
{"schemas":["urn:ietf:params:scim:api:messages:2.0:Error"],"status":"400","scimType":"invalidValue","detail":"members: user 70387bab-a3fa-4346-9876-6970836f8bc7 not found"}
```

🚫 **⑬ Unsupported filters and missing fields are clear `400`s** (never "ignore the filter, return everyone"):

```bash
curl -s -H "$T" $S/Users --get --data-urlencode 'filter=userName co "priya"'
curl -s -H "$T" -H "$J" $S/Users -d '{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"emails":[{"value":"no-username"}]}'
```
→
```
{"schemas":["urn:ietf:params:scim:api:messages:2.0:Error"],"status":"400","scimType":"invalidFilter","detail":"Only filters like userName eq \"value\" are supported"}
{"schemas":["urn:ietf:params:scim:api:messages:2.0:Error"],"status":"400","scimType":"invalidValue","detail":"userName is required"}
```

🗑️ **⑭ Delete Rahul:**

```bash
curl -s -i -X DELETE -H "$T" $S/Users/$RAHUL
curl -s -H "$T" $S/Users/$RAHUL
```
→ `HTTP/1.1 204 No Content` then `{"schemas":["urn:ietf:params:scim:api:messages:2.0:Error"],"status":"404","detail":"User 90db2b1b-1967-4e14-92cf-dc054807b284 not found"}`

The server terminal now holds the whole audit trail, one line per SCIM call:
```
🧾 SCIM [techcorp] GET /scim/v2/Users?filter=userName+eq+%22priya%40techcorp.com%22 → 200
👤 [techcorp] provisioned priya@techcorp.com
🧾 SCIM [techcorp] POST /scim/v2/Users → 201
🧾 SCIM [techcorp] POST /scim/v2/Users → 409
…
🧾 SCIM [chaiwala] GET /scim/v2/Users/85f6d03d-d694-4d27-9926-fc87cfd15494 → 404
🧾 SCIM [techcorp] DELETE /scim/v2/Users/90db2b1b-1967-4e14-92cf-dc054807b284 → 204
```

> **Windows PowerShell users:** the single quotes in `-d '...'`, `$(…)`, the `scimid` function and `VAR=value node ...` work in Git Bash. In PowerShell, use Git Bash or Postman, or set the port with `$env:PORT=3062; node server.js`. Restart the server to reset all users and groups.
