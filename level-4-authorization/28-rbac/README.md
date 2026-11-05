# 28. Role-Based Access Control (RBAC)

## Notes

### What is RBAC?

Authentication (Levels 1–3) answers **"who are you?"**. Authorization answers **"what are you allowed to do?"** (topic 01). **RBAC** is the most common way to answer it: you don't give permissions to people one by one. You give **permissions to roles**, and **roles to users**.

> **One-line answer:** RBAC = **users → roles → permissions**. Each user has one or more roles (`customer`, `support`, `admin`), each role is a list of permissions (`orders:refund`), and every route checks **a permission** on the **server**: `401` if we don't know who you are, `403` if we know and you're not allowed.

---

### Why does it matter?

| Without RBAC | What goes wrong |
|---|---|
| `if (user.email === "amit@shop.com")` scattered in routes | A new admin joins → you edit and redeploy 20 files |
| Every logged-in user can call every route | Rahul (a customer) calls `POST /admin/orders/ord_2/refund` and refunds himself money |
| Permissions given person by person | 500 employees × 30 permissions = nobody knows who can do what |
| Admin pages "protected" by hiding the button | Anyone with curl or DevTools calls the API directly |
| No clear list of who can do what | Audits (SOC 2, RBI, ISO) fail; you can't answer "who can issue refunds?" |

---

### Real-life example: a bank branch 🏦

At an SBI branch:

- **Rahul** walks in as a **customer**. He can see his passbook. He can't open the cash vault.
- **Priya** works the **cashier** counter. She can accept deposits and pay out cash.
- **The branch manager** can do everything Priya can, plus approve loans.
- When Priya is promoted to manager, nobody writes a new rule for "Priya". HR just **changes her role**, and the next morning her key card opens the manager's cabin.
- The security guard doesn't care **who** you are, only whether your card says your role is allowed through that door. He checks the card **at the door**, every time, not once at the main gate.

Role = job title. Permission = which doors that title opens. The door check = your middleware.

---

### The flow, step by step

#### 📊 Diagrams

Open **[diagrams.html](diagrams.html)** in your browser (just double-click the file) to see:

- **Flow diagram**: one request going through "who are you?" then "are you allowed?"
- **Data flow**: Rahul, Priya and Amit calling the same admin routes, and a live role change
- **The model**: users → roles → permissions, as tables

In short: `request → requireAuth (token → user, roles loaded fresh) → 401 if unknown → requirePermission("orders:refund") → permissions = union of the user's roles → has it? → route runs : 403 + log`.

---

### Step 1: List your permissions (the actions)

```js
const PERMISSIONS = ["products:read", "products:write", "orders:read_all", "orders:refund", "users:manage"];
```

A permission is **one action** on **one kind of thing**. The `resource:action` naming (`orders:refund`) is easy to read and easy to search.

| ✅ Do | ❌ Don't |
|---|---|
| Small, specific permissions: `orders:refund` | One giant `is_admin` flag for everything |
| Name the **action** (`orders:refund`) | Name the **page** (`can_see_admin_panel`) |

---

### Step 2: Group permissions into roles

```js
const ROLE_PERMISSIONS = {
  customer: ["products:read"],
  support:  ["products:read", "orders:read_all", "orders:refund"],
  editor:   ["products:read", "products:write"],
  admin:    ["products:read", "products:write", "orders:read_all", "orders:refund", "users:manage"],
};
```

- A **role** is a job title: a named bundle of permissions.
- A user can have **several roles**. Their permissions are the **union**: Rahul as `customer` + `editor` can read **and** write products.
- **Least privilege**: give each role only what that job needs. Support can refund; it can't edit products or manage users.
- **Role hierarchy** (optional): "admin inherits everything support has". It saves typing but hides what a role really can do. Listing permissions out (like above) is clearer for a small app.

In a real app this lives in tables:

```
users(id, …)            roles(id, name)           permissions(id, name)
user_roles(user_id, role_id)          role_permissions(role_id, permission_id)
```

---

### Step 3: Authenticate first, and load roles **fresh**

```js
function requireAuth(req, res, next) {
  const record = tokens.get(sha256(token));
  if (!record) return res.status(401).json({ error: "Please log in" });
  req.user = users.get(record.userId); // roles come from the DATABASE, not from the request
  next();
}
```

- Authorization **needs** authentication. Unknown user → **`401 Unauthorized`** ("log in first").
- **Where do the roles come from?** Always from **your server**: the database, or a token **you signed** (topic 27).
  - **Never** from the request body, a query string, a cookie you didn't sign, or a header like `X-Role: admin`.
- **Roles in a JWT** (a `roles` claim) save a database lookup, but they're a **snapshot**. If you remove Amit's admin role, his token still says `admin` until it expires. Keep access tokens short (topic 20), or look roles up by `sub` for sensitive actions. This demo looks them up on every request, so a change works **instantly**.

---

### Step 4: Check a **permission**, not a role

```js
function requirePermission(permission) {
  return (req, res, next) => {
    if (permissionsOf(req.user.roles).has(permission)) return next();
    res.status(403).json({ error: "You don't have permission to do this" });
  };
}

app.post("/admin/orders/:id/refund", requireAuth, requirePermission("orders:refund"), refund);
```

- Known user, not allowed → **`403 Forbidden`**.
- Check **permissions** in routes, not role names:

| ✅ Do | ❌ Don't |
|---|---|
| `requirePermission("orders:refund")` | `if (user.role === "admin" \|\| user.role === "support")` |
| New role "finance" = one line in `ROLE_PERMISSIONS` | New role = edit every route that lists roles |

- The check runs **on the server**, on **every** request. Hiding the "Refund" button in React is nice for the user, but it's not security: `GET /me` returns the permissions so the UI can hide buttons, and the server **still** checks.

---

### Step 5: Deny by default, and log it

- **Fail closed**: an unknown role has **no** permissions; a route without a guard is a bug (topic 30 shows how to make guards impossible to forget).
- Validate role changes against the **allow-list** of roles. `"superadmin"` or `"Admin "` → `400`.
- **Log** every denial and every role change (who, what, when). "Who gave Rahul admin?" must have an answer (Level 7: audit logs).
- Don't let an admin remove **their own** admin role (or the last admin) and lock everyone out.

---

### 🤔 Tricky parts

**1. 401 vs 403.**
`401` = "I don't know who you are" (no token, bad token). `403` = "I know who you are, and the answer is no". Logging in again won't fix a `403`.

**2. RBAC alone doesn't stop IDOR.**
A permission like `orders:read_own` says Rahul may read **orders**. It doesn't say **which** orders. `GET /orders/ord_2` (Sneha's order) must also check **ownership**: `order.customer === req.user.id` (topic 31). That's why the demo only has the "read **all** orders" permission, which belongs to support.

**3. Role explosion.**
"Support, but only for Mumbai, but only orders under ₹5,000" → you end up with `support_mumbai_small`, `support_delhi_small`, … hundreds of roles. That's when you need **attributes** (city, amount, time): ABAC, topic 29.

**4. Roles in tokens are stale.**
A JWT made at 10:00 says `admin` until it expires, even if you removed the role at 10:05. Short access tokens, a `ver` claim (topic 24), or a database lookup fix it.

**5. Multi-tenant apps.**
"Priya is admin" usually means "Priya is admin **in company A**". Roles then belong to a `(user, organisation)` pair, not just to the user (Level 8: multi-tenant auth).

**6. The frontend can see roles, and that's fine.**
Showing a user their own roles isn't a leak. Trusting the frontend to **enforce** them is the bug.

---

### Common beginner mistakes

1. **Only hiding buttons in the UI.**
   The API is still open. Every route checks on the server.

2. **Reading the role from the client** (`req.body.role`, `X-Role` header, an unsigned cookie).
   The attacker writes `admin`. Roles come from your database or a token you signed and verified.

3. **Hard-coding role names in routes** (`if (role === "admin")`).
   Check permissions, so adding a role doesn't mean editing every route.

4. **Returning 401 for "not allowed".**
   That's `403`. `401` means "not logged in".

5. **Forgetting a guard on one route.**
   One missed `requirePermission` = an open admin endpoint. Deny by default (topic 30).

6. **Giving everyone admin "for now".**
   Least privilege from day one; it's painful to take permissions away later.

7. **Letting users change their own roles.**
   Role changes need `users:manage`, a check against the role allow-list, and an audit log.

8. **Thinking RBAC covers "my own data".**
   It checks the action, not the row. Add ownership checks (topic 31).

---

### Interview questions

1. **What is RBAC?**
   Users get roles, roles get permissions, and code checks permissions. Access is managed by changing a user's roles instead of editing code per person.

2. **Role vs permission?**
   A permission is one allowed action (`orders:refund`). A role is a named group of permissions that matches a job (`support`).

3. **401 vs 403?**
   `401`: not authenticated (missing/invalid credentials). `403`: authenticated but not allowed.

4. **Why check permissions instead of roles in code?**
   Roles change and multiply; actions don't. With permission checks, a new role is a config change, not a code change in every route.

5. **Where should roles come from on each request?**
   From the server: the database, or a signed and verified token. Never from client-controlled input.

6. **What's the problem with roles inside a JWT?**
   They're a snapshot: removing a role doesn't affect tokens already issued until they expire. Use short-lived tokens, a version claim, or a database lookup for sensitive actions.

7. **What is least privilege?**
   Each user and role gets only the permissions it needs for its job, nothing "just in case".

8. **When is RBAC not enough?**
   When access depends on attributes of the user, resource or context (owner, department, amount, time, location). Then use ownership checks (IDOR, topic 31) or ABAC/policies (topic 29).

9. **Is hiding admin buttons enough?**
   No. It's only UX. The server enforces every permission on every request.

---

### Quick recap

- RBAC = **users → roles → permissions**
- **Permissions** are actions (`orders:refund`); **roles** are job titles that bundle them
- Several roles per user → permissions are the **union**
- Routes check **permissions**, not role names: `requirePermission("orders:refund")`
- **401** = who are you? **403** = you're not allowed
- Roles come from the **server** (database / signed token), loaded fresh so changes work at once
- **Deny by default**, validate role changes against an allow-list, **log** denials and changes
- The UI may **hide** buttons; only the **server** enforces
- RBAC checks **what action**, not **which row**: add ownership (topic 31) and attributes (topic 29)

## Code

A small **Express** shop API with four users and four roles. Everyone logs in the same way; what they can do depends only on their roles. `requireAuth` finds the user (loading roles **fresh** from the "database"), and `requirePermission("…")` checks one permission per route.

| User | Role | Can |
|---|---|---|
| `rahul` | customer | read products |
| `priya` | support | read products, see all orders, refund |
| `neha` | editor | read and add products |
| `amit` | admin | everything, including changing roles |

The password for every demo user is `chai1234`.

📄 **Full code: [server.js](server.js)**. Open it and read the comments, which follow the same steps as the notes above.

Install the dependencies once (from this folder), then start the server:

```bash
npm install
```

```bash
node server.js
```

> Port 3000 busy? Run it on another port: `PORT=3028 node server.js` (Git Bash), then use that port in the commands below.

### Try it

✅ **Log in as each user** and keep the tokens (Git Bash):

```bash
login() { curl -s http://localhost:3000/login -H "Content-Type: application/json" -d "{\"username\":\"$1\",\"password\":\"chai1234\"}" | grep -o '"accessToken":"[^"]*' | cut -d'"' -f4; }
R=$(login rahul); P=$(login priya); N=$(login neha); A=$(login amit)
```

One login on its own looks like: `{"accessToken":"Xv_ZkYiFxGB09YpvgXwECs_vYEgRBiztcy3MLtAyC_E","roles":["customer"]}`

✅ **What can I do?** (the UI uses this to hide buttons):

```bash
curl http://localhost:3000/me -H "Authorization: Bearer $R"
```
→ `{"id":"u_rahul","name":"Rahul (customer)","roles":["customer"],"permissions":["products:read"]}`

❌ **No token → 401:**

```bash
curl http://localhost:3000/products
```
→ `401 {"error":"Please log in"}`

🧪 **Same route, four users** (`orders:read_all`):

```bash
for u in R P N A; do printf "%s → " $u; curl -s http://localhost:3000/admin/orders -H "Authorization: Bearer ${!u}" -w " %{http_code}"; echo; done
```
→
```
R → {"error":"You don't have permission to do this"} 403
P → {"orders":[{"id":"ord_1","customer":"u_rahul",...,"status":"paid"},{"id":"ord_2","customer":"u_sneha",...}]} 200
N → {"error":"You don't have permission to do this"} 403
A → {"orders":[...]} 200
```

🧪 **Add a product** (`products:write`): only Neha (editor) and Amit (admin):

```bash
for u in R P N A; do printf "%s → " $u; curl -s http://localhost:3000/products -H "Authorization: Bearer ${!u}" -H "Content-Type: application/json" -d '{"name":"Elaichi","price":150}' -w " %{http_code}"; echo; done
```
→
```
R → {"error":"You don't have permission to do this"} 403
P → {"error":"You don't have permission to do this"} 403
N → {"id":"p_361ad744","name":"Elaichi","price":150} 201
A → {"id":"p_1839ba29","name":"Elaichi","price":150} 201
```

🧪 **Refund** (`orders:refund`): Rahul can't refund himself, Priya can:

```bash
curl -X POST http://localhost:3000/admin/orders/ord_1/refund -H "Authorization: Bearer $R"
```
→ `403 {"error":"You don't have permission to do this"}`

```bash
curl -X POST http://localhost:3000/admin/orders/ord_1/refund -H "Authorization: Bearer $P"
```
→ `200 {"id":"ord_1","customer":"u_rahul","item":"Masala chai (500 g)","total":240,"status":"refunded"}` (again → `409 {"error":"Order is already refunded"}`)

🧪 **Change roles** (`users:manage`, admin only):

```bash
curl -X PUT http://localhost:3000/admin/users/u_rahul/roles -H "Authorization: Bearer $P" -H "Content-Type: application/json" -d '{"roles":["admin"]}'
```
→ `403`: support can't promote anyone (Priya can't make Rahul admin).

```bash
curl -X PUT http://localhost:3000/admin/users/u_rahul/roles -H "Authorization: Bearer $A" -H "Content-Type: application/json" -d '{"roles":["superadmin"]}'
```
→ `400 {"error":"roles must be a non-empty list from: customer, support, editor, admin"}`

```bash
curl -X PUT http://localhost:3000/admin/users/u_amit/roles -H "Authorization: Bearer $A" -H "Content-Type: application/json" -d '{"roles":["customer"]}'
```
→ `400 {"error":"You can't remove your own admin role"}`

✅ **A role change works on the very next request** (same token, no re-login):

```bash
curl -X PUT http://localhost:3000/admin/users/u_rahul/roles -H "Authorization: Bearer $A" -H "Content-Type: application/json" -d '{"roles":["customer","editor"]}'
```
→ `{"id":"u_rahul","roles":["customer","editor"],"permissions":["products:read","products:write"]}`

```bash
curl http://localhost:3000/products -H "Authorization: Bearer $R" -H "Content-Type: application/json" -d '{"name":"Ginger chai","price":260}'
```
→ `201 {"id":"p_5bc9f2ca","name":"Ginger chai","price":260}`. Set Rahul back to `["customer"]` and the same call gives `403` again.

📋 **The server log** is the audit trail:

```
🚫 denied: u_rahul [customer] needs orders:read_all for GET /admin/orders
🚫 denied: u_rahul [customer] needs orders:refund for POST /admin/orders/ord_1/refund
💸 u_priya refunded ord_1 (₹240)
🚫 denied: u_priya [support] needs users:manage for PUT /admin/users/u_rahul/roles
🔑 u_amit changed roles of u_rahul: [customer] → [customer,editor]
🔑 u_amit changed roles of u_rahul: [customer,editor] → [customer]
```

> **Windows PowerShell users:** the `login()` function, `for` loops, `${!u}` and `PORT=... node ...` work in Git Bash. In PowerShell, use Git Bash, Postman, or `$env:PORT=3028; node server.js`.
