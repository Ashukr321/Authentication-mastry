# 31. Resource Ownership Checks (IDOR)

## Notes

### What is IDOR?

Rahul is logged in and opens his order: `GET /orders/ord_1001`. He changes the URL to `ord_1002`, and the API happily shows **Sneha's** order, with her address and phone number. That's an **IDOR: Insecure Direct Object Reference**. The API checked **who** Rahul is (authentication) and maybe **what** he may do (`orders:read`, topic 28), but never checked **whether this particular record is his**.

> **One-line answer:** IDOR = the server uses an **id from the request** to load a record **without checking the record belongs to the logged-in user**. Fix: load records **scoped to the owner from the token** (`WHERE id = $1 AND user_id = $me`), do it for **every** read, update, delete and list, return **404** for "not yours", only accept fields the user may change, and **log** the attempts.

---

### Why does it matter?

It's the **#1 risk** on the OWASP API Security Top 10 (**BOLA: Broken Object Level Authorization**), and one of the most common real bug-bounty findings, because it's so easy to find: change a number, see someone else's data.

| Where it hides | What leaks |
|---|---|
| `GET /orders/:id` | Other customers' orders, addresses, phone numbers |
| `GET /invoices/1234.pdf` | Other companies' invoices (just count up) |
| `GET /orders?userId=u_sneha` | Anyone's whole order history |
| `PATCH /orders/:id` / `DELETE /addresses/:id` | Changing or deleting other people's data |
| `PATCH` that copies the whole body | Users editing `total`, `status`, `userId` on their own records |

Login, HTTPS, JWT, RBAC: all of them can be perfect and IDOR still leaks everything.

---

### Real-life example: a cloakroom at a wedding 🧥

At a wedding hall in Jaipur, guests hand in their bags and get numbered tokens.

- Rahul's token says **#41**. He asks for **#42**, and the attendant hands over Sneha's bag without a glance. → **IDOR** (the number is the only check)
- A careful attendant checks the token **and** that the bag's tag matches **this guest's** token stub. → **ownership check**
- If the tag doesn't match, the attendant says **"no bag with that number"**, not "that's someone else's bag". → **404, not 403**
- The wedding planner (Priya, **support**) may look at any bag to help find a lost one, but **can't take bags home**. → a **permission** can widen **read** access; it doesn't make you the owner
- Using big random tokens instead of 1, 2, 3 makes guessing harder, but the attendant **still** has to check. → **random ids are not the fix**

---

### The flow, step by step

#### 📊 Diagrams

Open **[diagrams.html](diagrams.html)** in your browser (just double-click the file) to see:

- **Flow diagram**: authenticate → load **scoped** to the owner → 404 or act
- **Data flow**: Rahul walking through order ids on the buggy API vs the fixed API
- **The checklist**: every kind of endpoint and the ownership check it needs

In short: `request with :id → who are you? (token → req.user) → findOrder(id, ownerId = req.user.id) → not found or not yours → 404 + log → yours → (writes: allowed fields only, right state) → act`.

---

### Step 1: The owner comes from the token, and goes into the query

```js
// ❌ IDOR: any logged-in user can read any order
const order = await db.orders.findById(req.params.id);

// ✅ scoped: the record must belong to the person in the token
const order = await db.query("SELECT * FROM orders WHERE id = $1 AND user_id = $2", [req.params.id, req.user.id]);
```

- `req.user.id` comes from **your** session/token (topics 09, 19). **Never** from `req.body.userId`, `?userId=`, or a header.
- Putting the owner **in the query** is safer than loading first and comparing later: there's no way to forget the comparison, and the record never even reaches your code.
- **Lists** too: `GET /orders` returns `WHERE user_id = $me`. Don't accept a `userId` filter from customers at all.

| ✅ Do | ❌ Don't |
|---|---|
| `WHERE id = $1 AND user_id = $me` | `findById(req.params.id)` and nothing else |
| `GET /me/orders` / `GET /orders` scoped to the token | `GET /orders?userId=...` trusted from the client |
| A shared `findOrder(id, { ownerId })` helper | Copy-pasting the check (and forgetting it once) |

---

### Step 2: "Not yours" looks exactly like "doesn't exist" (404)

```js
if (!order) return res.status(404).json({ error: "Order not found" });
```

- If the API says `403 Forbidden` for `ord_1002`, Rahul learns that **order 1002 exists**: enough to count orders, guess sales, or target users.
- `404` for both "missing" and "not yours" reveals nothing.
- **Log** the attempt on the server side (`u_rahul tried GET ord_1002, which belongs to u_sneha`). Many in a row = someone walking through ids: alert, rate-limit (topic 16), or block.

---

### Step 3: Writes and deletes check ownership too, and only change allowed fields

```js
const EDITABLE_FIELDS = ["address", "phone"];
const order = findOrder(req.params.id, { ownerId: req.user.id });
if (!order) return res.status(404)...;
if (Object.keys(req.body).some((k) => !EDITABLE_FIELDS.includes(k))) return res.status(400)...;
if (order.status !== "placed") return res.status(409)...;
```

- Ownership on `GET` but not on `PATCH`/`DELETE` is the most common half-fix.
- Even on **your own** record, you can't change **everything**. `Object.assign(order, req.body)` lets Rahul set `"total": 1` or `"status": "delivered"`, or even `"userId"`. This is **mass assignment** (OWASP API3, "Broken Object **Property** Level Authorization"). Accept an **allow-list** of fields.
- The record's **state** can matter: an address can't change after the order has shipped.

---

### Step 4: Staff access is a permission, and usually read-only

```js
if (order.userId === ownerId) return order;
if (staff && can(staff, "orders:read_all")) return order; // support may READ any order
```

- Priya (support) needs to see Sneha's order to help her. That's an explicit **permission** (topic 28), not "skip the check for staff".
- Read access ≠ write access. In the demo, Priya can read `ord_1002` but `PATCH` gives her `404`.
- Real systems also check that staff stay **within their tenant/team/region** (topic 29, Level 8 multi-tenant).

---

### Step 5: Random ids are a seatbelt, not brakes

- `ord_1001, ord_1002, …` invite guessing. **UUIDs** or random ids make guessing very hard. Use them, **but**:
  - ids leak: URLs in emails, logs, screenshots, browser history, shared links, other API responses
  - an attacker may have **one** valid id of someone else's from anywhere
- The ownership check is the **fix**. Random ids are **defence in depth**.

---

### 🤔 Tricky parts

**1. Nested resources.**
`GET /orders/:orderId/items/:itemId` must check **both**: the order is yours **and** the item belongs to that order. Otherwise `/orders/<mine>/items/<someone else's>` works.

**2. IDs in the body, not just the URL.**
`POST /payments { "orderId": "ord_1002" }` or `POST /addresses/default { "addressId": "…" }`: every id the client sends, wherever it is, needs an ownership check.

**3. Files and download links.**
`/uploads/invoice_1002.pdf` served as a static file has **no** check at all. Serve private files through a route that checks ownership, or with short-lived signed URLs.

**4. GraphQL, batch and export endpoints.**
`query { order(id: "ord_1002") }`, `POST /orders/batch-get`, `GET /export?ids=...`: the same check per object, inside the resolver/loop.

**5. Shared resources.**
"Owner" may be a **team**, **company** or a **share list** ("Sneha shared this order with Rahul"). Then the check is "is the user a member of the owning group / in the share list" (ReBAC, topic 71).

**6. Caching.**
A CDN or app cache keyed only by URL can serve Rahul's response to Sneha. Private responses: `Cache-Control: no-store` / `private` (the demo sets `no-store`).

---

### Common beginner mistakes

1. **`findById(req.params.id)` with no owner check.**
   Logged in ≠ allowed to see everything. Scope every query to `req.user.id`.

2. **Trusting `userId` from the client** (`?userId=`, body, header).
   The owner comes from the token only.

3. **Checking on read, forgetting update and delete.**
   Every method, every endpoint that takes an id.

4. **Returning 403 for other people's records.**
   It confirms they exist. Return 404.

5. **`Object.assign(record, req.body)`.**
   Mass assignment: users change `total`, `status`, `role`, `userId`. Allow-list editable fields.

6. **"We use UUIDs, so we're safe."**
   UUIDs leak. Still check ownership.

7. **Hiding the "view" button in the UI.**
   The API is what gets called. The check is on the server.

8. **Doing the check in the frontend after fetching.**
   The data has already been sent to the browser.

9. **Admins/staff bypassing everything.**
   Give staff explicit, limited permissions (read vs write, their tenant only), and log their access.

---

### Interview questions

1. **What is IDOR / BOLA?**
   The API uses a client-supplied id to access an object without checking the current user is allowed to access **that** object. OWASP API #1 (Broken Object Level Authorization).

2. **How do you prevent it?**
   Scope every query by the authenticated owner (`WHERE id = $1 AND user_id = $2`), for every read, write, delete and list, in a shared helper or data-access layer; take the user id from the session/token only.

3. **403 or 404 for someone else's resource?**
   Usually 404, so attackers can't confirm the resource exists. Log the attempt on the server.

4. **Do UUIDs fix IDOR?**
   No. They make guessing harder but ids leak through URLs, logs and other responses. They're defence in depth on top of the ownership check.

5. **RBAC vs ownership?**
   RBAC says the user may perform an action on a **type** of resource (`orders:read`). Ownership says **this specific** record is theirs. You need both.

6. **What is mass assignment / BOPLA?**
   Copying request fields straight onto a model, so users can change fields they shouldn't (`total`, `role`, `userId`). Fix: allow-list editable fields per role.

7. **How do you let support staff see customer data?**
   An explicit permission (`orders:read_all`), usually read-only, scoped to their tenant/region, with access logged.

8. **How do you detect IDOR attacks?**
   Log and alert on many 404s for existing-but-not-owned ids from one user, rate-limit, and watch for sequential id access patterns.

9. **How would you test for IDOR?**
   Log in as two users, take user A's ids, and call every endpoint (GET/PATCH/DELETE, nested routes, body ids, files) as user B. Automate it in integration tests.

---

### Quick recap

- IDOR = trusting the **id** without checking the **owner**. OWASP API #1 (BOLA)
- Owner = `req.user.id` from **your token**; never `userId` from the client
- **Scope the query**: `WHERE id = $1 AND user_id = $me`, in a shared helper
- Every **read, update, delete, list**, nested route, body id and file
- **404** for "not yours", and **log** the attempt
- Writes: **allow-listed fields** only (no mass assignment), and the right **state**
- Staff: an explicit, usually **read-only** permission
- Random ids help, **but they're not the fix**
- Next: authenticating **programs** instead of people (topic 32: API keys)

## Code

A small **Express** orders API with **fixed** routes (`/orders/...`) and a **bug lab** (`/buggy/orders/...`) over the **same** data, so you can see each IDOR leak and its fix side by side. Order ids are **sequential on purpose** so the attack is easy to see.

| User | Role | Orders |
|---|---|---|
| `rahul` | customer | `ord_1001` (placed), `ord_1003` (delivered) |
| `sneha` | customer | `ord_1002` (placed): Kanjeevaram saree, ₹18,500, Delhi address |
| `priya` | support | none, but may **read** any order (`orders:read_all`) |

Every demo user's password is `chai1234`.

📄 **Full code: [server.js](server.js)**. Open it and read the comments, which follow the same steps as the notes above.

Install the dependencies once (from this folder), then start the server:

```bash
npm install
```

```bash
node server.js
```

> Port 3000 busy? Run it on another port: `PORT=3031 node server.js` (Git Bash), then use that port in the commands below.

### Try it

✅ **Log in** (Git Bash):

```bash
login() { curl -s http://localhost:3000/login -H "Content-Type: application/json" -d "{\"username\":\"$1\",\"password\":\"chai1234\"}" | grep -o '"accessToken":"[^"]*' | cut -d'"' -f4; }
R=$(login rahul); S=$(login sneha); P=$(login priya)
```

✅ **Rahul's list is scoped to Rahul:**

```bash
curl http://localhost:3000/orders -H "Authorization: Bearer $R"
```
→ `{"orders":[{"id":"ord_1001","item":"Masala chai (500 g)","total":240,"status":"placed"},{"id":"ord_1003","item":"Filter coffee (250 g)","total":180,"status":"delivered"}]}`

✅ **Rahul walks through ids on the fixed API:**

```bash
for i in 1001 1002 1003 1004; do printf "ord_$i → "; curl -s http://localhost:3000/orders/ord_$i -H "Authorization: Bearer $R" -w " %{http_code}"; echo; done
```
→
```
ord_1001 → {"id":"ord_1001","userId":"u_rahul","item":"Masala chai (500 g)","total":240,"status":"placed","address":"12 MG Road, Pune","phone":"98xxxxxx01"} 200
ord_1002 → {"error":"Order not found"} 404      ← Sneha's: looks exactly like a missing one
ord_1003 → {"id":"ord_1003","userId":"u_rahul",...,"status":"delivered",...} 200
ord_1004 → {"error":"Order not found"} 404      ← really missing
```
The terminal logs the probe: `🕵️  u_rahul tried GET ord_1002, which belongs to u_sneha`

✅ **Support can read, not edit:**

```bash
curl http://localhost:3000/orders/ord_1002 -H "Authorization: Bearer $P"
curl -X PATCH http://localhost:3000/orders/ord_1002 -H "Authorization: Bearer $P" -H "Content-Type: application/json" -d '{"address":"x"}'
```
→
```
{"id":"ord_1002","userId":"u_sneha","item":"Kanjeevaram saree","total":18500,"status":"placed","address":"7 Lodhi Colony, Delhi","phone":"98xxxxxx02"} 200
{"error":"Order not found"} 404
```

✅ **Writes: ownership, allowed fields, and state:**

```bash
curl -X PATCH http://localhost:3000/orders/ord_1002 -H "Authorization: Bearer $R" -H "Content-Type: application/json" -d '{"address":"Rahul flat, Pune"}'
curl -X PATCH http://localhost:3000/orders/ord_1001 -H "Authorization: Bearer $R" -H "Content-Type: application/json" -d '{"total":1,"status":"delivered"}'
curl -X PATCH http://localhost:3000/orders/ord_1001 -H "Authorization: Bearer $R" -H "Content-Type: application/json" -d '{"address":"44 FC Road, Pune"}'
curl -X PATCH http://localhost:3000/orders/ord_1003 -H "Authorization: Bearer $R" -H "Content-Type: application/json" -d '{"address":"44 FC Road, Pune"}'
```
→
```
{"error":"Order not found"} 404                         ← Sneha's order
{"error":"You can't change: total, status"} 400         ← his own order, but not those fields
{"id":"ord_1001",...,"address":"44 FC Road, Pune",...} 200
{"error":"Order has already shipped"} 409               ← ord_1003 is delivered
```

🐛 **Bug lab 1: no owner check.** The same walk on the buggy route:

```bash
for i in 1001 1002 1003; do printf "ord_$i → "; curl -s http://localhost:3000/buggy/orders/ord_$i -H "Authorization: Bearer $R"; echo; done
```
→
```
ord_1001 → {"id":"ord_1001","userId":"u_rahul",...}
ord_1002 → {"id":"ord_1002","userId":"u_sneha","item":"Kanjeevaram saree","total":18500,"status":"placed","address":"7 Lodhi Colony, Delhi","phone":"98xxxxxx02"}   ← leaked
ord_1003 → {"id":"ord_1003","userId":"u_rahul",...}
```

🐛 **Bug lab 2: `?userId=` trusted from the client:**

```bash
curl "http://localhost:3000/buggy/orders?userId=u_sneha" -H "Authorization: Bearer $R"
curl "http://localhost:3000/orders?userId=u_sneha" -H "Authorization: Bearer $R"
```
→
```
{"orders":[{"id":"ord_1002","userId":"u_sneha","item":"Kanjeevaram saree",...,"address":"7 Lodhi Colony, Delhi","phone":"98xxxxxx02"}]}   ← Sneha's history
{"orders":[{"id":"ord_1001",...},{"id":"ord_1003",...}]}                                                                                ← fixed route ignores it
```

🐛 **Bug lab 3: mass assignment.** Ownership **is** checked, but the whole body is copied:

```bash
curl -X PATCH http://localhost:3000/buggy/orders/ord_1001 -H "Authorization: Bearer $R" -H "Content-Type: application/json" -d '{"total":1,"status":"delivered"}'
```
→ `{"id":"ord_1001","userId":"u_rahul","item":"Masala chai (500 g)","total":1,"status":"delivered",...}`: a ₹240 order now costs ₹1 and is marked delivered. Sending `{"userId":"u_sneha"}` even moves the order into Sneha's account.

> **Windows PowerShell users:** `login()`, `for` loops, `$R` and `PORT=... node ...` work in Git Bash. In PowerShell, use Git Bash, Postman, or `$env:PORT=3031; node server.js`.
