# 29. ABAC / Policy-Based Authorization

## Notes

### What is ABAC?

RBAC (topic 28) asks **"what is your role?"**. That works until the rule sounds like a sentence: *"support staff can refund orders **in their own city**, **up to ₹5,000**, **during office hours**, unless the order is **on legal hold**"*. A role can't hold all that. **ABAC (Attribute-Based Access Control)** decides using **attributes**: facts about the **user**, the **thing** they're touching, the **action**, and the **situation**.

> **One-line answer:** ABAC = **policies** (rules) over **attributes** of the **subject** (user: role, region, refund limit), the **resource** (order: owner, region, amount, legal hold), the **action** (`order:refund`) and the **environment** (time, network). A central **decide()** function evaluates the policies: **deny by default**, any matching **deny wins**, otherwise a matching **allow** lets the request through.

---

### Why does it matter?

| Problem with roles only | What ABAC does |
|---|---|
| "Support, Mumbai only, under ₹5,000" → `support_mumbai_small`, `support_delhi_small`, … (**role explosion**) | One rule: `resource.region === subject.region && resource.total <= subject.refundLimit` |
| RBAC says "can read **orders**", not **which** orders | `resource.customerId === subject.id`: Rahul sees only his own |
| "Not after office hours", "only from the office network" | Environment attributes: `env.hour`, `env.ip` |
| "Nobody, not even an admin, touches orders under legal hold" | A **deny** policy that overrides every allow |
| Rules hidden in `if`s across 40 routes | Policies in **one place**, readable, testable, auditable |

---

### Real-life example: a bank locker room 🏦

At an HDFC branch, the locker room door doesn't just ask "are you an employee?" (a role). It asks:

- **Who** is Priya? An employee, branch **Mumbai-Andheri**, a **joint key-holder** (subject attributes)
- **Which** locker? Locker #214, **branch Mumbai-Andheri**, belongs to Rahul, **sealed by court order** (resource attributes)
- **What** does she want? **Open** it (action)
- **When / where?** **11 am**, a **working day**, from **inside the branch** (environment)

The rule book says: *"Staff may open a locker of their own branch, with the customer present, during banking hours. No one opens a sealed locker."* That rule book is the **policy**. The guard who checks it is the **decision point**. The court seal is a **deny** that beats every "yes".

---

### The flow, step by step

#### 📊 Diagrams

Open **[diagrams.html](diagrams.html)** in your browser (just double-click the file) to see:

- **Flow diagram**: how `decide()` turns attributes and policies into allow or deny
- **Data flow**: Priya, Arjun and Amit trying refunds, and the same refund at 10 pm
- **The parts**: PEP, PDP, PIP and PAP, and which code in the demo plays each part

In short: `request → authenticate → load the resource → collect attributes (subject, resource, action, env) → decide(): any deny? → 403 : any allow? → go : 403 (default deny) → log the decision`.

---

### Step 1: Collect the attributes

```js
subject  = { id: "u_priya", role: "support", region: "Mumbai", refundLimit: 5000 } // from YOUR database
resource = { id: "ord_1", customerId: "u_rahul", region: "Mumbai", total: 240, legalHold: false }
action   = "order:refund"
env      = { hour: 11 }                                                           // from YOUR clock
```

| Kind | Examples | Where it must come from |
|---|---|---|
| **Subject** (who) | role, department, region, refund limit, clearance, MFA done? | Your database / a token **you** signed |
| **Resource** (what) | owner, region, amount, status, sensitivity, legal hold | Your database, loaded **before** deciding |
| **Action** | `order:read`, `order:refund` | Your route (not the client) |
| **Environment** (context) | time, IP / network, device, country | Your server's clock and connection |

| ✅ Do | ❌ Don't |
|---|---|
| Load attributes on the **server**, fresh | Trust `req.body.region` or an `X-Department` header |
| Take the time from **your** clock | Let the client send `?hour=11` |

---

### Step 2: Write policies

```js
{ id: "support-refunds-small-own-region-office-hours", effect: "allow", action: "order:refund",
  when: ({ subject, resource, env }) =>
    subject.role === "support" && resource.region === subject.region &&
    resource.total <= subject.refundLimit && env.hour >= 9 && env.hour < 18 },

{ id: "no-refund-on-legal-hold", effect: "deny", action: "order:refund",
  when: ({ resource }) => resource.legalHold === true },
```

- A **policy** = an **effect** (allow / deny) + an **action** + a **condition** over attributes.
- Give each one an **id**: when something is allowed or denied, the log says **which** rule did it.
- Roles don't disappear: `subject.role` is just **one attribute** among others. ABAC usually **builds on** RBAC.

---

### Step 3: Decide in one place (deny-overrides)

```js
function decide(action, subject, resource, env) {
  const matching = POLICIES.filter((p) => p.action === action && p.when({ subject, resource, env }));
  if (matching.some((p) => p.effect === "deny")) return { allowed: false };  // 1. any deny wins
  if (matching.some((p) => p.effect === "allow")) return { allowed: true };  // 2. else any allow
  return { allowed: false };                                                 // 3. else DENY by default
}
```

- **Default deny**: an action with no matching allow (a typo, a new action, a missing attribute) is refused.
- **Deny overrides**: the legal-hold rule beats the manager's "refund anything" rule. That's how you write "**never**, for anyone".
- Keep `decide()` **pure** (no database calls inside): easy to unit-test, as the demo's startup `assert`s do.

---

### Step 4: Enforce it in the route (after loading the resource)

```js
app.post("/orders/:id/refund", requireAuth, (req, res) => {
  const order = orders.get(req.params.id);
  if (!order) return res.status(404).json({ error: "Order not found" });
  if (!authorize(req, res, "order:refund", order)) return;   // 403 if decide() says no
  ...
});
```

- RBAC can run as middleware **before** the handler. ABAC needs the **resource's** attributes, so you **load it first**, then decide.
- **Lists** use the same policy as a **filter**: `GET /orders` returns only the orders `decide("order:read", …)` allows. Rahul gets his 3 orders, Sneha gets 1, Priya gets every Mumbai order.

---

### Step 5: Log every decision

```
✅ u_priya order:refund ord_1: allowed by support-refunds-small-own-region-office-hours
🚫 u_amit order:refund ord_4: denied by no-refund-on-legal-hold
```

"Why could Priya refund this?" and "Why was Amit blocked?" both have an answer: the policy id. Send the client only a generic `403` (the demo adds `debugReason` outside production, like topic 27).

---

### The standard names (XACML vocabulary)

| Part | What it does | In the demo |
|---|---|---|
| **PEP** (Policy Enforcement Point) | Stops the request, asks for a decision, obeys it | `authorize()` in each route |
| **PDP** (Policy Decision Point) | Evaluates policies → allow / deny | `decide()` |
| **PIP** (Policy Information Point) | Supplies attributes | `users` / `orders` Maps, the clock |
| **PAP** (Policy Administration Point) | Where policies are written and managed | The `POLICIES` array (or a policy repo / admin UI) |

Real tools: **OPA** (Open Policy Agent, policies in Rego), **AWS Cedar** / Amazon Verified Permissions, **Casbin**, **CASL** (JS). They're the same idea with a policy language and tooling. For relationship-based rules ("Priya can edit docs in folders shared with her team"), see **ReBAC / Zanzibar** (topic 71).

---

### 🤔 Tricky parts

**1. 403 or 404 for someone else's order?**
Rahul asks for Sneha's order `ord_2`. `403` tells him it **exists**. Many APIs return `404` so IDs can't be probed (topic 31). The demo uses `403` so you can see the decision.

**2. Missing attributes must deny.**
`resource.total <= subject.refundLimit` with `refundLimit` undefined is `false` in JS, so it denies. Good. But a condition like `!(resource.total > subject.refundLimit)` would **allow**. Write conditions so missing data means "no".

**3. Stale attributes.**
If attributes live inside a JWT (`region: "Mumbai"`), moving Priya to Delhi doesn't change tokens already issued. Load sensitive attributes fresh, like the demo does.

**4. Performance on lists.**
Filtering 1 million orders in JS is slow. Real systems turn the policy into a **database query** (`WHERE region = $1`), or tools like OPA/Cedar do "partial evaluation" for you.

**5. Policies are code.**
Review them, test them (one test per rule, plus "deny wins" and "default deny"), and version them. A one-character mistake in a policy is a security bug.

**6. Don't build XACML on day one.**
Start with RBAC + ownership checks. Move to ABAC when roles start multiplying or rules mention amounts, time, location or status.

---

### Common beginner mistakes

1. **Taking attributes from the request** (`req.body.region`, a client-sent time).
   The attacker sets them. Attributes come from your database, your signed tokens and your clock.

2. **Default allow.**
   "If no rule says no, let it through." New actions and typos become open doors. Default **deny**.

3. **Deciding before loading the resource.**
   You can't check `resource.region` you haven't read. Load, then decide.

4. **Scattering conditions across routes.**
   `if (user.region === order.region && …)` in 15 places will drift. One `decide()`.

5. **Forgetting lists.**
   `GET /orders/:id` is protected, but `GET /orders` returns everything. Filter with the same policy.

6. **"Allow" rules for "never" cases.**
   Writing legal hold as "allow if not on hold" in every allow rule means one forgotten rule leaks. Use a single **deny** policy.

7. **No decision log.**
   Without the policy id in the logs, nobody can explain an allow or a deny later.

---

### Interview questions

1. **What is ABAC?**
   Access control where policies decide using attributes of the subject, resource, action and environment, instead of only the user's role.

2. **RBAC vs ABAC?**
   RBAC: roles map to permissions; simple, coarse. ABAC: rules over attributes; fine-grained (owner, amount, region, time), but more complex. Most real systems use RBAC plus some ABAC rules.

3. **What is role explosion?**
   Creating a new role for every combination of conditions (`support_mumbai_under5k`). ABAC replaces those with one attribute-based rule.

4. **Name the four attribute categories.**
   Subject, resource, action, environment (context).

5. **What are PEP and PDP?**
   The PEP intercepts the request and enforces the decision; the PDP evaluates policies and returns allow/deny. (PIP supplies attributes, PAP manages policies.)

6. **What does deny-overrides mean?**
   If any matching policy denies, the result is deny, even if others allow. Combined with default deny when nothing matches.

7. **How do you apply ABAC to list endpoints?**
   Filter results through the same policy, or translate the policy into a database query so only allowed rows are fetched.

8. **Name some ABAC / policy tools.**
   OPA (Rego), AWS Cedar / Verified Permissions, Casbin, CASL. XACML is the older standard that defined PEP/PDP/PIP/PAP.

9. **Where should the time for a "business hours" rule come from?**
   The server's clock, in the right time zone. Never from the client.

---

### Quick recap

- ABAC = **policies over attributes**: subject, resource, action, environment
- Solves **role explosion** and rules like "own region, under ₹5,000, office hours"
- Attributes come from **your** database, signed tokens and clock, never the client
- One **`decide()`**: **default deny**, **deny overrides**, then allow
- **Load the resource first**, then decide; **filter lists** with the same policy
- **Log** the policy id for every decision; generic `403` to the client
- PEP enforces, PDP decides, PIP supplies attributes, PAP manages policies
- Tools: OPA, Cedar, Casbin, CASL. Next: making guards impossible to forget (topic 30)

## Code

A small **Express** API over the same tea shop as topic 28, but now refunds follow **rules**, not just roles. `decide()` is a ~10-line policy engine with **default deny** and **deny overrides**. Every route loads the order, then calls `authorize()`, and every decision is logged with the policy id.

| User | Attributes |
|---|---|
| `rahul`, `sneha` | customer (Mumbai / Delhi) |
| `priya` | support, Mumbai, refund limit ₹5,000 |
| `arjun` | support, Delhi, refund limit ₹5,000 |
| `amit` | manager |

| Order | Owner | Region | Total | Note |
|---|---|---|---|---|
| `ord_1` | Rahul | Mumbai | ₹240 | |
| `ord_2` | Sneha | Delhi | ₹180 | |
| `ord_3` | Rahul | Mumbai | ₹12,000 | over support's limit |
| `ord_4` | Rahul | Mumbai | ₹900 | **legal hold** |

Every demo user's password is `chai1234`. Refunds are only allowed **9 am – 6 pm India time**; the demo lets you fake the hour with `DEMO_HOUR`.

📄 **Full code: [server.js](server.js)**. Open it and read the comments, which follow the same steps as the notes above.

Install the dependencies once (from this folder), then start the server (here at a pretend 11 am):

```bash
npm install
```

```bash
DEMO_HOUR=11 node server.js
```

> Port 3000 busy? Run it on another port: `PORT=3029 DEMO_HOUR=11 node server.js` (Git Bash), then use that port in the commands below. Without `DEMO_HOUR` it uses the real time in India.

### Try it

✅ **Log in as everyone** (Git Bash):

```bash
login() { curl -s http://localhost:3000/login -H "Content-Type: application/json" -d "{\"username\":\"$1\",\"password\":\"chai1234\"}" | grep -o '"accessToken":"[^"]*' | cut -d'"' -f4; }
R=$(login rahul); S=$(login sneha); P=$(login priya); AR=$(login arjun); A=$(login amit)
```

```bash
curl http://localhost:3000/me -H "Authorization: Bearer $P"
```
→ `{"id":"u_priya","username":"priya","role":"support","region":"Mumbai","refundLimit":5000,"hourIST":11}`

🧪 **Same list endpoint, filtered by the policy:**

```bash
for u in R S P AR A; do printf "%-3s → " $u; curl -s http://localhost:3000/orders -H "Authorization: Bearer ${!u}" | grep -o '"id":"ord_[0-9]"' | tr '\n' ' '; echo; done
```
→
```
R   → "id":"ord_1" "id":"ord_3" "id":"ord_4"
S   → "id":"ord_2"
P   → "id":"ord_1" "id":"ord_3" "id":"ord_4"
AR  → "id":"ord_2"
A   → "id":"ord_1" "id":"ord_2" "id":"ord_3" "id":"ord_4"
```

❌ **Rahul reads Sneha's order:**

```bash
curl http://localhost:3000/orders/ord_2 -H "Authorization: Bearer $R"
```
→ `403 {"error":"You don't have permission to do this","debugReason":"no policy allows this (default deny)"}`

🧪 **Refunds at 11 am:**

```bash
ref() { printf "%-6s %s → " $1 $2; curl -s -X POST http://localhost:3000/orders/$2/refund -H "Authorization: Bearer $3" -w " %{http_code}"; echo; }
ref rahul ord_1 $R; ref priya ord_2 $P; ref priya ord_3 $P; ref priya ord_4 $P; ref amit ord_4 $A
ref priya ord_1 $P; ref priya ord_1 $P; ref arjun ord_2 $AR; ref amit ord_3 $A
```
→
```
rahul  ord_1 → {"error":"You don't have permission to do this","debugReason":"no policy allows this (default deny)"} 403
priya  ord_2 → {"error":"You don't have permission to do this","debugReason":"no policy allows this (default deny)"} 403
priya  ord_3 → {"error":"You don't have permission to do this","debugReason":"no policy allows this (default deny)"} 403
priya  ord_4 → {"error":"You don't have permission to do this","debugReason":"denied by no-refund-on-legal-hold"} 403
amit   ord_4 → {"error":"You don't have permission to do this","debugReason":"denied by no-refund-on-legal-hold"} 403
priya  ord_1 → {"id":"ord_1","customerId":"u_rahul","region":"Mumbai","item":"Masala chai (500 g)","total":240,"status":"refunded","legalHold":false} 200
priya  ord_1 → {"error":"Order is already refunded"} 409
arjun  ord_2 → {"id":"ord_2","customerId":"u_sneha","region":"Delhi","item":"Filter coffee (250 g)","total":180,"status":"refunded","legalHold":false} 200
amit   ord_3 → {"id":"ord_3","customerId":"u_rahul","region":"Mumbai","item":"Espresso machine","total":12000,"status":"refunded","legalHold":false} 200
```

Read it line by line: customers can't refund; Priya can't refund a **Delhi** order (`ord_2`) or one **over her limit** (`ord_3`); **nobody**, not even manager Amit, can refund the order on **legal hold** (`ord_4`, deny overrides); Arjun can refund the Delhi one; Amit can refund the big one.

🌙 **Same refunds at 10 pm.** Stop the server and restart it with `DEMO_HOUR=22 node server.js`, log in again, then:

```bash
ref priya ord_1 $P; ref amit ord_3 $A
```
→
```
priya  ord_1 → {"error":"You don't have permission to do this","debugReason":"no policy allows this (default deny)"} 403
amit   ord_3 → {"error":"You don't have permission to do this","debugReason":"no policy allows this (default deny)"} 403
```

Reading still works at night (`GET /orders/ord_1` as Priya → `200`): only the refund rules check the hour.

📋 **The decision log** in the terminal says which policy made each call:

```
🚫 u_rahul order:read ord_2: no policy allows this (default deny)
✅ u_rahul order:read ord_1: allowed by customer-reads-own-order
🚫 u_priya order:refund ord_4: denied by no-refund-on-legal-hold
🚫 u_amit order:refund ord_4: denied by no-refund-on-legal-hold
✅ u_priya order:refund ord_1: allowed by support-refunds-small-own-region-office-hours
💸 u_priya refunded ord_1 (₹240)
✅ u_amit order:refund ord_3: allowed by manager-refunds-office-hours
💸 u_amit refunded ord_3 (₹12000)
```

With `NODE_ENV=production` the `debugReason` disappears from responses; the log still has it.

> **Windows PowerShell users:** `login()`, `ref()`, `for` loops, `${!u}` and `DEMO_HOUR=11 node ...` work in Git Bash. In PowerShell, use Git Bash, Postman, or `$env:DEMO_HOUR=11; node server.js`.
