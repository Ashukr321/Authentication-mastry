# 30. Route Guards & Middleware

## Notes

### What is a route guard?

Topics 28 and 29 decided **what** a user may do. A **route guard** is **where** that decision is enforced: a small piece of **middleware** that runs **before** the route handler and either lets the request through (`next()`) or stops it (`401` / `403`). The hard part isn't writing one guard. It's making sure **every** route has the right one, **in the right order**, and that **no bug lets a request slip past**.

> **One-line answer:** a route guard is middleware that runs before the handler and answers "may this request continue?": `return next()` for yes, `return res.status(401|403)…` for no. Make guards **impossible to forget**: authenticate once globally, protect whole groups with `router.use(guard)`, force every route to **declare** its access (`"public"`, `"user"`, `{ permission }`), and deny by default.

---

### Why does it matter?

Most real authorization bugs aren't wrong rules. They're **missing or broken guards**:

| Bug | What happens |
|---|---|
| A new route with no guard | `DELETE /api/products/:id` is open to the internet |
| Guard on `GET`, not on `DELETE` of the same path | Reading is protected, deleting isn't |
| Guard sends `403` but forgets `return` | The client sees "Forbidden", **and the delete still happens** |
| Hand-written `req.path.startsWith("/admin")` | `/ADMIN/...` matches the route but skips the check |
| A route registered **above** `router.use(requireAuth)` | That route is public |
| Each developer writes their own check | Some check `401`, some forget the role, some log, some don't |

(OWASP's #1 API risk, "Broken Object Level / Function Level Authorization", is mostly this.)

---

### Real-life example: an office building 🏢

Rahul visits Priya's office in Bengaluru.

- **Reception** checks everyone's ID once and gives a visitor badge → **authenticate** (global middleware sets `req.user`)
- The **lift lobby** is open to all badge holders → `"user"` routes
- The **server room floor** has a card reader at the **floor entrance**, not on each rack → **router-level guard** (`admin.use(...)`)
- The **finance cabin** inside also has its own lock → a **per-route permission**
- The building **won't open a new room** until facilities says who may enter it → **routes must declare access** or the app won't start
- A guard who says "you can't go in" **and then holds the door open** → the **missing `return`** bug

---

### The flow, step by step

#### 📊 Diagrams

Open **[diagrams.html](diagrams.html)** in your browser (just double-click the file) to see:

- **Flow diagram**: the middleware chain a request goes through, and where it can stop
- **Data flow**: the three classic guard bugs from the demo's bug lab, and why they leak
- **Structure**: how the app is organised: global authenticate, public routes, user routes, the guarded admin router

In short: `request → express.json → authenticate (sets req.user or 401 for a bad token) → route found → its guards (requireAuth → requirePermission) → handler → 404 / error handler`. Every route says who may call it; a route that doesn't **won't even start**.

---

### Step 1: Authenticate once, globally

```js
app.use((req, res, next) => {
  req.user = null;
  if (!req.headers.authorization) return next();      // anonymous: guards decide later
  const user = findUserByToken(...);
  if (!user) return res.status(401).json({ error: "Invalid or expired token" });
  req.user = user;
  next();
});
```

- **Authentication** (who are you?) runs for **every** request, in **one** place. It **doesn't block** anonymous users; the guards do.
- A token that's **present but wrong** is always `401`, even on public routes. Silently treating it as "anonymous" hides bugs.

---

### Step 2: Write guards the safe way

```js
function requireAuth(req, res, next) {
  if (req.user) return next();
  return res.status(401).json({ error: "Please log in" });
}

function requirePermission(permission) {               // a guard FACTORY
  return (req, res, next) => {
    if (!req.user) return res.status(401).json({ error: "Please log in" });
    if (can(req.user, permission)) return next();
    return res.status(403).json({ error: "You don't have permission to do this" });
  };
}
```

| ✅ Do | ❌ Don't |
|---|---|
| `return next()` / `return res.status(...)` | `res.status(403).json(...)` with no `return`, then `next()` |
| One guard = one question | One giant guard with 15 `if`s |
| A factory for parameters: `requirePermission("x")` | Copy-paste a guard per permission |
| Guards that also work alone (check `req.user`) | Assume another guard already ran |

**Async guards** (that load from a database): in **Express 5**, a rejected promise goes to the error handler automatically. In **Express 4** you need `try/catch` or a wrapper, or the request hangs.

---

### Step 3: Make every route declare its access

```js
route("get",    "/products",     "public",                       listProducts);
route("get",    "/me",           "user",                         me);
route("post",   "/products",     { permission: "products:write" }, createProduct);
route("delete", "/products/:id", { permission: "products:write" }, deleteProduct);
route("get",    "/forgot", handler);  // ❌ throws at STARTUP: declare access as "public", "user" or { permission }
```

- `route()` is a tiny wrapper over `app.get/post/...` that **adds the guards for you**.
- Forgetting the access isn't a security hole anymore; it's a **crash on startup**, found by the developer, not by an attacker.
- Every **method** is its own line, so `DELETE` can't "inherit" `GET`'s protection by accident.
- `"public"` must be written out. Being public is a decision, never a default.

---

### Step 4: Guard whole groups with a router

```js
const admin = express.Router();
admin.use(requireAuth, requirePermission("admin:access"));  // runs before EVERY admin route
admin.get("/stats", ...);
admin.get("/users", requirePermission("users:manage"), ...); // extra, stricter guard for one route
app.use("/admin", admin);
```

- New admin routes added next year are protected **automatically**.
- `app.use("/admin", ...)` matches paths **the same way** routes do (`/ADMIN/stats`, `/admin/stats/`), so there's no gap. A hand-written `req.path.startsWith("/admin")` is case-sensitive and does have a gap.
- **Order matters**: middleware only protects what's registered **after** it.
- Unknown paths under `/admin` return `403` to non-admins and `404` to admins, so outsiders can't map out admin routes.

---

### Step 5: Review the access table

At startup the demo prints every route and who may call it:

```
│ 'GET /products'        │ 'public'         │
│ 'DELETE /products/:id' │ 'products:write' │
│ 'GET /admin/users'     │ 'users:manage'   │
```

In code review, "what's public?" is one glance. In bigger apps, the same table becomes a **test**: "every route except this allow-list needs a login".

---

### 🤔 Tricky parts

**1. `next()` doesn't stop your function.**
`next()` just calls the next middleware; your code keeps running after it returns. That's why every branch needs `return`.

**2. `res.status(403)` doesn't stop anything either.**
Sending a response doesn't end your function. If code after it calls `next()` or changes data, it **still happens**. The log message `Cannot set headers after they are sent` is a sign of this bug.

**3. Case and trailing slashes.**
Express routing ignores case and a trailing slash by default (`caseSensitive` and `strict` are `false`). Your own string checks don't. Let Express do the path matching: `app.use("/admin", guard)`.

**4. Method-level holes.**
`app.get("/orders/:id", guard, ...)` doesn't protect `app.put("/orders/:id", ...)`. Also watch `app.all` and `HEAD` (Express answers `HEAD` with the `GET` handler, guards included).

**5. Guards on the frontend are UX only.**
React/Next.js route guards that redirect to `/login` are nice, but the API must guard every endpoint itself.

**6. Guards aren't ownership checks.**
`requirePermission("orders:read")` says "you may read orders", not "this order is yours". That check needs the loaded resource (topic 31).

---

### Common beginner mistakes

1. **Forgetting `return` before `res.status(...)` in a guard.**
   The handler still runs. Always `return res...` and `return next()`.

2. **Adding guards route by route, by hand.**
   One day someone forgets. Use a router guard or a `route()` helper that forces a decision.

3. **Protecting `GET` but not `POST`/`PUT`/`DELETE` on the same path.**
   Each method is a separate route.

4. **Hand-written path checks** (`startsWith`, regex on `req.url`).
   Case, encoding and trailing slashes slip past. Mount guards with `app.use(path, guard)`.

5. **Registering routes above the guard.**
   `router.use(guard)` only covers what comes after it.

6. **Treating a bad token as anonymous.**
   Return `401`; don't quietly continue as a guest.

7. **Unhandled async errors in guards (Express 4).**
   The request hangs or the process crashes. Use Express 5 or wrap async middleware.

8. **Only guarding in the frontend.**
   curl doesn't run your React code.

---

### Interview questions

1. **What is middleware in Express?**
   A function `(req, res, next)` that runs in order for matching requests. It can change `req`/`res`, end the response, or call `next()` to pass control on.

2. **What is a route guard?**
   Middleware that decides whether a request may reach the handler: `next()` to continue, `401`/`403` to stop.

3. **Why `return next()` and `return res.status(...)`?**
   Neither `next()` nor sending a response stops the function. Without `return`, code after it still runs, which can perform the forbidden action.

4. **How do you make sure no route is left unprotected?**
   Deny by default: authenticate globally, protect groups with router-level guards, require each route to declare its access (fail at startup otherwise), and test that every non-public route needs auth.

5. **Where should authentication vs authorization middleware go?**
   Authentication first (global), then authorization guards per router/route, then the handler.

6. **What is a guard factory?**
   A function that takes options and returns middleware: `requirePermission("products:write")`.

7. **Why is `req.path.startsWith("/admin")` a bad guard?**
   It's case-sensitive and ignores encoding/trailing slash differences, while Express routing isn't. Mount the guard with `app.use("/admin", guard)` so it matches exactly the same paths.

8. **How does Express 5 differ for async middleware?**
   Rejected promises are passed to the error handler automatically. Express 4 needed `try/catch` + `next(err)`.

9. **401 or 403 for an unknown admin URL?**
   For non-admins, the router guard answers first (`401`/`403`), which hides which admin routes exist. Admins get `404`.

---

### Quick recap

- A guard = middleware: `return next()` or `return res.status(401|403)`
- **Authenticate once**, globally; a bad token is `401`, no token = anonymous
- **Guard factories** for parameters: `requirePermission("x")`
- **Router-level guards** protect whole groups, including future routes
- Force every route to **declare** its access; forgetting = **startup crash**
- Every **method** needs its own guard; **order** of registration matters
- Let Express match paths; don't hand-write `startsWith` checks
- Print/test an **access table** so "what's public?" is obvious
- Next: checking that the **specific record** belongs to the user (topic 31)

## Code

A small **Express** shop API built **secure by default**: a global `authenticate` middleware, two guards (`requireAuth`, `requirePermission(...)`), a `route()` helper that refuses to register a route without declared access, and an `/admin` router with one guard for everything inside it. A **bug lab** under `/buggy/...` shows three real guard bugs next to the fixed code.

| User | Role | Permissions |
|---|---|---|
| `rahul` | customer | none |
| `neha` | editor | `products:write` |
| `amit` | admin | `products:write`, `admin:access`, `users:manage` |

Every demo user's password is `chai1234`.

📄 **Full code: [server.js](server.js)**. Open it and read the comments, which follow the same steps as the notes above.

Install the dependencies once (from this folder), then start the server:

```bash
npm install
```

```bash
node server.js
```

> Port 3000 busy? Run it on another port: `PORT=3030 node server.js` (Git Bash), then use that port in the commands below.

On startup it prints the **access table**:

```
┌─────────┬────────────────────────┬──────────────────┐
│ (index) │ route                  │ access           │
├─────────┼────────────────────────┼──────────────────┤
│ 0       │ 'GET /health'          │ 'public'         │
│ 1       │ 'POST /login'          │ 'public'         │
│ 2       │ 'GET /me'              │ 'user'           │
│ 3       │ 'GET /products'        │ 'public'         │
│ 4       │ 'POST /products'       │ 'products:write' │
│ 5       │ 'DELETE /products/:id' │ 'products:write' │
│ 6       │ 'GET /admin/stats'     │ 'admin:access'   │
│ 7       │ 'GET /admin/users'     │ 'users:manage'   │
└─────────┴────────────────────────┴──────────────────┘
```

### Try it

✅ **Log in** (Git Bash):

```bash
login() { curl -s http://localhost:3000/login -H "Content-Type: application/json" -d "{\"username\":\"$1\",\"password\":\"chai1234\"}" | grep -o '"accessToken":"[^"]*' | cut -d'"' -f4; }
R=$(login rahul); N=$(login neha); A=$(login amit)
```

🧪 **Public, user and bad-token routes:**

```bash
curl http://localhost:3000/products
curl http://localhost:3000/me
curl http://localhost:3000/me -H "Authorization: Bearer $R"
curl http://localhost:3000/products -H "Authorization: Bearer wrong"
```
→
```
{"products":[{"id":"p_1","name":"Masala chai (500 g)","price":240}]} 200
{"error":"Please log in"} 401
{"id":"u_rahul","role":"customer"} 200
{"error":"Invalid or expired token"} 401      (a bad token is never treated as "anonymous")
```

🧪 **Each method has its own guard:**

```bash
curl -X POST http://localhost:3000/products -H "Authorization: Bearer $R" -H "Content-Type: application/json" -d '{"name":"Elaichi","price":150}'
curl -X POST http://localhost:3000/products -H "Authorization: Bearer $N" -H "Content-Type: application/json" -d '{"name":"Elaichi","price":150}'
curl -X DELETE http://localhost:3000/products/p_1 -H "Authorization: Bearer $R"
curl -X DELETE http://localhost:3000/products/p_1 -H "Authorization: Bearer $N"
```
→
```
{"error":"You don't have permission to do this"} 403
{"id":"p_86b4bd57","name":"Elaichi","price":150} 201
{"error":"You don't have permission to do this"} 403
204
```

🧪 **The admin router guards everything under `/admin`**, any case, including paths that don't exist:

```bash
curl http://localhost:3000/admin/stats
curl http://localhost:3000/admin/stats -H "Authorization: Bearer $N"
curl http://localhost:3000/ADMIN/stats -H "Authorization: Bearer $N"
curl http://localhost:3000/admin/stats -H "Authorization: Bearer $A"
curl http://localhost:3000/admin/nope -H "Authorization: Bearer $R"
curl http://localhost:3000/admin/nope -H "Authorization: Bearer $A"
```
→
```
{"error":"Please log in"} 401
{"error":"You don't have permission to do this"} 403
{"error":"You don't have permission to do this"} 403     (/ADMIN is guarded too)
{"users":3,"products":1} 200
{"error":"You don't have permission to do this"} 403     (outsiders can't tell which admin URLs exist)
{"error":"Not found"} 404
```

🐛 **Bug lab 1: the missing `return`.** Rahul (a customer) deletes a product:

```bash
curl -X DELETE http://localhost:3000/buggy/products/p_2 -H "Authorization: Bearer $R"
curl http://localhost:3000/buggy/products
```
→
```
{"error":"Admins only"} 403
{"products":[{"id":"p_1","name":"Masala chai (500 g)"}]}       ← p_2 is GONE
```
The terminal shows the tell-tale sign:
```
⚠️  error after the response was already sent (DELETE /buggy/products/p_2): Cannot set headers after they are sent to the client
```

🐛 **Bug lab 2: a hand-written `startsWith` check.** Same route, different case:

```bash
curl http://localhost:3000/buggy/admin/secrets
curl http://localhost:3000/BUGGY/ADMIN/secrets
```
→
```
{"error":"Admins only"} 403
{"secret":"UPI merchant key: demo-123"} 200      ← no token at all!
```

🐛 **Bug lab 3: a route registered above `router.use(requireAuth)`:**

```bash
curl http://localhost:3000/buggy/reports
curl http://localhost:3000/buggy/profile
```
→
```
{"report":"Today's sales: ₹48,000"} 200     ← above the guard: public
{"error":"Please log in"} 401               ← below the guard: protected
```

✅ **A route with no declared access doesn't start.** Add `route("get", "/forgot", (req, res) => res.json({}));` to `server.js` and run it:

```
Error: GET /forgot: declare access as "public", "user" or { permission }
```

> **Windows PowerShell users:** `login()`, `$R` and `PORT=... node ...` work in Git Bash. In PowerShell, use Git Bash, Postman, or `$env:PORT=3030; node server.js`.
