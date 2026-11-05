const express = require("express");
const crypto = require("crypto");
const { promisify } = require("util");

const scrypt = promisify(crypto.scrypt);
const SCRYPT_OPTIONS = { N: 2 ** 17, r: 8, p: 1, maxmem: 256 * 1024 * 1024 };

const PORT = Number(process.env.PORT) || 3000;
const TOKEN_TTL_MS = 60 * 60 * 1000;

// Roles → permissions, as in topic 28
const ROLE_PERMISSIONS = {
  customer: [],
  editor: ["products:write"],
  admin: ["products:write", "admin:access", "users:manage"],
};

// ---------- "Database" ----------
// shortcut: in-memory Maps, lost on restart. A real app uses database tables.
const users = new Map([
  ["u_rahul", { id: "u_rahul", username: "rahul", role: "customer" }],
  ["u_neha", { id: "u_neha", username: "neha", role: "editor" }],
  ["u_amit", { id: "u_amit", username: "amit", role: "admin" }],
]);
const tokens = new Map(); // sha256(token) -> { userId, expiresAt }
const products = new Map([["p_1", { id: "p_1", name: "Masala chai (500 g)", price: 240 }]]);

async function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const hash = await scrypt(password, salt, 64, SCRYPT_OPTIONS);
  return `${salt.toString("hex")}:${hash.toString("hex")}`;
}
async function verifyPassword(password, stored) {
  const [saltHex, hashHex] = stored.split(":");
  const attempt = await scrypt(password, Buffer.from(saltHex, "hex"), 64, SCRYPT_OPTIONS);
  return crypto.timingSafeEqual(attempt, Buffer.from(hashHex, "hex"));
}
const DUMMY_HASH_PROMISE = hashPassword("dummy-password-never-used");
const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");
// Password for every demo user: "chai1234" (demo only!)
const ready = Promise.all([...users.values()].map(async (u) => { u.passwordHash = await hashPassword("chai1234"); }));

const app = express();
app.use(express.json({ limit: "10kb" }));
app.use((req, res, next) => { res.set("Cache-Control", "no-store"); next(); });

// ---------- Step 1: AUTHENTICATE once, for every request ----------
// Reads the token if there is one and sets req.user (or null). It does NOT block: the guards below decide.
// A token that is present but wrong is always an error, even on public routes.
app.use((req, res, next) => {
  req.user = null;
  const header = req.headers.authorization;
  if (!header) return next();
  const [scheme, token] = header.split(" ");
  const record = scheme === "Bearer" && token && tokens.get(sha256(token));
  if (!record || record.expiresAt < Date.now() || !users.get(record.userId)) return res.status(401).json({ error: "Invalid or expired token" });
  req.user = users.get(record.userId); // loaded fresh: role changes apply at once
  next();
});

// ---------- Step 2: GUARDS = small middleware that say yes (next) or no (respond) ----------
// Every "no" path RETURNS. Every "yes" path is `return next()`. Nothing runs after either.
function requireAuth(req, res, next) {
  if (req.user) return next();
  return res.status(401).json({ error: "Please log in" });
}

// A guard FACTORY: call it with a permission, get back a guard for that permission
function requirePermission(permission) {
  return function permissionGuard(req, res, next) {
    if (!req.user) return res.status(401).json({ error: "Please log in" }); // works even if someone forgot requireAuth before it
    if (ROLE_PERMISSIONS[req.user.role]?.includes(permission)) return next();
    console.log(`🚫 ${req.user.id} (${req.user.role}) needs ${permission} for ${req.method} ${req.originalUrl}`);
    return res.status(403).json({ error: "You don't have permission to do this" });
  };
}

// ---------- Step 3: SECURE BY DEFAULT: a route can't be registered without saying who may call it ----------
const ROUTES = []; // the access table, printed at startup
function secureRoutes(router, prefix = "") {
  return function route(method, path, access, ...handlers) {
    let guards;
    if (access === "public") guards = [];
    else if (access === "user") guards = [requireAuth];
    else if (typeof access?.permission === "string") guards = [requireAuth, requirePermission(access.permission)];
    else throw new Error(`${method.toUpperCase()} ${prefix}${path}: declare access as "public", "user" or { permission }`); // fails at STARTUP, not in production
    ROUTES.push({ route: `${method.toUpperCase()} ${prefix}${path}`, access: access.permission ?? access });
    router[method](path, ...guards, ...handlers);
  };
}
const route = secureRoutes(app);

route("get", "/health", "public", (req, res) => res.json({ ok: true }));

route("post", "/login", "public", async (req, res) => {
  const { username, password } = req.body ?? {};
  if (typeof username !== "string" || typeof password !== "string") return res.status(400).json({ error: "username and password are required" });
  await ready;
  const user = [...users.values()].find((u) => u.username === username.toLowerCase());
  const ok = await verifyPassword(password, user?.passwordHash ?? (await DUMMY_HASH_PROMISE)); // same timing for unknown users
  if (!user || !ok) return res.status(401).json({ error: "Wrong username or password" });
  const token = crypto.randomBytes(32).toString("base64url");
  tokens.set(sha256(token), { userId: user.id, expiresAt: Date.now() + TOKEN_TTL_MS });
  res.json({ accessToken: token });
});

route("get", "/me", "user", (req, res) => res.json({ id: req.user.id, role: req.user.role }));

route("get", "/products", "public", (req, res) => res.json({ products: [...products.values()] }));

route("post", "/products", { permission: "products:write" }, (req, res) => {
  const { name, price } = req.body ?? {};
  if (typeof name !== "string" || !name.trim() || name.length > 100) return res.status(400).json({ error: "name must be 1-100 characters" });
  if (!Number.isInteger(price) || price <= 0) return res.status(400).json({ error: "price must be a positive whole number of rupees" });
  const product = { id: `p_${crypto.randomUUID().slice(0, 8)}`, name: name.trim(), price };
  products.set(product.id, product);
  res.status(201).json(product);
});

// Same path, different method: DELETE gets its OWN guard. A guard on GET protects nothing else.
route("delete", "/products/:id", { permission: "products:write" }, (req, res) => {
  if (!products.delete(req.params.id)) return res.status(404).json({ error: "Product not found" });
  res.status(204).end();
});

// ---------- Step 4: GROUP GUARDS: one router, one guard for everything inside it ----------
// app.use("/admin", ...) matches /admin, /ADMIN, /admin/ the SAME way the routes do, so there is no case/slash gap.
const admin = express.Router();
admin.use(requireAuth, requirePermission("admin:access")); // runs before EVERY admin route, including future ones
const adminRoute = secureRoutes(admin, "/admin");
adminRoute("get", "/stats", { permission: "admin:access" }, (req, res) => res.json({ users: users.size, products: products.size }));
adminRoute("get", "/users", { permission: "users:manage" }, (req, res) =>
  res.json({ users: [...users.values()].map(({ id, username, role }) => ({ id, username, role })) }));
app.use("/admin", admin);

// =====================================================================================
// 🐛 BUG LAB: three real guard bugs, side by side with the fixed app above. NEVER copy these.
// shortcut: dev-only routes in the same file so the demo is one process.
// =====================================================================================
const buggyProducts = new Map([["p_1", { id: "p_1", name: "Masala chai (500 g)" }], ["p_2", { id: "p_2", name: "Kesar (10 g)" }]]);

// Bug 1: the guard sends 403 but forgets `return`, so next() still runs the handler
function buggyRequireAdmin(req, res, next) {
  if (req.user?.role !== "admin") {
    res.status(403).json({ error: "Admins only" }); // ❌ no return
  }
  next(); // ❌ runs for everyone
}
app.get("/buggy/products", (req, res) => res.json({ products: [...buggyProducts.values()] }));
app.delete("/buggy/products/:id", buggyRequireAdmin, (req, res) => {
  buggyProducts.delete(req.params.id); // ❌ the delete happens even though the client was told 403
  res.json({ deleted: req.params.id }); // throws "Cannot set headers after they are sent": see the error handler log
});

// Bug 2: a hand-written prefix check. Express routes ignore case, startsWith() doesn't.
app.use((req, res, next) => {
  if (req.path.startsWith("/buggy/admin") && req.user?.role !== "admin") return res.status(403).json({ error: "Admins only" });
  next();
});
app.get("/buggy/admin/secrets", (req, res) => res.json({ secret: "UPI merchant key: demo-123" })); // /BUGGY/ADMIN/secrets skips the check

// Bug 3: order. A route registered BEFORE router.use(requireAuth) is not protected by it.
const buggyRouter = express.Router();
buggyRouter.get("/reports", (req, res) => res.json({ report: "Today's sales: ₹48,000" })); // ❌ above the guard
buggyRouter.use(requireAuth);
buggyRouter.get("/profile", (req, res) => res.json({ id: req.user.id }));                  // ✅ below the guard
app.use("/buggy", buggyRouter);

// ---------- Default: anything not matched is 404 ----------
app.use((req, res) => res.status(404).json({ error: "Not found" }));

// Errors (bad JSON, body too big, bugs) come here. Never send the stack trace to the client.
app.use((err, req, res, next) => {
  // An error AFTER the response was sent usually means a guard or handler forgot `return` (bug 1)
  if (res.headersSent) return console.error(`⚠️  error after the response was already sent (${req.method} ${req.originalUrl}): ${err.message}`);
  if (err.type === "entity.parse.failed") return res.status(400).json({ error: "Body must be valid JSON" });
  if (err.type === "entity.too.large") return res.status(413).json({ error: "Request body too large" });
  console.error(err);
  res.status(500).json({ error: "Something went wrong" });
});

ready.then(() => app.listen(PORT, () => {
  console.log(`Route guards demo on http://localhost:${PORT} (users rahul, neha, amit; password chai1234)`);
  console.table(ROUTES); // Step 5: an access table you can review: every route and who may call it
}));
