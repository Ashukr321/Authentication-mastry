const express = require("express");
const crypto = require("crypto");
const assert = require("assert");
const { promisify } = require("util");

const scrypt = promisify(crypto.scrypt);
const SCRYPT_OPTIONS = { N: 2 ** 17, r: 8, p: 1, maxmem: 256 * 1024 * 1024 };

const PORT = Number(process.env.PORT) || 3000;
const TOKEN_TTL_MS = 60 * 60 * 1000; // access tokens live 1 hour

// ---------- Step 1: PERMISSIONS = the actions your app has ----------
// Name them "resource:action". Routes check THESE, never role names.
const PERMISSIONS = ["products:read", "products:write", "orders:read_all", "orders:refund", "users:manage"];

// ---------- Step 2: ROLES = named bundles of permissions ----------
// shortcut: hard-coded in code. Big apps keep roles/permissions in tables so admins can edit them without a deploy.
const ROLE_PERMISSIONS = {
  customer: ["products:read"],
  support:  ["products:read", "orders:read_all", "orders:refund"],
  editor:   ["products:read", "products:write"],
  admin:    [...PERMISSIONS], // listed out explicitly: no magic "*" that silently grants future permissions
};
const ROLES = Object.keys(ROLE_PERMISSIONS);

// A user can have several roles: their permissions are the UNION of all of them.
function permissionsOf(roles) {
  return new Set(roles.flatMap((role) => ROLE_PERMISSIONS[role] ?? [])); // unknown role = no permissions (fail closed)
}

// Tiny self-check of the security core: runs on every start.
assert.ok(permissionsOf(["customer"]).has("products:read"));
assert.ok(!permissionsOf(["customer"]).has("orders:refund"));
assert.ok(permissionsOf(["customer", "editor"]).has("products:write"));
assert.equal(permissionsOf(["ghost-role"]).size, 0);

// ---------- "Database" ----------
// shortcut: in-memory Maps, lost on restart. A real app uses tables: users, roles, permissions, user_roles, role_permissions.
const users = new Map();    // userId -> { id, username, name, passwordHash, roles: [] }
const tokens = new Map();   // sha256(token) -> { userId, expiresAt }
const products = new Map([["p_1", { id: "p_1", name: "Masala chai (500 g)", price: 240 }]]);
const orders = new Map([
  ["ord_1", { id: "ord_1", customer: "u_rahul", item: "Masala chai (500 g)", total: 240, status: "paid" }],
  ["ord_2", { id: "ord_2", customer: "u_sneha", item: "Filter coffee (250 g)", total: 180, status: "paid" }],
]);

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

// Demo users. Password for everyone: "chai1234" (demo only!)
const SEED = [
  { id: "u_rahul", username: "rahul", name: "Rahul (customer)", roles: ["customer"] },
  { id: "u_priya", username: "priya", name: "Priya (support)", roles: ["support"] },
  { id: "u_neha", username: "neha", name: "Neha (editor)", roles: ["editor"] },
  { id: "u_amit", username: "amit", name: "Amit (admin)", roles: ["admin"] },
];
const ready = Promise.all(SEED.map(async (u) => users.set(u.id, { ...u, passwordHash: await hashPassword("chai1234") })));

// ---------- App ----------
const app = express();
app.use(express.json({ limit: "10kb" }));
app.use((req, res, next) => { res.set("Cache-Control", "no-store"); next(); });

app.post("/login", async (req, res) => {
  const { username, password } = req.body ?? {};
  if (typeof username !== "string" || typeof password !== "string") return res.status(400).json({ error: "username and password are required" });
  await ready;
  const user = [...users.values()].find((u) => u.username === username.toLowerCase());
  // Always run scrypt, even for unknown users, so the response time doesn't reveal which usernames exist (topic 07)
  const ok = await verifyPassword(password, user?.passwordHash ?? (await DUMMY_HASH_PROMISE));
  if (!user || !ok) return res.status(401).json({ error: "Wrong username or password" });

  const token = crypto.randomBytes(32).toString("base64url");
  tokens.set(sha256(token), { userId: user.id, expiresAt: Date.now() + TOKEN_TTL_MS });
  // Note: the roles are NOT put inside the token. They are looked up on every request (Step 3).
  res.json({ accessToken: token, roles: user.roles });
});

// ---------- Step 3: AUTHENTICATION: who are you? (401 if we don't know) ----------
function requireAuth(req, res, next) {
  const [scheme, token] = (req.headers.authorization ?? "").split(" ");
  const record = scheme === "Bearer" && token && tokens.get(sha256(token));
  if (!record || record.expiresAt < Date.now()) return res.status(401).json({ error: "Please log in" });
  // Load the user FRESH from the database, so a role change (or removal) works on the very next request
  req.user = users.get(record.userId);
  if (!req.user) return res.status(401).json({ error: "Please log in" });
  next();
}

// ---------- Step 4: AUTHORIZATION: are you allowed? (403 if not) ----------
// Checks a PERMISSION, not a role: adding a new role later never means editing every route.
function requirePermission(permission) {
  if (!PERMISSIONS.includes(permission)) throw new Error(`Unknown permission "${permission}"`); // catches typos at startup
  return (req, res, next) => {
    if (permissionsOf(req.user.roles).has(permission)) return next();
    // Step 5: deny by default, log the detail for audits, tell the client only that it's forbidden
    console.log(`🚫 denied: ${req.user.id} [${req.user.roles}] needs ${permission} for ${req.method} ${req.path}`);
    res.status(403).json({ error: "You don't have permission to do this" });
  };
}

// The frontend uses this to HIDE buttons. Hiding is for convenience only: the server still checks every request.
app.get("/me", requireAuth, (req, res) => {
  const { id, name, roles } = req.user;
  res.json({ id, name, roles, permissions: [...permissionsOf(roles)] });
});

app.get("/products", requireAuth, requirePermission("products:read"), (req, res) => {
  res.json({ products: [...products.values()] });
});

app.post("/products", requireAuth, requirePermission("products:write"), (req, res) => {
  const { name, price } = req.body ?? {};
  if (typeof name !== "string" || !name.trim() || name.length > 100) return res.status(400).json({ error: "name must be 1-100 characters" });
  if (!Number.isInteger(price) || price <= 0) return res.status(400).json({ error: "price must be a positive whole number of rupees" });
  const product = { id: `p_${crypto.randomUUID().slice(0, 8)}`, name: name.trim(), price };
  products.set(product.id, product);
  res.status(201).json(product);
});

app.get("/admin/orders", requireAuth, requirePermission("orders:read_all"), (req, res) => {
  res.json({ orders: [...orders.values()] });
});

app.post("/admin/orders/:id/refund", requireAuth, requirePermission("orders:refund"), (req, res) => {
  const order = orders.get(req.params.id);
  if (!order) return res.status(404).json({ error: "Order not found" });
  if (order.status === "refunded") return res.status(409).json({ error: "Order is already refunded" });
  order.status = "refunded";
  console.log(`💸 ${req.user.id} refunded ${order.id} (₹${order.total})`); // audit log: who did what
  res.json(order);
});

// Change someone's roles. Only users:manage (admins) may do this.
app.put("/admin/users/:id/roles", requireAuth, requirePermission("users:manage"), (req, res) => {
  const target = users.get(req.params.id);
  if (!target) return res.status(404).json({ error: "User not found" });
  const { roles } = req.body ?? {};
  // Validate against the allow-list: never store a role name you don't know ("superadmin", "ADMIN ")
  if (!Array.isArray(roles) || roles.length === 0 || !roles.every((r) => ROLES.includes(r))) {
    return res.status(400).json({ error: `roles must be a non-empty list from: ${ROLES.join(", ")}` });
  }
  // Don't let an admin remove their own admin role and lock everyone out
  if (target.id === req.user.id && !roles.includes("admin")) return res.status(400).json({ error: "You can't remove your own admin role" });
  const before = target.roles;
  target.roles = [...new Set(roles)];
  console.log(`🔑 ${req.user.id} changed roles of ${target.id}: [${before}] → [${target.roles}]`);
  res.json({ id: target.id, roles: target.roles, permissions: [...permissionsOf(target.roles)] });
});

app.use((req, res) => res.status(404).json({ error: "Not found" }));

// Errors (bad JSON, body too big, bugs) come here. Never send the stack trace to the client.
app.use((err, req, res, next) => {
  if (err.type === "entity.parse.failed") return res.status(400).json({ error: "Body must be valid JSON" });
  if (err.type === "entity.too.large") return res.status(413).json({ error: "Request body too large" });
  console.error(err);
  res.status(500).json({ error: "Something went wrong" });
});

ready.then(() => app.listen(PORT, () => console.log(`RBAC demo on http://localhost:${PORT} (users: rahul, priya, neha, amit; password chai1234)`)));
