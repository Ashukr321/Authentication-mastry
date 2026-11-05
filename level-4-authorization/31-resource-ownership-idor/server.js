const express = require("express");
const crypto = require("crypto");
const { promisify } = require("util");

const scrypt = promisify(crypto.scrypt);
const SCRYPT_OPTIONS = { N: 2 ** 17, r: 8, p: 1, maxmem: 256 * 1024 * 1024 };

const PORT = Number(process.env.PORT) || 3000;
const TOKEN_TTL_MS = 60 * 60 * 1000;

// Roles → permissions, as in topic 28. Support may READ any order (to help customers), never change one.
const ROLE_PERMISSIONS = { customer: [], support: ["orders:read_all"] };
const can = (user, permission) => ROLE_PERMISSIONS[user.role]?.includes(permission) ?? false;

// ---------- "Database" ----------
// shortcut: in-memory Maps, lost on restart. A real app uses tables with an orders.user_id column.
const users = new Map([
  ["u_rahul", { id: "u_rahul", username: "rahul", role: "customer" }],
  ["u_sneha", { id: "u_sneha", username: "sneha", role: "customer" }],
  ["u_priya", { id: "u_priya", username: "priya", role: "support" }],
]);
const tokens = new Map(); // sha256(token) -> { userId, expiresAt }
// Sequential ids on purpose: they make IDOR easy to see (just add 1). Random ids help, but are NOT the fix.
const orders = new Map([
  ["ord_1001", { id: "ord_1001", userId: "u_rahul", item: "Masala chai (500 g)", total: 240, status: "placed", address: "12 MG Road, Pune", phone: "98xxxxxx01" }],
  ["ord_1002", { id: "ord_1002", userId: "u_sneha", item: "Kanjeevaram saree", total: 18500, status: "placed", address: "7 Lodhi Colony, Delhi", phone: "98xxxxxx02" }],
  ["ord_1003", { id: "ord_1003", userId: "u_rahul", item: "Filter coffee (250 g)", total: 180, status: "delivered", address: "12 MG Road, Pune", phone: "98xxxxxx01" }],
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
// Password for every demo user: "chai1234" (demo only!)
const ready = Promise.all([...users.values()].map(async (u) => { u.passwordHash = await hashPassword("chai1234"); }));

const app = express();
app.use(express.json({ limit: "10kb" }));
app.use((req, res, next) => { res.set("Cache-Control", "no-store"); next(); });

app.post("/login", async (req, res) => {
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

// Topic 30's guard: who are you? (401). Ownership comes AFTER this, inside each route.
function requireAuth(req, res, next) {
  const [scheme, token] = (req.headers.authorization ?? "").split(" ");
  const record = scheme === "Bearer" && token && tokens.get(sha256(token));
  req.user = record && record.expiresAt > Date.now() && users.get(record.userId);
  if (!req.user) return res.status(401).json({ error: "Please log in" });
  next();
}

// ---------- Step 1: the owner comes from the TOKEN, never from the request ----------
// Like SQL: SELECT * FROM orders WHERE id = $1 AND user_id = $2. "Not yours" and "doesn't exist" look the same.
function findOrder(id, { ownerId, staff }) {
  const order = orders.get(id);
  if (!order) return null;
  if (order.userId === ownerId) return order;
  if (staff && can(staff, "orders:read_all")) return order; // Step 4: a permission can widen access, on purpose
  return null;
}

// ---------- Step 2: answer 404, not 403, and log the attempt ----------
function notFound(req, res) {
  const real = orders.get(req.params.id);
  // An attempt on someone else's order is a signal: many in a row = someone walking through ids
  if (real) console.log(`🕵️  ${req.user.id} tried ${req.method} ${req.params.id}, which belongs to ${real.userId}`);
  return res.status(404).json({ error: "Order not found" });
}

// Lists are scoped by the logged-in user. No ?userId= parameter to trust.
app.get("/orders", requireAuth, (req, res) => {
  const mine = [...orders.values()].filter((o) => o.userId === req.user.id);
  res.json({ orders: mine.map(({ id, item, total, status }) => ({ id, item, total, status })) });
});

app.get("/orders/:id", requireAuth, (req, res) => {
  const order = findOrder(req.params.id, { ownerId: req.user.id, staff: req.user });
  if (!order) return notFound(req, res);
  res.json(order);
});

// ---------- Step 3: writes check ownership too, and only accept the fields a user may change ----------
const EDITABLE_FIELDS = ["address", "phone"]; // NOT userId, total, status
app.patch("/orders/:id", requireAuth, (req, res) => {
  const order = findOrder(req.params.id, { ownerId: req.user.id }); // no staff override: support can read, not edit
  if (!order) return notFound(req, res);
  const body = req.body ?? {};
  const unknown = Object.keys(body).filter((k) => !EDITABLE_FIELDS.includes(k));
  if (unknown.length) return res.status(400).json({ error: `You can't change: ${unknown.join(", ")}` });
  for (const field of EDITABLE_FIELDS) {
    if (body[field] === undefined) continue;
    if (typeof body[field] !== "string" || !body[field].trim() || body[field].length > 200) return res.status(400).json({ error: `${field} must be 1-200 characters` });
  }
  if (order.status !== "placed") return res.status(409).json({ error: "Order has already shipped" }); // state is part of the rule too
  for (const field of EDITABLE_FIELDS) if (body[field] !== undefined) order[field] = body[field].trim();
  res.json(order);
});

// =====================================================================================
// 🐛 BUG LAB: classic IDOR mistakes. NEVER copy these.
// shortcut: dev-only routes in the same file so the demo is one process. They share the same orders.
// =====================================================================================

// Bug 1: logged in = allowed to read ANY order. The id in the URL is trusted.
app.get("/buggy/orders/:id", requireAuth, (req, res) => {
  const order = orders.get(req.params.id); // ❌ no "AND user_id = me"
  if (!order) return res.status(404).json({ error: "Order not found" });
  res.json(order);
});

// Bug 2: the list trusts a userId from the query string
app.get("/buggy/orders", requireAuth, (req, res) => {
  const userId = req.query.userId ?? req.user.id; // ❌ the client picks whose orders to see
  res.json({ orders: [...orders.values()].filter((o) => o.userId === userId) });
});

// Bug 3: ownership IS checked, but the whole body is copied onto the order (mass assignment)
app.patch("/buggy/orders/:id", requireAuth, (req, res) => {
  const order = orders.get(req.params.id);
  if (!order || order.userId !== req.user.id) return res.status(404).json({ error: "Order not found" });
  Object.assign(order, req.body); // ❌ total, status, even userId can be changed
  res.json(order);
});

app.use((req, res) => res.status(404).json({ error: "Not found" }));

// Errors (bad JSON, body too big, bugs) come here. Never send the stack trace to the client.
app.use((err, req, res, next) => {
  if (err.type === "entity.parse.failed") return res.status(400).json({ error: "Body must be valid JSON" });
  if (err.type === "entity.too.large") return res.status(413).json({ error: "Request body too large" });
  console.error(err);
  res.status(500).json({ error: "Something went wrong" });
});

ready.then(() => app.listen(PORT, () => console.log(`IDOR demo on http://localhost:${PORT} (users rahul, sneha, priya; password chai1234)`)));
