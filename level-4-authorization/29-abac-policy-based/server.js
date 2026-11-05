const express = require("express");
const crypto = require("crypto");
const assert = require("assert");
const { promisify } = require("util");

const scrypt = promisify(crypto.scrypt);
const SCRYPT_OPTIONS = { N: 2 ** 17, r: 8, p: 1, maxmem: 256 * 1024 * 1024 };

const PORT = Number(process.env.PORT) || 3000;
const TOKEN_TTL_MS = 60 * 60 * 1000;
const SHOW_DEBUG = process.env.NODE_ENV !== "production";

// ---------- Step 1: ATTRIBUTES ----------
// Subject attributes live on the user, resource attributes on the order, environment attributes come from the request/clock.
// shortcut: in-memory Maps, lost on restart. A real app reads these from tables (and maybe HR / CRM systems).
const users = new Map([
  ["u_rahul", { id: "u_rahul", username: "rahul", role: "customer", region: "Mumbai" }],
  ["u_sneha", { id: "u_sneha", username: "sneha", role: "customer", region: "Delhi" }],
  ["u_priya", { id: "u_priya", username: "priya", role: "support", region: "Mumbai", refundLimit: 5000 }],
  ["u_arjun", { id: "u_arjun", username: "arjun", role: "support", region: "Delhi", refundLimit: 5000 }],
  ["u_amit", { id: "u_amit", username: "amit", role: "manager", region: "Mumbai" }],
]);
const orders = new Map([
  ["ord_1", { id: "ord_1", customerId: "u_rahul", region: "Mumbai", item: "Masala chai (500 g)", total: 240, status: "paid", legalHold: false }],
  ["ord_2", { id: "ord_2", customerId: "u_sneha", region: "Delhi", item: "Filter coffee (250 g)", total: 180, status: "paid", legalHold: false }],
  ["ord_3", { id: "ord_3", customerId: "u_rahul", region: "Mumbai", item: "Espresso machine", total: 12000, status: "paid", legalHold: false }],
  ["ord_4", { id: "ord_4", customerId: "u_rahul", region: "Mumbai", item: "Kesar (10 g)", total: 900, status: "paid", legalHold: true }],
]);
const tokens = new Map(); // sha256(token) -> { userId, expiresAt }

// Environment attribute: the hour in India. Refunds are only allowed during office hours.
// shortcut: DEMO_HOUR lets you fake the clock for the demo. Never let the CLIENT send the time.
function currentHourIST() {
  if (process.env.DEMO_HOUR !== undefined) return Number(process.env.DEMO_HOUR);
  return Number(new Intl.DateTimeFormat("en-IN", { hour: "numeric", hourCycle: "h23", timeZone: "Asia/Kolkata" }).format(new Date()));
}
const isOfficeHours = (env) => env.hour >= 9 && env.hour < 18;

// ---------- Step 2: POLICIES = rules over attributes ----------
// Each policy: which action, allow or deny, and a condition on { subject, resource, env }.
// shortcut: policies as JS functions in this file. Big systems keep them in a policy language (OPA/Rego, Cedar) so they're
// reviewed and deployed separately from app code.
const POLICIES = [
  { id: "customer-reads-own-order", effect: "allow", action: "order:read",
    when: ({ subject, resource }) => subject.role === "customer" && resource.customerId === subject.id },
  { id: "support-reads-own-region", effect: "allow", action: "order:read",
    when: ({ subject, resource }) => subject.role === "support" && resource.region === subject.region },
  { id: "manager-reads-all", effect: "allow", action: "order:read",
    when: ({ subject }) => subject.role === "manager" },

  { id: "support-refunds-small-own-region-office-hours", effect: "allow", action: "order:refund",
    when: ({ subject, resource, env }) =>
      subject.role === "support" && resource.region === subject.region && resource.total <= subject.refundLimit && isOfficeHours(env) },
  { id: "manager-refunds-office-hours", effect: "allow", action: "order:refund",
    when: ({ subject, env }) => subject.role === "manager" && isOfficeHours(env) },

  // A DENY wins over every allow: not even a manager can refund an order under legal hold.
  { id: "no-refund-on-legal-hold", effect: "deny", action: "order:refund",
    when: ({ resource }) => resource.legalHold === true },
];

// ---------- Step 3: THE DECISION POINT (PDP) ----------
// Default DENY. Any matching deny → deny. Otherwise any matching allow → allow. Nothing matched → deny.
function decide(action, subject, resource, env) {
  const input = { subject, resource, env };
  const matching = POLICIES.filter((p) => p.action === action && p.when(input));
  const deny = matching.find((p) => p.effect === "deny");
  if (deny) return { allowed: false, reason: `denied by ${deny.id}` };
  const allow = matching.find((p) => p.effect === "allow");
  if (allow) return { allowed: true, reason: `allowed by ${allow.id}` };
  return { allowed: false, reason: "no policy allows this (default deny)" };
}

// Self-check of the security core: runs on every start.
{
  const priya = users.get("u_priya"), amit = users.get("u_amit"), rahul = users.get("u_rahul");
  const day = { hour: 11 }, night = { hour: 22 };
  assert.ok(decide("order:refund", priya, orders.get("ord_1"), day).allowed);           // small, own region, daytime
  assert.ok(!decide("order:refund", priya, orders.get("ord_1"), night).allowed);        // after hours
  assert.ok(!decide("order:refund", priya, orders.get("ord_2"), day).allowed);          // Delhi order
  assert.ok(!decide("order:refund", priya, orders.get("ord_3"), day).allowed);          // over her limit
  assert.ok(decide("order:refund", amit, orders.get("ord_3"), day).allowed);            // manager, any amount
  assert.ok(!decide("order:refund", amit, orders.get("ord_4"), day).allowed);           // deny overrides allow
  assert.ok(!decide("order:read", rahul, orders.get("ord_2"), day).allowed);            // someone else's order
  assert.ok(!decide("order:delete", amit, orders.get("ord_1"), day).allowed);           // unknown action → deny
}

// ---------- Auth (same idea as topic 28) ----------
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

function requireAuth(req, res, next) {
  const [scheme, token] = (req.headers.authorization ?? "").split(" ");
  const record = scheme === "Bearer" && token && tokens.get(sha256(token));
  req.user = record && record.expiresAt > Date.now() && users.get(record.userId); // attributes loaded FRESH every request
  if (!req.user) return res.status(401).json({ error: "Please log in" });
  next();
}

// The attributes we show to the outside world (never the password hash)
const publicUser = ({ passwordHash, ...rest }) => rest;
const envOf = (req) => ({ hour: currentHourIST() });

// ---------- Step 4: THE ENFORCEMENT POINT (PEP) ----------
// ABAC needs the RESOURCE's attributes, so: load the resource first, then ask decide(), then act.
function authorize(req, res, action, resource) {
  const decision = decide(action, req.user, resource, envOf(req));
  // Step 5: log every decision (who, what, which resource, which policy) so "why was this allowed?" has an answer
  console.log(`${decision.allowed ? "✅" : "🚫"} ${req.user.id} ${action} ${resource.id}: ${decision.reason}`);
  if (!decision.allowed) res.status(403).json({ error: "You don't have permission to do this", ...(SHOW_DEBUG && { debugReason: decision.reason }) });
  return decision.allowed;
}

app.get("/me", requireAuth, (req, res) => res.json({ ...publicUser(req.user), hourIST: currentHourIST() }));

// Lists use the SAME policy as a filter: each user sees only the orders they may read
app.get("/orders", requireAuth, (req, res) => {
  const env = envOf(req);
  res.json({ orders: [...orders.values()].filter((o) => decide("order:read", req.user, o, env).allowed) });
});

app.get("/orders/:id", requireAuth, (req, res) => {
  const order = orders.get(req.params.id);
  if (!order) return res.status(404).json({ error: "Order not found" });
  if (!authorize(req, res, "order:read", order)) return;
  res.json(order);
});

app.post("/orders/:id/refund", requireAuth, (req, res) => {
  const order = orders.get(req.params.id);
  if (!order) return res.status(404).json({ error: "Order not found" });
  if (!authorize(req, res, "order:refund", order)) return;
  if (order.status === "refunded") return res.status(409).json({ error: "Order is already refunded" });
  order.status = "refunded";
  console.log(`💸 ${req.user.id} refunded ${order.id} (₹${order.total})`);
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

ready.then(() => app.listen(PORT, () =>
  console.log(`ABAC demo on http://localhost:${PORT} (hour in India: ${currentHourIST()}; users rahul, sneha, priya, arjun, amit; password chai1234)`)));
