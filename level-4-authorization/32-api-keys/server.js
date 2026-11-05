const express = require("express");
const crypto = require("crypto");
const { promisify } = require("util");

const scrypt = promisify(crypto.scrypt);
const SCRYPT_OPTIONS = { N: 2 ** 17, r: 8, p: 1, maxmem: 256 * 1024 * 1024 };

const PORT = Number(process.env.PORT) || 3000;
const TOKEN_TTL_MS = 60 * 60 * 1000;
const KEY_PREFIX = "chai_key_";                                 // a fixed prefix lets secret scanners (GitHub, GitGuardian) spot leaked keys
const SCOPES = ["orders:read", "orders:write"];                 // what a key MAY be allowed to do
const MAX_KEYS_PER_USER = 10;
const RATE_LIMIT = Number(process.env.RATE_LIMIT) || 10;        // requests per key per window
const RATE_WINDOW_MS = 60 * 1000;

// ---------- "Database" ----------
// shortcut: in-memory Maps, lost on restart. A real app uses tables (api_keys with a UNIQUE index on key_hash).
const users = new Map([
  ["u_rahul", { id: "u_rahul", username: "rahul", shop: "Rahul's Chai Stall" }],
  ["u_sneha", { id: "u_sneha", username: "sneha", shop: "Sneha's Sarees" }],
]);
const sessions = new Map(); // sha256(token) -> { userId, expiresAt }   (humans, for the dashboard)
const apiKeys = new Map();  // sha256(key) -> { id, userId, name, hint, scopes, createdAt, expiresAt, lastUsedAt, revokedAt }
const orders = [
  { id: "ord_1", userId: "u_rahul", item: "Masala chai x 40", total: 800 },
  { id: "ord_2", userId: "u_sneha", item: "Kanjeevaram saree", total: 18500 },
];
const rateCounters = new Map(); // keyId -> { windowStart, count }

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
// SHA-256 (fast) is fine for API keys: they're 256 random bits, so they can't be guessed like passwords.
const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");
// Password for every demo user: "chai1234" (demo only!)
const ready = Promise.all([...users.values()].map(async (u) => { u.passwordHash = await hashPassword("chai1234"); }));

const app = express();
app.use(express.json({ limit: "10kb" }));
app.use((req, res, next) => { res.set("Cache-Control", "no-store"); next(); });

// ---------- Humans log in to MANAGE keys (dashboard) ----------
app.post("/login", async (req, res) => {
  const { username, password } = req.body ?? {};
  if (typeof username !== "string" || typeof password !== "string") return res.status(400).json({ error: "username and password are required" });
  await ready;
  const user = [...users.values()].find((u) => u.username === username.toLowerCase());
  const ok = await verifyPassword(password, user?.passwordHash ?? (await DUMMY_HASH_PROMISE)); // same timing for unknown users
  if (!user || !ok) return res.status(401).json({ error: "Wrong username or password" });
  const token = crypto.randomBytes(32).toString("base64url");
  sessions.set(sha256(token), { userId: user.id, expiresAt: Date.now() + TOKEN_TTL_MS });
  res.json({ accessToken: token });
});

function requireUser(req, res, next) {
  const [scheme, token] = (req.headers.authorization ?? "").split(" ");
  const record = scheme === "Bearer" && token && sessions.get(sha256(token));
  req.user = record && record.expiresAt > Date.now() && users.get(record.userId);
  if (!req.user) return res.status(401).json({ error: "Please log in" });
  next();
}

// What the dashboard may show about a key: never the key itself, or its hash
const publicKey = ({ id, name, hint, scopes, createdAt, expiresAt, lastUsedAt, revokedAt }) =>
  ({ id, name, hint, scopes, createdAt, expiresAt, lastUsedAt, revoked: Boolean(revokedAt) });
const keysOf = (userId) => [...apiKeys.values()].filter((k) => k.userId === userId);

// ---------- Step 1: CREATE a key: random, shown ONCE, stored as a hash ----------
app.post("/keys", requireUser, (req, res) => {
  const { name, scopes, expiresInDays } = req.body ?? {};
  if (typeof name !== "string" || !name.trim() || name.length > 50) return res.status(400).json({ error: "name must be 1-50 characters" });
  if (!Array.isArray(scopes) || scopes.length === 0 || !scopes.every((s) => SCOPES.includes(s))) {
    return res.status(400).json({ error: `scopes must be a non-empty list from: ${SCOPES.join(", ")}` });
  }
  if (expiresInDays !== undefined && (!Number.isInteger(expiresInDays) || expiresInDays < 1 || expiresInDays > 365)) {
    return res.status(400).json({ error: "expiresInDays must be a whole number from 1 to 365" });
  }
  if (keysOf(req.user.id).filter((k) => !k.revokedAt).length >= MAX_KEYS_PER_USER) return res.status(409).json({ error: "Too many active keys. Revoke one first." });

  const key = KEY_PREFIX + crypto.randomBytes(32).toString("base64url"); // 256 bits of randomness
  const record = {
    id: `key_${crypto.randomUUID().slice(0, 8)}`,
    userId: req.user.id,
    name: name.trim(),
    hint: `${key.slice(0, KEY_PREFIX.length + 4)}…${key.slice(-4)}`, // enough to recognise it in the dashboard, useless to an attacker
    scopes: [...new Set(scopes)],
    createdAt: new Date().toISOString(),
    expiresAt: expiresInDays ? new Date(Date.now() + expiresInDays * 86400000).toISOString() : null,
    lastUsedAt: null,
    revokedAt: null,
  };
  apiKeys.set(sha256(key), record); // ONLY the hash is stored. If the database leaks, the keys don't.
  console.log(`🔑 ${req.user.id} created ${record.id} (${record.name}) scopes=[${record.scopes}]`); // log the id, NEVER the key
  res.status(201).json({ ...publicKey(record), key, warning: "Copy this key now. It will not be shown again." });
});

app.get("/keys", requireUser, (req, res) => res.json({ keys: keysOf(req.user.id).map(publicKey) }));

// ---------- Step 5: REVOKE: works instantly, because every request looks the key up ----------
app.delete("/keys/:id", requireUser, (req, res) => {
  const record = keysOf(req.user.id).find((k) => k.id === req.params.id); // only YOUR keys (topic 31)
  if (!record) return res.status(404).json({ error: "Key not found" });
  record.revokedAt ??= new Date().toISOString();
  console.log(`🗑️  ${req.user.id} revoked ${record.id}`);
  res.json(publicKey(record));
});

// ---------- Step 2: AUTHENTICATE a program by its key ----------
function requireApiKey(req, res, next) {
  // Keys in the URL end up in server logs, proxy logs and browser history: refuse them loudly
  if (req.query.api_key !== undefined || req.query.key !== undefined) {
    return res.status(400).json({ error: "Send the API key in the X-API-Key header, never in the URL. Treat this key as leaked and rotate it." });
  }
  const key = req.get("X-API-Key");
  const record = typeof key === "string" && key.startsWith(KEY_PREFIX) && apiKeys.get(sha256(key));
  // Same answer for unknown, revoked and expired keys. The reason goes to the log.
  const problem = !record ? "unknown key" : record.revokedAt ? `${record.id} is revoked` : record.expiresAt && Date.parse(record.expiresAt) < Date.now() ? `${record.id} is expired` : null;
  if (problem) {
    console.log(`❌ API key rejected: ${problem}`);
    return res.status(401).json({ error: "Invalid API key" });
  }

  // ---------- Step 4: RATE LIMIT per key ----------
  // shortcut: fixed window in memory, per process. Real APIs use Redis (shared across servers) and often a sliding window.
  const now = Date.now();
  let counter = rateCounters.get(record.id);
  if (!counter || now - counter.windowStart >= RATE_WINDOW_MS) rateCounters.set(record.id, (counter = { windowStart: now, count: 0 }));
  counter.count++;
  res.set("X-RateLimit-Limit", String(RATE_LIMIT));
  res.set("X-RateLimit-Remaining", String(Math.max(0, RATE_LIMIT - counter.count)));
  if (counter.count > RATE_LIMIT) {
    res.set("Retry-After", String(Math.ceil((counter.windowStart + RATE_WINDOW_MS - now) / 1000)));
    return res.status(429).json({ error: "Too many requests for this API key" });
  }

  record.lastUsedAt = new Date().toISOString(); // shows unused keys you can delete, and when a leaked key was used
  req.apiKey = record;
  next();
}

// ---------- Step 3: SCOPES: what this key may do (a key is not its owner's password) ----------
function requireScope(scope) {
  return (req, res, next) => {
    if (req.apiKey.scopes.includes(scope)) return next();
    console.log(`🚫 ${req.apiKey.id} needs ${scope}`);
    return res.status(403).json({ error: `This API key is missing the ${scope} scope` });
  };
}

// The key acts for its owner, and only sees the owner's data (topic 31)
app.get("/api/orders", requireApiKey, requireScope("orders:read"), (req, res) => {
  res.json({ orders: orders.filter((o) => o.userId === req.apiKey.userId) });
});

app.post("/api/orders", requireApiKey, requireScope("orders:write"), (req, res) => {
  const { item, total } = req.body ?? {};
  if (typeof item !== "string" || !item.trim() || item.length > 100) return res.status(400).json({ error: "item must be 1-100 characters" });
  if (!Number.isInteger(total) || total <= 0) return res.status(400).json({ error: "total must be a positive whole number of rupees" });
  const order = { id: `ord_${crypto.randomUUID().slice(0, 8)}`, userId: req.apiKey.userId, item: item.trim(), total };
  orders.push(order);
  console.log(`🧾 ${req.apiKey.id} created ${order.id} for ${req.apiKey.userId}`); // audit: WHICH key did it
  res.status(201).json(order);
});

app.use((req, res) => res.status(404).json({ error: "Not found" }));

// Errors (bad JSON, body too big, bugs) come here. Never send the stack trace to the client.
app.use((err, req, res, next) => {
  if (err.type === "entity.parse.failed") return res.status(400).json({ error: "Body must be valid JSON" });
  if (err.type === "entity.too.large") return res.status(413).json({ error: "Request body too large" });
  console.error(err);
  res.status(500).json({ error: "Something went wrong" });
});

ready.then(() => app.listen(PORT, () => console.log(`API keys demo on http://localhost:${PORT} (users rahul, sneha; password chai1234; ${RATE_LIMIT} requests/min per key)`)));
