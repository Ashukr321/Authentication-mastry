const express = require("express");
const crypto = require("crypto");

const PORT = Number(process.env.PORT) || 3000;
// Every workspace (tenant) lives on its own subdomain: acme.localhost, zenith.localhost, ...
// Browsers and curl send *.localhost to 127.0.0.1, so this works with no DNS setup.
const APP_DOMAIN = "localhost";
const BASE_URL = `http://${APP_DOMAIN}:${PORT}`;

// ---------- "Database" ----------
// shortcut: in-memory Maps, lost on restart. A real app uses tables, and EVERY tenant-owned table has a tenant_id column.
// STEP 1: tenants have an immutable id ("t_1") and a slug for the URL. Rename the slug, the id never changes.
const tenants = new Map([
  ["t_1", { id: "t_1", slug: "acme", name: "Acme Traders", status: "active", policy: { passwordLogin: true, sessionMinutes: 480 } }],
  ["t_2", { id: "t_2", slug: "zenith", name: "Zenith Textiles", status: "active", policy: { passwordLogin: true, sessionMinutes: 30 } }],
  ["t_3", { id: "t_3", slug: "nimbus", name: "Nimbus Bank", status: "active", policy: { passwordLogin: false, sessionMinutes: 60 } }],
  ["t_4", { id: "t_4", slug: "oldco", name: "OldCo", status: "suspended", policy: { passwordLogin: true, sessionMinutes: 480 } }],
]);
const users = new Map();       // userId -> { id, email, salt, passwordHash }   (ONE global identity per person)
const memberships = new Map(); // `${tenantId}:${userId}` -> role ("admin" | "member")   (a role PER tenant)
const tokens = new Map();      // sha256(token) -> { userId, tenantId, expiresAt }
const invoices = new Map([     // invoiceId -> { id, tenantId, ... }   every row says which tenant owns it
  ["inv_101", { id: "inv_101", tenantId: "t_1", customer: "Sharma Stores", amount: "₹45,000" }],
  ["inv_102", { id: "inv_102", tenantId: "t_1", customer: "Gupta & Sons", amount: "₹1,20,000" }],
  ["inv_201", { id: "inv_201", tenantId: "t_2", customer: "Mehta Fabrics", amount: "₹8,500" }],
]);

// ---------- Helpers ----------
const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");
const randomToken = () => crypto.randomBytes(32).toString("base64url");
const str = (v) => (typeof v === "string" ? v : undefined);
const tenantBySlug = (slug) => [...tenants.values()].find((t) => t.slug === slug);
const findUser = (email) => [...users.values()].find((u) => u.email === email);
const roleIn = (tenantId, userId) => memberships.get(`${tenantId}:${userId}`);

const DUMMY_SALT = crypto.randomBytes(16);
// shortcut: test accounts with known passwords. A real app has signup + invitations (topics 06, 62).
for (const [email, password, roles] of [
  ["priya@acme.in", "priya-pass-2026", { t_1: "admin", t_2: "member", t_3: "member" }], // a consultant in 3 workspaces
  ["rahul@acme.in", "rahul-pass-2026", { t_1: "member" }],
  ["vikram@zenith.in", "vikram-pass-2026", { t_2: "admin" }],
  ["meera@oldco.in", "meera-pass-2026", { t_4: "admin" }],
]) {
  const salt = crypto.randomBytes(16);
  const id = crypto.randomUUID();
  users.set(id, { id, email, salt, passwordHash: crypto.scryptSync(password, salt, 64) });
  for (const [tenantId, role] of Object.entries(roles)) memberships.set(`${tenantId}:${id}`, role);
}

function checkPassword(email, password) {
  const user = email ? findUser(email) : undefined;
  // Hash even for unknown emails so the response time doesn't reveal who has an account (topic 51)
  const hash = crypto.scryptSync(password ?? "", user?.salt ?? DUMMY_SALT, 64);
  return user && crypto.timingSafeEqual(hash, user.passwordHash) ? user : null;
}

// A token is issued for ONE tenant. The tenant's own policy decides how long it lives.
function issueToken(user, tenant) {
  const token = randomToken();
  const expiresAt = Date.now() + tenant.policy.sessionMinutes * 60 * 1000;
  tokens.set(sha256(token), { userId: user.id, tenantId: tenant.id, expiresAt }); // store only the hash
  return { token, tenant: tenant.slug, role: roleIn(tenant.id, user.id), expiresAt: new Date(expiresAt).toISOString() };
}

// Is this tenant open for business, and does its policy allow a password login? (STEP 5)
function tenantBlocks(tenant) {
  if (tenant.status !== "active") return { status: 403, error: `${tenant.name} is suspended. Contact your administrator` };
  if (!tenant.policy.passwordLogin) return { status: 403, error: `${tenant.name} requires sign-in through its company SSO (topic 60)` };
  return null;
}

// Reads a valid token (any tenant). Callers decide what to do with the tenant it belongs to.
function readToken(req) {
  const [scheme, token] = (req.get("authorization") ?? "").split(" ");
  if (scheme !== "Bearer" || !token) return null;
  const s = tokens.get(sha256(token));
  if (!s || s.expiresAt < Date.now()) return null;
  return { ...s, key: sha256(token) };
}

// ---------- App ----------
const app = express();
app.use(express.json({ limit: "10kb" }));
app.use((req, res, next) => {
  res.set("Cache-Control", "no-store");
  next();
});

// STEP 2: work out the tenant from the SUBDOMAIN, before anything else.
// The subdomain is only a lookup key: it must match a tenant we know, or the request stops here.
app.use((req, res, next) => {
  const host = req.hostname; // Express 5: from the Host header (trust proxy is off, so X-Forwarded-Host is ignored)
  if (host === APP_DOMAIN) return next(); // the bare domain has no tenant: only the 404 handler below
  const slug = host.endsWith(`.${APP_DOMAIN}`) ? host.slice(0, -APP_DOMAIN.length - 1) : null;
  const tenant = slug && tenantBySlug(slug);
  if (!tenant) return res.status(404).json({ error: "Unknown workspace" });
  req.tenant = tenant;
  next();
});

// STEP 3: ✅ SAFE auth middleware. The token must belong to THIS tenant, and the user must STILL be a member of it.
function requireAuth(req, res, next) {
  if (!req.tenant) return res.status(404).json({ error: "Not found" });
  const s = readToken(req);
  if (!s) return res.status(401).json({ error: "Not signed in" });
  // The key line of multi-tenant auth: a token from zenith is worthless on acme, even though it's a valid token.
  if (s.tenantId !== req.tenant.id) return res.status(401).json({ error: "This token is for a different workspace" });
  if (req.tenant.status !== "active") return res.status(403).json({ error: `${req.tenant.name} is suspended` });
  // Look the role up on EVERY request (not from the token), so "removed from the workspace" works instantly
  const role = roleIn(s.tenantId, s.userId);
  if (!role) return res.status(403).json({ error: "You are no longer a member of this workspace" });
  req.user = users.get(s.userId);
  req.role = role;
  req.tokenKey = s.key;
  next();
}

const requireRole = (role) => (req, res, next) =>
  req.role === role ? next() : res.status(403).json({ error: `Only ${role}s of ${req.tenant.name} can do this` });

// Login happens ON a tenant: acme.localhost/login logs you into Acme, nowhere else.
app.post("/login", (req, res) => {
  if (!req.tenant) return res.status(404).json({ error: "Open your workspace URL, like acme.localhost" });
  const user = checkPassword(str(req.body?.email)?.trim().toLowerCase(), str(req.body?.password));
  // STEP 4: a correct password is NOT enough. The person must be a member of THIS tenant.
  // Same message as a wrong password, so outsiders can't probe who works where.
  if (!user || !roleIn(req.tenant.id, user.id)) return res.status(401).json({ error: "Wrong email or password" });
  const blocked = tenantBlocks(req.tenant); // checked after the password, so it doesn't leak who is a member
  if (blocked) return res.status(blocked.status).json({ error: blocked.error });
  res.json(issueToken(user, req.tenant));
});

app.get("/me", requireAuth, (req, res) => {
  res.json({ email: req.user.email, tenant: req.tenant.slug, tenantName: req.tenant.name, role: req.role });
});

// The "workspace picker": every tenant this person belongs to. It only lists the user's OWN memberships.
app.get("/workspaces", requireAuth, (req, res) => {
  const list = [...tenants.values()]
    .filter((t) => roleIn(t.id, req.user.id))
    .map((t) => ({ tenant: t.slug, name: t.name, role: roleIn(t.id, req.user.id), url: `http://${t.slug}.${APP_DOMAIN}:${PORT}` }));
  res.json({ workspaces: list });
});

// STEP 5: switch workspace = get a NEW token for the other tenant. Membership AND the target's policy are checked again.
app.post("/switch", requireAuth, (req, res) => {
  const target = tenantBySlug(str(req.body?.tenant));
  // Not a member and "doesn't exist" look the same: don't confirm which companies use the app
  if (!target || !roleIn(target.id, req.user.id)) return res.status(404).json({ error: "Workspace not found" });
  const blocked = tenantBlocks(target); // a password-login session can't be "switched" into an SSO-only tenant
  if (blocked) return res.status(blocked.status).json({ error: blocked.error });
  res.json(issueToken(req.user, target));
});

// STEP 6: ✅ every query is filtered by the tenant from requireAuth. Never by a tenant id the client sends.
app.get("/invoices", requireAuth, (req, res) => {
  res.json({ tenant: req.tenant.slug, invoices: [...invoices.values()].filter((i) => i.tenantId === req.tenant.id) });
});

app.get("/invoices/:id", requireAuth, (req, res) => {
  const inv = invoices.get(req.params.id);
  // Another tenant's invoice answers 404, exactly like a missing one: don't even confirm that it exists
  if (!inv || inv.tenantId !== req.tenant.id) return res.status(404).json({ error: "Invoice not found" });
  res.json(inv);
});

// STEP 7: roles are PER tenant. Priya is admin in Acme and a plain member in Zenith.
app.get("/members", requireAuth, requireRole("admin"), (req, res) => {
  const members = [...users.values()]
    .filter((u) => roleIn(req.tenant.id, u.id))
    .map((u) => ({ email: u.email, role: roleIn(req.tenant.id, u.id) }));
  res.json({ tenant: req.tenant.slug, members });
});

// An admin removes someone from THEIR tenant. Their tokens for this tenant stop working at once (requireAuth looks the role up).
app.delete("/members/:email", requireAuth, requireRole("admin"), (req, res) => {
  const user = findUser(req.params.email.toLowerCase());
  if (!user || !memberships.delete(`${req.tenant.id}:${user.id}`)) return res.status(404).json({ error: "Member not found" });
  for (const [k, s] of tokens) if (s.userId === user.id && s.tenantId === req.tenant.id) tokens.delete(k); // clean up too
  res.json({ message: `${user.email} removed from ${req.tenant.name}` });
});

app.post("/logout", requireAuth, (req, res) => {
  tokens.delete(req.tokenKey);
  res.json({ message: "Logged out" });
});

// ---------- ❌ VULNERABLE routes (the two classic multi-tenant bugs) ----------
// Any valid token from ANY tenant is accepted here: only "is the token real?" is checked.
function anyValidToken(req, res, next) {
  const s = readToken(req);
  if (!s) return res.status(401).json({ error: "Not signed in" });
  req.user = users.get(s.userId);
  next();
}

// ❌ BUG 1: the tenant comes from a header the CLIENT sets, not from the token. Change the header, read another company.
app.get("/vulnerable/invoices", anyValidToken, (req, res) => {
  const tenant = tenantBySlug(str(req.get("x-tenant")));
  if (!tenant) return res.status(400).json({ error: "Send the X-Tenant header" });
  res.json({ tenant: tenant.slug, invoices: [...invoices.values()].filter((i) => i.tenantId === tenant.id) });
});

// ❌ BUG 2: cross-tenant IDOR. Looks the invoice up by id alone, with no "AND tenant_id = ?".
app.get("/vulnerable/invoices/:id", anyValidToken, (req, res) => {
  const inv = invoices.get(req.params.id);
  if (!inv) return res.status(404).json({ error: "Invoice not found" });
  res.json(inv);
});

app.use((req, res) => res.status(404).json({ error: "Not found" }));

// Errors (bad JSON, body too big, bugs) come here. Never send the stack trace to the client.
app.use((err, req, res, next) => {
  if (err.type === "entity.parse.failed") return res.status(400).json({ error: "Body must be valid JSON" });
  if (err.type === "entity.too.large") return res.status(413).json({ error: "Request body too large" });
  console.error(err);
  res.status(500).json({ error: "Something went wrong" });
});

// Express 5 passes a listen error (like "port already in use") to this callback instead of crashing
app.listen(PORT, (err) => {
  if (err) throw err;
  console.log(`🏢 Multi-tenant app on ${BASE_URL}`);
  for (const t of tenants.values()) console.log(`   ${t.name}: http://${t.slug}.${APP_DOMAIN}:${PORT}`);
});

// Sweep expired tokens so the Map doesn't grow forever
setInterval(() => {
  for (const [k, s] of tokens) if (s.expiresAt < Date.now()) tokens.delete(k);
}, 60_000).unref();
