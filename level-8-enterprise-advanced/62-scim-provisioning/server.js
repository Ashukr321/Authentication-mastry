const express = require("express");
const crypto = require("crypto");

const PORT = Number(process.env.PORT) || 3000;
const BASE_URL = `http://localhost:${PORT}`;
const SCIM_BASE = `${BASE_URL}/scim/v2`;
const ADMIN_GROUP = "ChaiDesk Admins"; // members of this IdP group get the "admin" role in our app

// The fixed names SCIM uses to say "what kind of JSON is this"
const USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User";
const GROUP_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:Group";
const LIST_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:ListResponse";
const PATCH_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:PatchOp";
const ERROR_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:Error";

// ---------- "Database" ----------
// shortcut: in-memory Maps, lost on restart. A real app uses tables with a tenant_id column on every row.
const tenants = new Map();  // sha256(scimToken) -> { id, name }
const users = new Map();    // id -> { id, tenant, userName, externalId, name, displayName, title, emails, active, created, lastModified, version }
const groups = new Map();   // id -> { id, tenant, displayName, externalId, members: Set(userId), created, lastModified, version }
const sessions = new Map(); // sha256(sid) -> { userId }

// ---------- Helpers ----------
const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");
const str = (v) => (typeof v === "string" ? v : undefined);
const parseCookies = (req) => Object.fromEntries((req.headers.cookie ?? "").split(";").filter((c) => c.includes("="))
  .map((c) => [c.slice(0, c.indexOf("=")).trim(), c.slice(c.indexOf("=") + 1).trim()]));
const now = () => new Date().toISOString();

// STEP 1: each customer (tenant) gets its OWN long random token, pasted once into their IdP's SCIM settings.
// shortcut: fixed demo tokens so the curl examples work. A real app generates randomBytes(32) per tenant in an
// admin page, shows it ONCE, stores only the hash, and lets the customer rotate it.
for (const [token, id, name] of [
  ["scim-techcorp-demo-token-7f3a", "techcorp", "TechCorp (uses Okta)"],
  ["scim-chaiwala-demo-token-91bc", "chaiwala", "Chaiwala Inc (uses Microsoft Entra ID)"],
]) tenants.set(sha256(token), { id, name });

// SCIM errors have their own JSON shape. Note: "status" is a STRING in SCIM.
class ScimError extends Error {
  constructor(status, detail, scimType) { super(detail); this.status = status; this.scimType = scimType; }
}
const scimError = (res, status, detail, scimType) =>
  res.status(status).json({ schemas: [ERROR_SCHEMA], status: String(status), ...(scimType && { scimType }), detail });

// ---------- Validation (the IdP is a client like any other: never trust its JSON) ----------
function text(v, field, max, required = false) {
  if (v === undefined || v === null || v === "") {
    if (required) throw new ScimError(400, `${field} is required`, "invalidValue");
    return undefined;
  }
  if (typeof v !== "string" || v.trim().length > max) throw new ScimError(400, `${field} must be a string up to ${max} characters`, "invalidValue");
  return v.trim();
}

// Microsoft Entra ID sends active as the STRING "False" in some PATCH requests. Accept both, reject anything else.
function bool(v, field) {
  if (typeof v === "boolean") return v;
  if (typeof v === "string" && /^(true|false)$/i.test(v)) return v.toLowerCase() === "true";
  throw new ScimError(400, `${field} must be true or false`, "invalidValue");
}

function emailsOf(v) {
  if (v === undefined || v === null) return [];
  if (!Array.isArray(v) || v.length > 10) throw new ScimError(400, "emails must be an array of up to 10 items", "invalidValue");
  return v.map((e) => {
    const value = text(e?.value, "emails.value", 254, true);
    if (!value.includes("@")) throw new ScimError(400, "emails.value must be an email address", "invalidValue");
    return { value, type: text(e.type, "emails.type", 20), primary: e.primary === undefined ? undefined : bool(e.primary, "emails.primary") };
  });
}

// One function turns any incoming User JSON (POST, PUT, or the result of a PATCH) into clean attributes.
// Anything not listed here (like "password" or unknown extensions) is simply not stored.
function userAttrs(b) {
  if (!b || typeof b !== "object" || Array.isArray(b)) throw new ScimError(400, "Body must be a SCIM User object", "invalidSyntax");
  const name = b.name ?? {};
  if (typeof name !== "object" || Array.isArray(name)) throw new ScimError(400, "name must be an object", "invalidValue");
  return {
    userName: text(b.userName, "userName", 256, true),
    externalId: text(b.externalId, "externalId", 256),
    name: { givenName: text(name.givenName, "name.givenName", 100), familyName: text(name.familyName, "name.familyName", 100) },
    displayName: text(b.displayName, "displayName", 200),
    title: text(b.title, "title", 100),
    emails: emailsOf(b.emails),
    active: b.active === undefined ? true : bool(b.active, "active"),
  };
}

// ---------- Lookups (STEP 2: every query is scoped to the caller's tenant) ----------
const tenantUsers = (tenant) => [...users.values()].filter((u) => u.tenant === tenant);
const tenantGroups = (tenant) => [...groups.values()].filter((g) => g.tenant === tenant);
const groupsOf = (u) => tenantGroups(u.tenant).filter((g) => g.members.has(u.id));

function findUser(req, id) {
  const u = users.get(id);
  // Another tenant's user gets the same 404 as a missing one: don't even confirm it exists
  if (!u || u.tenant !== req.tenant.id) throw new ScimError(404, `User ${id} not found`);
  return u;
}
function findGroup(req, id) {
  const g = groups.get(id);
  if (!g || g.tenant !== req.tenant.id) throw new ScimError(404, `Group ${id} not found`);
  return g;
}

// userName is unique per tenant and NOT case-sensitive (Priya@TechCorp.com and priya@techcorp.com are one person)
function assertUniqueUserName(tenant, userName, exceptId) {
  const taken = tenantUsers(tenant).some((u) => u.id !== exceptId && u.userName.toLowerCase() === userName.toLowerCase());
  if (taken) throw new ScimError(409, `userName ${userName} already exists`, "uniqueness");
}

// ---------- Output ----------
const meta = (type, r) => ({
  resourceType: type, created: r.created, lastModified: r.lastModified,
  location: `${SCIM_BASE}/${type}s/${r.id}`, version: `W/"${r.version}"`,
});

const toScimUser = (u) => ({
  schemas: [USER_SCHEMA],
  id: u.id,
  externalId: u.externalId,
  userName: u.userName,
  name: u.name,
  displayName: u.displayName,
  title: u.title,
  emails: u.emails,
  active: u.active,
  groups: groupsOf(u).map((g) => ({ value: g.id, display: g.displayName })), // read-only: change membership via /Groups
  meta: meta("User", u),
});

const toScimGroup = (g) => ({
  schemas: [GROUP_SCHEMA],
  id: g.id,
  externalId: g.externalId,
  displayName: g.displayName,
  members: [...g.members].map((id) => ({ value: id, display: users.get(id)?.userName })),
  meta: meta("Group", g),
});

// GET /Users?filter=userName eq "x"&startIndex=1&count=100 is the first thing Okta and Entra ID send.
// shortcut: supports only `attribute eq "value"`. Full SCIM filters (and, or, co, sw, gt, [..]) need a real parser.
function filterBy(req, allowed) {
  const filter = str(req.query.filter);
  if (filter === undefined) return () => true;
  const m = filter.length <= 300 && /^\s*([\w.]+)\s+eq\s+"((?:[^"\\]|\\.)*)"\s*$/i.exec(filter);
  const attr = m && allowed.find((a) => a.toLowerCase() === m[1].toLowerCase());
  if (!attr) throw new ScimError(400, `Only filters like ${allowed[0]} eq "value" are supported`, "invalidFilter");
  const value = m[2].replace(/\\(.)/g, "$1");
  // externalId is case-exact; userName and displayName are not
  return attr === "externalId" ? (r) => r[attr] === value : (r) => r[attr]?.toLowerCase() === value.toLowerCase();
}

function listResponse(req, all) {
  const startIndex = Math.max(1, Number.parseInt(str(req.query.startIndex) ?? "1", 10) || 1); // SCIM counts from 1
  const n = Number.parseInt(str(req.query.count) ?? "100", 10);
  const count = Number.isInteger(n) ? Math.min(100, Math.max(0, n)) : 100;
  const page = all.slice(startIndex - 1, startIndex - 1 + count);
  return { schemas: [LIST_SCHEMA], totalResults: all.length, startIndex, itemsPerPage: page.length, Resources: page };
}

// STEP 5: the whole point. The moment the IdP deactivates or deletes someone, their sessions die.
function endSessions(userId, why) {
  let ended = 0;
  for (const [k, s] of sessions) if (s.userId === userId) { sessions.delete(k); ended++; }
  if (ended) console.log(`🔒 ${why}: ended ${ended} session(s)`);
}

function touch(r) {
  r.lastModified = now();
  r.version++;
}

// ---------- PATCH (STEP 4) ----------
// Okta:     {"op":"replace","value":{"active":false}}                     (no path, value is an object)
// Entra ID: {"op":"Replace","path":"active","value":"False"}             (capital R, string "False")
// Entra ID: {"op":"replace","path":"emails[type eq \"work\"].value","value":"…"}
const USER_PATHS = Object.fromEntries(
  ["userName", "externalId", "displayName", "title", "active", "emails", "name", "name.givenName", "name.familyName"]
    .map((p) => [p.toLowerCase(), p]),
);
const EMAIL_BY_TYPE = /^emails\[type eq "(\w+)"\]\.value$/i;

function opsOf(body) {
  if (!body?.schemas?.includes?.(PATCH_SCHEMA)) throw new ScimError(400, `schemas must include ${PATCH_SCHEMA}`, "invalidSyntax");
  const ops = body.Operations;
  if (!Array.isArray(ops) || ops.length === 0 || ops.length > 50) throw new ScimError(400, "Operations must be an array of 1 to 50 items", "invalidSyntax");
  return ops.map((o) => {
    const op = str(o?.op)?.toLowerCase(); // "Replace" and "replace" are the same op
    if (!["add", "replace", "remove"].includes(op)) throw new ScimError(400, `Unknown op "${o?.op}"`, "invalidSyntax");
    if (o.path !== undefined && (typeof o.path !== "string" || o.path.length > 200)) throw new ScimError(400, "path must be a string", "invalidPath");
    return { op, path: o.path, value: o.value };
  });
}

function setUserPath(t, rawPath, value) {
  const email = EMAIL_BY_TYPE.exec(rawPath);
  if (email) {
    const type = email[1].toLowerCase();
    t.emails = (t.emails ?? []).filter((e) => e.type?.toLowerCase() !== type);
    if (value !== undefined) t.emails.unshift({ value, type, primary: true });
    return;
  }
  const path = USER_PATHS[rawPath.toLowerCase()];
  if (!path) throw new ScimError(400, `Unsupported path "${rawPath}"`, "invalidPath");
  const [a, b] = path.split(".");
  if (b) t[a] = { ...t[a], [b]: value };
  // A complex attribute without a sub-path: listed sub-attributes are replaced, the others are kept (RFC 7644 3.5.2)
  else if (a === "name" && value && typeof value === "object") t.name = { ...t.name, ...value };
  else t[a] = value;
}

function patchUser(u, body) {
  // Apply the ops to a COPY, then run the result through the same validation as POST/PUT
  const draft = structuredClone({
    userName: u.userName, externalId: u.externalId, name: u.name, displayName: u.displayName,
    title: u.title, emails: u.emails, active: u.active,
  });
  for (const { op, path, value } of opsOf(body)) {
    if (op === "remove") {
      if (!path) throw new ScimError(400, "remove needs a path", "noTarget");
      setUserPath(draft, path, undefined);
    } else if (path) {
      setUserPath(draft, path, value);
    } else {
      if (!value || typeof value !== "object" || Array.isArray(value)) throw new ScimError(400, "value must be an object when there is no path", "invalidValue");
      for (const [k, v] of Object.entries(value)) setUserPath(draft, k, v);
    }
  }
  return userAttrs(draft);
}

function memberIds(req, value) {
  if (!Array.isArray(value) || value.length > 100) throw new ScimError(400, "members must be an array of up to 100 items", "invalidValue");
  // A member must be a user of THIS tenant: Okta for TechCorp can't add Chaiwala's users to its groups
  return value.map((m) => {
    const id = str(m?.value);
    if (users.get(id)?.tenant !== req.tenant.id) throw new ScimError(400, `members: user ${id} not found`, "invalidValue");
    return id;
  });
}

const MEMBER_BY_VALUE = /^members\[value eq "([\w-]+)"\]$/i;

function patchGroup(req, g, body) {
  for (const { op, path, value } of opsOf(body)) {
    const p = path?.toLowerCase();
    const one = path && MEMBER_BY_VALUE.exec(path);
    if (op === "remove" && one) g.members.delete(one[1]);                              // Okta style
    else if (op === "remove" && p === "members") {
      if (value === undefined) g.members.clear();
      else for (const id of memberIds(req, value)) g.members.delete(id);               // Entra ID style
    } else if (op === "add" && p === "members") for (const id of memberIds(req, value)) g.members.add(id);
    else if (op === "replace" && p === "members") g.members = new Set(memberIds(req, value));
    else if (op === "replace" && (p === "displayname" || (!path && value?.displayName !== undefined))) {
      g.displayName = text(path ? value : value.displayName, "displayName", 200, true);
    } else throw new ScimError(400, `Unsupported ${op} on "${path ?? "(no path)"}"`, "invalidPath");
  }
  touch(g);
}

// ---------- App ----------
const app = express();
// IdPs send Content-Type: application/scim+json, which express.json() ignores by default
app.use(express.json({ limit: "10kb", type: ["application/json", "application/scim+json"] }));
app.use((req, res, next) => {
  res.set("Cache-Control", "no-store");
  next();
});

// ---------- SCIM API (the IdP calls this) ----------
const scim = express.Router();

scim.use((req, res, next) => {
  res.type("application/scim+json"); // res.json() keeps a Content-Type that is already set
  next();
});

// Tells the IdP what we support. Public: it says nothing about any customer.
scim.get("/ServiceProviderConfig", (req, res) => {
  res.json({
    schemas: ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
    patch: { supported: true },
    bulk: { supported: false, maxOperations: 0, maxPayloadSize: 0 },
    filter: { supported: true, maxResults: 100 },
    changePassword: { supported: false },
    sort: { supported: false },
    etag: { supported: false },
    authenticationSchemes: [{ type: "oauthbearertoken", name: "Bearer token", description: "Per-tenant token from ChaiDesk admin settings" }],
  });
});

// STEP 1: the bearer token says WHICH tenant is calling. Nothing in the URL or body can choose the tenant.
scim.use((req, res, next) => {
  const m = /^Bearer ([\w-]{10,200})$/.exec(req.get("authorization") ?? "");
  const tenant = m && tenants.get(sha256(m[1])); // hash lookup: no timing leak from comparing secrets
  if (!tenant) {
    res.set("WWW-Authenticate", 'Bearer realm="scim"');
    return scimError(res, 401, "Missing or invalid SCIM bearer token");
  }
  req.tenant = tenant;
  // Audit trail: every change the IdP makes to your users should be traceable (topic 55)
  // The URL stays %-encoded on purpose: decoding it would let "%0A" in a filter forge fake log lines
  res.on("finish", () => console.log(`🧾 SCIM [${tenant.id}] ${req.method} ${req.originalUrl} → ${res.statusCode}`));
  next();
});

// STEP 3: create
scim.post("/Users", (req, res) => {
  const attrs = userAttrs(req.body);
  assertUniqueUserName(req.tenant.id, attrs.userName);
  const t = now();
  const u = { id: crypto.randomUUID(), tenant: req.tenant.id, ...attrs, created: t, lastModified: t, version: 1 };
  users.set(u.id, u);
  console.log(`👤 [${u.tenant}] provisioned ${u.userName}${u.active ? "" : " (inactive)"}`);
  res.status(201).location(meta("User", u).location).json(toScimUser(u));
});

scim.get("/Users", (req, res) => {
  const match = filterBy(req, ["userName", "externalId"]);
  res.json(listResponse(req, tenantUsers(req.tenant.id).filter(match).map(toScimUser)));
});

scim.get("/Users/:id", (req, res) => res.json(toScimUser(findUser(req, req.params.id))));

// PUT = replace the whole user. Attributes left out are cleared (that's the difference from PATCH).
scim.put("/Users/:id", (req, res) => {
  const u = findUser(req, req.params.id);
  const attrs = userAttrs(req.body);
  assertUniqueUserName(req.tenant.id, attrs.userName, u.id);
  const wasActive = u.active;
  Object.assign(u, attrs); // id, tenant and created are never taken from the body
  touch(u);
  if (wasActive && !u.active) endSessions(u.id, `[${u.tenant}] ${u.userName} deactivated`);
  res.json(toScimUser(u));
});

// STEP 4 + 5: PATCH is how Okta and Entra ID deactivate someone who left the company
scim.patch("/Users/:id", (req, res) => {
  const u = findUser(req, req.params.id);
  const attrs = patchUser(u, req.body);
  assertUniqueUserName(req.tenant.id, attrs.userName, u.id);
  const wasActive = u.active;
  Object.assign(u, attrs);
  touch(u);
  if (wasActive && !u.active) endSessions(u.id, `[${u.tenant}] ${u.userName} deactivated`);
  res.json(toScimUser(u));
});

scim.delete("/Users/:id", (req, res) => {
  const u = findUser(req, req.params.id);
  // shortcut: hard delete. Many apps soft-delete (keep the row, inactive) so the user's data and audit history survive.
  users.delete(u.id);
  for (const g of groupsOf(u)) g.members.delete(u.id);
  endSessions(u.id, `[${u.tenant}] ${u.userName} deleted`);
  res.status(204).end();
});

// STEP 6: groups. The IdP pushes its groups; we map group names to roles in our app.
scim.post("/Groups", (req, res) => {
  const b = req.body ?? {};
  const displayName = text(b.displayName, "displayName", 200, true);
  if (tenantGroups(req.tenant.id).some((g) => g.displayName.toLowerCase() === displayName.toLowerCase())) {
    throw new ScimError(409, `Group ${displayName} already exists`, "uniqueness");
  }
  const t = now();
  const g = {
    id: crypto.randomUUID(), tenant: req.tenant.id, displayName, externalId: text(b.externalId, "externalId", 256),
    members: new Set(b.members === undefined ? [] : memberIds(req, b.members)), created: t, lastModified: t, version: 1,
  };
  groups.set(g.id, g);
  res.status(201).location(meta("Group", g).location).json(toScimGroup(g));
});

scim.get("/Groups", (req, res) => {
  const match = filterBy(req, ["displayName", "externalId"]);
  res.json(listResponse(req, tenantGroups(req.tenant.id).filter(match).map(toScimGroup)));
});

scim.get("/Groups/:id", (req, res) => res.json(toScimGroup(findGroup(req, req.params.id))));

// shortcut: no PUT /Groups. Okta and Entra ID use PATCH for membership changes.
scim.patch("/Groups/:id", (req, res) => {
  const g = findGroup(req, req.params.id);
  patchGroup(req, g, req.body);
  res.json(toScimGroup(g));
});

scim.delete("/Groups/:id", (req, res) => {
  groups.delete(findGroup(req, req.params.id).id);
  res.status(204).end();
});

scim.use((req, res) => scimError(res, 404, "Unknown SCIM endpoint"));
app.use("/scim/v2", scim);

// ---------- The app itself (what the employees use) ----------
// shortcut: SSO stand-in. In real life the user signs in through Okta / Entra ID with OIDC or SAML (topics 58, 60),
// and THEN this check runs: is the person who just proved who they are provisioned and active in our app?
app.post("/sso/login", (req, res) => {
  const tenant = str(req.body?.tenant);
  const userName = str(req.body?.userName)?.trim().toLowerCase();
  const u = tenant && userName && tenantUsers(tenant).find((x) => x.userName.toLowerCase() === userName);
  if (!u) return res.status(403).json({ error: "No ChaiDesk account. Ask your IT admin to assign you the app." });
  if (!u.active) return res.status(403).json({ error: "Your ChaiDesk account is deactivated" });
  const sid = crypto.randomBytes(32).toString("base64url");
  sessions.set(sha256(sid), { userId: u.id });
  res.cookie("sid", sid, { httpOnly: true, sameSite: "lax", path: "/" }); // add secure: true on HTTPS
  res.json({ message: `Welcome ${u.displayName ?? u.userName}` });
});

const roles = (u) => (groupsOf(u).some((g) => g.displayName === ADMIN_GROUP) ? ["member", "admin"] : ["member"]);

// Every request re-reads the user: deactivation and group changes take effect on the very next request
function currentUser(req) {
  const sid = parseCookies(req).sid;
  const s = sid && sessions.get(sha256(sid));
  const u = s && users.get(s.userId);
  if (!u?.active) {
    if (s) sessions.delete(sha256(sid));
    return null;
  }
  return u;
}

app.get("/me", (req, res) => {
  const u = currentUser(req);
  if (!u) return res.status(401).json({ error: "Not signed in" });
  res.json({ tenant: u.tenant, userName: u.userName, displayName: u.displayName, title: u.title, roles: roles(u) });
});

app.get("/admin/reports", (req, res) => {
  const u = currentUser(req);
  if (!u) return res.status(401).json({ error: "Not signed in" });
  if (!roles(u).includes("admin")) return res.status(403).json({ error: `Only members of "${ADMIN_GROUP}" can see reports` });
  res.json({ tenant: u.tenant, activeUsers: tenantUsers(u.tenant).filter((x) => x.active).length });
});

app.use((req, res) => res.status(404).json({ error: "Not found" }));

// Errors (bad JSON, body too big, ScimError, bugs) come here. Never send the stack trace to the client.
app.use((err, req, res, next) => {
  const isScim = req.path.startsWith("/scim/");
  let status = 500;
  let detail = "Something went wrong";
  let scimType;
  if (err instanceof ScimError) ({ status, message: detail, scimType } = err);
  else if (err.type === "entity.parse.failed") [status, detail, scimType] = [400, "Body must be valid JSON", "invalidSyntax"];
  else if (err.type === "entity.too.large") [status, detail] = [413, "Request body too large"];
  else console.error(err);
  if (isScim) return scimError(res, status, detail, scimType);
  res.status(status).json({ error: detail });
});

// Express 5 passes a listen error (like "port already in use") to this callback instead of crashing
app.listen(PORT, (err) => {
  if (err) throw err;
  console.log(`☕ ChaiDesk on ${BASE_URL} (SCIM base URL: ${SCIM_BASE})`);
});
