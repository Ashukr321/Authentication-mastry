const express = require("express");
const crypto = require("crypto");

const PORT = Number(process.env.PORT) || 3000;
const BASE_URL = `http://localhost:${PORT}`;

// ---------- Helpers ----------
const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");
const str = (v) => (typeof v === "string" ? v : undefined);
const fail = (status, message) => Object.assign(new Error(message), { status });

// =====================================================================================
// PART 1: Zanzibar / OpenFGA-style relationships (ReBAC)
// =====================================================================================

// STEP 1: the authorization MODEL. It says which relations exist and how they imply each other.
// It is this OpenFGA model, written as a JS object (the DSL version is in the README):
//   type doc
//     relations
//       define parent: [folder]
//       define owner:  [user]
//       define editor: [user, team#member] or owner or editor from parent
//       define viewer: [user, user:*, team#member] or editor or viewer from parent
// direct   = which kinds of subject a tuple may grant this relation to
// computed = another relation on the SAME object implies this one (every owner is an editor)
// from     = follow a relation to ANOTHER object and check there (viewer of the parent folder = viewer of the doc)
const MODEL = {
  org: { admin: { direct: ["user"] } },
  team: { member: { direct: ["user", "team#member"] } }, // a team can contain another team
  folder: {
    owner: { direct: ["user"] },
    editor: { direct: ["user", "team#member"], computed: ["owner"] },
    viewer: { direct: ["user", "team#member"], computed: ["editor"] },
  },
  doc: {
    parent: { direct: ["folder"] },
    owner: { direct: ["user"] },
    editor: { direct: ["user", "team#member"], computed: ["owner"], from: [["parent", "editor"]] },
    viewer: { direct: ["user", "user:*", "team#member"], computed: ["editor"], from: [["parent", "viewer"]] },
  },
};

// STEP 2: relationship TUPLES: "object#relation@subject", e.g. "doc:roadmap#viewer@user:priya".
// shortcut: in-memory Map, lost on restart. OpenFGA/SpiceDB keep tuples in Postgres/MySQL/Spanner.
const tuples = new Map(); // "doc:roadmap#viewer" -> Set { "user:priya", "team:eng#member", ... }
const key = (object, relation) => `${object}#${relation}`;
const typeOf = (obj) => obj.split(":")[0];
const subjectKind = (s) => (s === "user:*" ? "user:*" : s.includes("#") ? `${typeOf(s)}#${s.split("#")[1]}` : typeOf(s));
const OBJECT_RE = /^[a-z]+:[a-z0-9-]{1,40}$/;
const SUBJECT_RE = /^([a-z]+:[a-z0-9-]{1,40}(#[a-z]+)?|user:\*)$/;

function writeTuple(object, relation, subject) {
  if (!OBJECT_RE.test(object) || !SUBJECT_RE.test(subject)) throw fail(400, "Bad object or subject");
  // The model is the schema: you can't write a tuple the model doesn't allow (a folder can't be a doc's viewer)
  if (!MODEL[typeOf(object)]?.[relation]?.direct.includes(subjectKind(subject))) {
    throw fail(400, `${subjectKind(subject)} can't be ${relation} of a ${typeOf(object)}`);
  }
  const k = key(object, relation);
  if (!tuples.has(k)) tuples.set(k, new Set());
  tuples.get(k).add(subject);
}
const deleteTuple = (object, relation, subject) => tuples.get(key(object, relation))?.delete(subject) ?? false;

// STEP 3: CHECK. "Is there a path in the tuple graph from object#relation to this user?"
// Returns the path (WHY they have access) or null. `seen` stops loops (team A in team B in team A).
// shortcut: no depth limit or caching. OpenFGA stops at depth 25 and caches sub-checks.
function check(object, relation, user, seen = new Set()) {
  const k = key(object, relation);
  const def = MODEL[typeOf(object)]?.[relation];
  if (!def || seen.has(k)) return null;
  seen.add(k);

  for (const s of tuples.get(k) ?? []) {
    // a) direct tuple: doc:roadmap#viewer@user:priya (or the public wildcard user:*)
    if (s === user || (s === "user:*" && user.startsWith("user:"))) return [`${k}@${s}`];
    // b) userset: doc:roadmap#viewer@team:eng#member → is the user a member of team:eng?
    if (s.includes("#")) {
      const [obj, rel] = s.split("#");
      const sub = check(obj, rel, user, seen);
      if (sub) return [`${k}@${s}`, ...sub];
    }
  }
  // c) computed userset: every editor is also a viewer
  for (const rel of def.computed ?? []) {
    const sub = check(object, rel, user, seen);
    if (sub) return [`${k} (every ${rel} is also ${relation})`, ...sub];
  }
  // d) tuple-to-userset: viewer of the parent folder → viewer of the doc
  for (const [via, rel] of def.from ?? []) {
    for (const parent of tuples.get(key(object, via)) ?? []) {
      const sub = check(parent, rel, user, seen);
      if (sub) return [`${key(object, via)}@${parent}`, ...sub];
    }
  }
  return null;
}

// STEP 4: LIST OBJECTS. "Which docs can Priya view?" (for the doc list page)
// shortcut: runs check() on every doc. Fine for 10 docs; for millions, real systems walk the graph
// backwards or keep a pre-computed index (Zanzibar's "Leopard"), or use OpenFGA's ListObjects API.
const listObjects = (relation, user) => [...docs.keys()].filter((id) => check(`doc:${id}`, relation, user));

// =====================================================================================
// PART 2: OPA-style policy (guardrails on attributes)
// =====================================================================================

// STEP 5: the POLICY. In real life this is a Rego file run by OPA (a sidecar or service): the app sends
// an INPUT document (JSON), OPA returns a DECISION (JSON). The same rules in Rego are in the README.
// It's a pure function: no database, no clock, no I/O. Same input → same answer, easy to unit test.
function policy(input) {
  const { user, action, resource, relationship, target } = input;
  const deny = [];
  if (!relationship.allowed) deny.push(`needs ${relationship.relation} on ${resource.type}:${resource.id}`);
  if (user.status !== "active") deny.push("user is suspended");
  if (resource.classification === "confidential" && user.employment === "contractor") {
    deny.push("contractors can't access confidential docs"); // even if someone shared it with them
  }
  if (action === "share" && target?.org && target.org !== user.org) deny.push("can't share outside your company");
  if (action === "share" && target?.subject === "user:*" && resource.classification !== "public") {
    deny.push(`a ${resource.classification} doc can't be made public`);
  }
  return { allow: deny.length === 0, deny }; // default deny: allowed only if NO rule objects
}

// =====================================================================================
// The app: DocuChai, a tiny Google-Docs. Routes are the PEP (enforcement point).
// =====================================================================================

// shortcut: in-memory Maps, lost on restart. A real app uses database tables.
const users = new Map();  // username -> { username, salt, passwordHash, org, employment, status }
const tokens = new Map(); // sha256(token) -> username
const docs = new Map();   // id -> { title, body, classification }

// shortcut: test accounts with known passwords. A real app has a signup (topic 06) and SSO (topic 57).
for (const [username, org, employment] of [
  ["rahul", "chaico", "employee"], ["priya", "chaico", "employee"], ["karan", "chaico", "employee"],
  ["vikram", "chaico", "contractor"], ["anita", "chaico", "employee"], ["sneha", "otherco", "employee"],
]) {
  const salt = crypto.randomBytes(16);
  users.set(username, { username, salt, passwordHash: crypto.scryptSync(`${username}-pass-2026`, salt, 64), org, employment, status: "active" });
}
docs.set("roadmap", { title: "2027 Roadmap", body: "Ship passkeys.", classification: "internal" });
docs.set("q3-budget", { title: "Q3 Budget", body: "₹42 lakh for servers.", classification: "confidential" });
docs.set("lunch-menu", { title: "Lunch Menu", body: "Friday: biryani.", classification: "public" });
for (const t of [
  "org:chaico#admin@user:anita",
  "team:eng#member@user:priya",
  "team:eng#member@user:vikram",
  "team:eng#member@team:interns#member", // nested team: every intern is in eng
  "team:interns#member@user:karan",
  "folder:engineering#owner@user:rahul",
  "folder:engineering#viewer@team:eng#member",
  "doc:roadmap#parent@folder:engineering",
  "doc:roadmap#owner@user:rahul",
  "doc:q3-budget#parent@folder:engineering",
  "doc:q3-budget#owner@user:rahul",
  "doc:lunch-menu#owner@user:anita",
  "doc:lunch-menu#viewer@user:*",
]) {
  const [left, subject] = t.split("@");
  const [object, relation] = left.split("#");
  writeTuple(object, relation, subject);
}

const DUMMY_SALT = crypto.randomBytes(16);
function checkPassword(username, password) {
  const user = username ? users.get(username) : undefined;
  const hash = crypto.scryptSync(password ?? "", user?.salt ?? DUMMY_SALT, 64); // same time for unknown users (topic 51)
  return user && crypto.timingSafeEqual(hash, user.passwordHash) ? user : null;
}

// Each action needs one relation. This table is the only place the app maps actions to the model.
const ACTION_RELATION = { view: "viewer", edit: "editor", share: "owner" };

// STEP 6: ask BOTH engines. Relationship first (OpenFGA), then guardrails (OPA). Both must say yes.
function authorize(user, action, id, target) {
  const doc = docs.get(id);
  const relation = ACTION_RELATION[action];
  const why = check(`doc:${id}`, relation, `user:${user.username}`);
  const input = {
    user: { id: user.username, org: user.org, employment: user.employment, status: user.status },
    action,
    resource: { type: "doc", id, classification: doc.classification },
    relationship: { relation, allowed: Boolean(why) },
    target,
  };
  const decision = policy(input);
  // STEP 7: the decision log. Who, what, which doc, the answer, and why. (OPA ships these for you.)
  console.log(`🧾 ${JSON.stringify({ user: user.username, action, doc: id, allow: decision.allow, deny: decision.deny })}`);
  return { ...decision, why };
}

// Load the doc and authorize, or answer 404/403. Not even a viewer → 404, so nobody learns which ids exist (topic 31).
function guard(req, res, action, target) {
  const id = req.params.id;
  if (!docs.has(id) || !check(`doc:${id}`, "viewer", `user:${req.user.username}`)) {
    res.status(404).json({ error: "Doc not found" });
    return null;
  }
  const d = authorize(req.user, action, id, target);
  if (!d.allow) {
    res.status(403).json({ error: "Forbidden", reasons: d.deny });
    return null;
  }
  return { id, doc: docs.get(id), why: d.why };
}

const app = express();
app.use(express.json({ limit: "10kb" }));
app.use((req, res, next) => {
  res.set("Cache-Control", "no-store");
  next();
});

app.post("/login", (req, res) => {
  const user = checkPassword(str(req.body?.username)?.trim().toLowerCase(), str(req.body?.password));
  if (!user) return res.status(401).json({ error: "Wrong username or password" });
  const token = crypto.randomBytes(32).toString("base64url");
  tokens.set(sha256(token), user.username); // store only the hash (topic 09)
  res.json({ token });
});

// Authentication is a different job (who are you?). Everything below is authorization (what may you do?).
function requireLogin(req, res, next) {
  const token = req.get("authorization")?.match(/^Bearer (.+)$/)?.[1];
  const username = token && tokens.get(sha256(token));
  if (!username) return res.status(401).json({ error: "Log in first" });
  req.user = users.get(username);
  next();
}

// The list: ListObjects (relationships) THEN the policy, so a contractor's list hides confidential docs
app.get("/docs", requireLogin, (req, res) => {
  const ids = listObjects("viewer", `user:${req.user.username}`).filter((id) => authorize(req.user, "view", id).allow);
  res.json({ docs: ids.map((id) => ({ id, title: docs.get(id).title })) });
});

app.get("/docs/:id", requireLogin, (req, res) => {
  const g = guard(req, res, "view");
  if (g) res.json({ id: g.id, ...g.doc, why: g.why });
});

app.put("/docs/:id", requireLogin, (req, res) => {
  const body = str(req.body?.body);
  if (body === undefined || body.length > 5000) return res.status(400).json({ error: "body must be a string up to 5000 characters" });
  const g = guard(req, res, "edit");
  if (!g) return;
  g.doc.body = body;
  res.json({ id: g.id, ...g.doc, why: g.why });
});

// Sharing = writing a tuple. Only owners share, and the policy can still say no (outside company, public).
app.post("/docs/:id/share", requireLogin, (req, res) => {
  const subject = str(req.body?.with);
  const relation = str(req.body?.relation);
  if (!subject || !SUBJECT_RE.test(subject) || !["viewer", "editor"].includes(relation)) {
    return res.status(400).json({ error: 'Send {"with":"user:priya" | "team:eng#member" | "user:*", "relation":"viewer" | "editor"}' });
  }
  const person = subject.startsWith("user:") && subject !== "user:*" ? users.get(subject.slice(5)) : null;
  if (subject.startsWith("user:") && subject !== "user:*" && !person) return res.status(400).json({ error: "No such user" });
  const g = guard(req, res, "share", { subject, org: person?.org });
  if (!g) return;
  writeTuple(`doc:${g.id}`, relation, subject);
  res.json({ message: `Shared doc:${g.id} with ${subject} as ${relation}`, tuple: `doc:${g.id}#${relation}@${subject}` });
});

// Revoking = deleting the tuple. The very next check sees it: no token to wait out.
app.delete("/docs/:id/share", requireLogin, (req, res) => {
  const subject = str(req.body?.with);
  const relation = str(req.body?.relation);
  if (!subject || !["viewer", "editor"].includes(relation)) return res.status(400).json({ error: "Send with and relation" });
  const g = guard(req, res, "share");
  if (!g) return;
  const removed = deleteTuple(`doc:${g.id}`, relation, subject);
  res.json({ message: removed ? `Removed doc:${g.id}#${relation}@${subject}` : "That tuple didn't exist" });
});

// Admins are a relation too: org:chaico#admin@user:anita
function requireAdmin(req, res, next) {
  if (!check("org:chaico", "admin", `user:${req.user.username}`)) return res.status(403).json({ error: "Admins only" });
  next();
}

// Suspending changes an ATTRIBUTE, not a tuple. One switch, and the policy blocks the user everywhere.
app.post("/admin/users/:username/status", requireLogin, requireAdmin, (req, res) => {
  const user = users.get(req.params.username);
  const status = str(req.body?.status);
  if (!user) return res.status(404).json({ error: "No such user" });
  if (!["active", "suspended"].includes(status)) return res.status(400).json({ error: "status must be active or suspended" });
  user.status = status;
  res.json({ username: user.username, status });
});

// A raw Check API, like OpenFGA's POST /stores/{id}/check. Internal, so admins only:
// letting anyone ask "can X see Y?" would leak who has access to what.
app.post("/authz/check", requireLogin, requireAdmin, (req, res) => {
  const object = str(req.body?.object);
  const relation = str(req.body?.relation);
  const user = str(req.body?.user);
  if (!object || !OBJECT_RE.test(object) || !relation || !user || !SUBJECT_RE.test(user)) {
    return res.status(400).json({ error: 'Send {"object":"doc:roadmap","relation":"viewer","user":"user:priya"}' });
  }
  const why = check(object, relation, user);
  res.json({ allowed: Boolean(why), why });
});

app.use((req, res) => res.status(404).json({ error: "Not found" }));

app.use((err, req, res, next) => {
  if (err.type === "entity.parse.failed") return res.status(400).json({ error: "Body must be valid JSON" });
  if (err.type === "entity.too.large") return res.status(413).json({ error: "Request body too large" });
  if (err.status === 400) return res.status(400).json({ error: err.message });
  console.error(err);
  res.status(500).json({ error: "Something went wrong" });
});

app.listen(PORT, (err) => {
  if (err) throw err;
  console.log(`📄 DocuChai on ${BASE_URL}`);
});
