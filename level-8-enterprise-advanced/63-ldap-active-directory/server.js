const express = require("express");
const crypto = require("crypto");
const assert = require("assert");

const PORT = Number(process.env.PORT) || 3000;
const BASE_URL = `http://localhost:${PORT}`;

// ======================================================================
// PART A: a tiny fake Active Directory (the company's user directory)
// shortcut: everything below pretends to be a Domain Controller. A real app talks to a real one over the network
// (ldaps://dc1.chaicorp.local:636) with a library like `ldapts`. The rules it follows (DNs, filters, bind results,
// AD error codes, lockout) are the real ones, so the app code in PART B looks like real LDAP code.
// ======================================================================

const BASE_DN = "DC=chaicorp,DC=local";        // the domain chaicorp.local, written as a DN
const PEOPLE = `OU=People,${BASE_DN}`;          // folder (Organizational Unit) for employees
const GROUPS = `OU=Groups,${BASE_DN}`;
const SERVICE = `OU=Service Accounts,${BASE_DN}`;
const group = (cn) => `CN=${cn},${GROUPS}`;

const UAC_DISABLED = 0x2;          // userAccountControl bit 2 = ACCOUNTDISABLE (512 = normal, 514 = disabled)
const LOCKOUT_THRESHOLD = 5;       // domain policy: 5 wrong passwords in a row and the account is locked everywhere
const LOCKOUT_MS = 30 * 60 * 1000; // ...for 30 minutes (Windows login, email, VPN, every app that uses AD)

class LdapError extends Error {
  constructor(code, message) { super(message); this.code = code; }
}
// AD packs the real reason into the message of error 49 (invalidCredentials) as "data XXX"
const adBindError = (sub) => new LdapError(49, `80090308: LdapErr: DSID-0C09044E, comment: AcceptSecurityContext error, data ${sub}, v4563`);

// shortcut: in-memory list, lost on restart. A real AD is a replicated database on the Domain Controllers.
const entries = []; // { dn, attrs, secret?, badPwdCount, lockedUntil }
const hashPw = (pw, salt) => crypto.scryptSync(pw, salt, 64); // real AD stores an NT hash; scrypt keeps the demo honest

function addEntry(dn, attrs, password) {
  const secret = password && (() => { const salt = crypto.randomBytes(16); return { salt, hash: hashPw(password, salt) }; })();
  // distinguishedName and objectGUID exist on every AD object. objectGUID never changes, even if the user is renamed.
  entries.push({ dn, attrs: { ...attrs, distinguishedName: dn, objectGUID: crypto.randomUUID() }, secret, badPwdCount: 0, lockedUntil: 0 });
}
function addUser({ sam, cn, department, title, salary, memberOf, uac = 512, ou = PEOPLE, password }) {
  addEntry(`CN=${cn},${ou}`, {
    objectClass: ["top", "person", "organizationalPerson", "user"],
    cn, sAMAccountName: sam, userPrincipalName: `${sam}@chaicorp.local`, mail: `${sam}@chaicorp.in`,
    department, title, salary, memberOf, userAccountControl: String(uac),
  }, password);
}

// Groups can be members of other groups (nested): IT-Leads → Portal-Admins → Portal-Users
// shortcut: we store only memberOf. Real AD stores `member` on the group and computes `memberOf` from it.
addEntry(group("Portal-Users"), { objectClass: ["top", "group"], cn: "Portal-Users", memberOf: [] });
addEntry(group("Portal-Admins"), { objectClass: ["top", "group"], cn: "Portal-Admins", memberOf: [group("Portal-Users")] });
addEntry(group("IT-Leads"), { objectClass: ["top", "group"], cn: "IT-Leads", memberOf: [group("Portal-Admins")] });
addEntry(group("Engineering"), { objectClass: ["top", "group"], cn: "Engineering", memberOf: [group("Portal-Users")] });
addEntry(group("Finance"), { objectClass: ["top", "group"], cn: "Finance", memberOf: [] });

addUser({ sam: "priya", cn: "Priya Sharma", department: "IT", title: "IT Lead", salary: "2475000", memberOf: [group("IT-Leads")], password: "masala-dosa-77" });
addUser({ sam: "rahul", cn: "Rahul Verma", department: "Engineering", title: "Backend Developer", salary: "1850000", memberOf: [group("Engineering")], password: "chai-and-code-42" });
addUser({ sam: "amit", cn: "Amit Patel", department: "Engineering", title: "Ex-employee", salary: "1600000", memberOf: [group("Engineering")], uac: 514, password: "old-pass-123" });
addUser({ sam: "neha", cn: "Neha Gupta", department: "Finance", title: "Accountant", salary: "1400000", memberOf: [group("Finance")], password: "ledger-and-tea-9" });

// The app's own AD account, used only to SEARCH for users. Its password comes from a secrets manager (topic 54).
const SVC_DN = `CN=svc-chaiportal,${SERVICE}`;
const SVC_PASSWORD = crypto.randomBytes(18).toString("base64url");
addUser({ sam: "svc-chaiportal", cn: "svc-chaiportal", department: "IT", title: "Service account", memberOf: [], uac: 66048, ou: SERVICE, password: SVC_PASSWORD });

// ---------- LDAP search filters (RFC 4515), e.g. (&(objectClass=user)(sAMAccountName=rahul)) ----------

// STEP 3 (the fix for LDAP injection): turn every special filter character into \XX so it is plain data
const escapeFilter = (value) => String(value).replace(/[\\*()\0]/g, (c) => "\\" + c.charCodeAt(0).toString(16).padStart(2, "0"));

function parseFilter(text) {
  let i = 0;
  const fail = () => { throw new LdapError(87, `Bad search filter: ${text}`); };
  function filter() {
    if (text[i++] !== "(") fail();
    let node;
    if (text[i] === "&" || text[i] === "|") {
      const op = text[i++], list = [];
      while (text[i] === "(") list.push(filter());
      node = { op, list };
    } else if (text[i] === "!") {
      i++;
      node = { op: "!", inner: filter() };
    } else {
      const m = /^([A-Za-z][A-Za-z0-9-]*)=([^()]*)/.exec(text.slice(i)); // only "=" here; AD also has >=, <=, ~=
      if (!m) fail();
      i += m[0].length;
      if (/\\(?![0-9a-fA-F]{2})/.test(m[2])) fail();
      const decode = (s) => s.replace(/\\([0-9a-fA-F]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16)));
      // An unescaped * is a wildcard. An escaped one (\2a) is a real star, and it is NOT split here.
      node = m[2] === "*" ? { op: "present", attr: m[1] } : { op: "match", attr: m[1], parts: m[2].split("*").map(decode) };
    }
    if (text[i++] !== ")") fail();
    return node;
  }
  const tree = filter();
  if (i !== text.length) fail();
  return tree;
}

// Attribute names and (most) values are case-insensitive in AD
const values = (attrs, name) => {
  const key = Object.keys(attrs).find((k) => k.toLowerCase() === name.toLowerCase());
  const v = key === undefined ? [] : attrs[key];
  return (Array.isArray(v) ? v : [v]).filter((x) => x !== undefined);
};
const escapeRe = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

function matches(node, attrs) {
  if (node.op === "&") return node.list.every((n) => matches(n, attrs));
  if (node.op === "|") return node.list.some((n) => matches(n, attrs));
  if (node.op === "!") return !matches(node.inner, attrs);
  if (node.op === "present") return values(attrs, node.attr).length > 0;
  const re = new RegExp("^" + node.parts.map(escapeRe).join(".*") + "$", "is"); // parts = text between wildcards
  return values(attrs, node.attr).some((v) => re.test(String(v)));
}

const sameDn = (a, b) => a.toLowerCase() === b.toLowerCase();
const underDn = (dn, base) => sameDn(dn, base) || dn.toLowerCase().endsWith("," + base.toLowerCase());

// One LDAP connection. bind() = "log in to the directory", search() = "find entries".
function connect(url) {
  let boundAs = null; // null = anonymous
  return {
    bind(dn, password) {
      if (url.startsWith("ldap://")) console.log(`👀 Sniffer on the network (${url}) sees: BindRequest dn="${dn}" password="${password}"`);
      else console.log(`🔒 ${url}: bind for "${dn}" travels inside TLS, a sniffer sees only encrypted bytes`);
      // ⚠️ The famous trap (RFC 4513 "unauthenticated bind"): a DN with an EMPTY password is not an error.
      // AD answers "success" and the connection is simply anonymous. An app that checks only "did bind throw?" lets anyone in.
      if (password === "") { boundAs = null; return; }
      const e = entries.find((x) => sameDn(x.dn, dn));
      if (!e?.secret) throw adBindError("525");                         // 525 = user not found
      if (e.lockedUntil > Date.now()) throw adBindError("775");         // 775 = account locked out
      if (!crypto.timingSafeEqual(hashPw(password, e.secret.salt), e.secret.hash)) {
        if (++e.badPwdCount >= LOCKOUT_THRESHOLD) { e.lockedUntil = Date.now() + LOCKOUT_MS; e.badPwdCount = 0; }
        throw adBindError("52e");                                       // 52e = wrong password
      }
      e.badPwdCount = 0;
      // AD reports these only AFTER the password was right, so 533 also means "the password was correct"
      if (Number(e.attrs.userAccountControl) & UAC_DISABLED) throw adBindError("533"); // 533 = account disabled
      boundAs = e.dn;
    },
    search(base, { scope = "sub", filter, attributes = [], sizeLimit = 0 }) {
      // AD refuses searches on anonymous connections, which is why the app needs its own service account
      if (!boundAs) throw new LdapError(1, "000004DC: LdapErr: DSID-0C090A5C, comment: In order to perform this operation a successful bind must be completed on the connection.");
      const tree = parseFilter(filter);
      let found = entries.filter((e) => (scope === "base" ? sameDn(e.dn, base) : underDn(e.dn, base)) && matches(tree, e.attrs));
      if (sizeLimit) found = found.slice(0, sizeLimit);
      return found.map((e) => {
        const out = { dn: e.dn };
        for (const [k, v] of Object.entries(e.attrs)) {
          if (!attributes.length || attributes.some((a) => a.toLowerCase() === k.toLowerCase())) out[k] = v;
        }
        return out; // the password hash is never an attribute, so it can never be returned
      });
    },
  };
}

// Self-check of the filter parser and escaping (runs on every start, takes under 1 ms)
assert.equal(escapeFilter("a*b(c)\\"), "a\\2ab\\28c\\29\\5c");
assert.throws(() => parseFilter("(cn=a"));
assert.throws(() => parseFilter("(cn=a))"));
assert.equal(matches(parseFilter("(&(cn=Pri*)(!(salary=1*)))"), { cn: "Priya Sharma", salary: "2475000" }), true);
assert.equal(matches(parseFilter(`(cn=${escapeFilter("*")})`), { cn: "Rahul" }), false);
assert.equal(matches(parseFilter(`(cn=${escapeFilter("*)(x")})`), { cn: "*)(x" }), true);

// ======================================================================
// PART B: ChaiPortal, the company's internal web app, which logs employees in with their AD password
// ======================================================================

// STEP 1: one service connection, opened once and reused (a connection pool in real apps)
// shortcut: no reconnect logic. Real LDAP connections drop; libraries like ldapts reconnect for you.
const LDAP_URL = "ldaps://dc1.chaicorp.local:636";  // ✅ TLS. Plain ldap:// on 389 sends passwords in clear text.
const svc = connect(LDAP_URL);
svc.bind(SVC_DN, SVC_PASSWORD);

const vulnLdapUrl = "ldap://dc1.chaicorp.local:389"; // ❌ no TLS
const vulnSvc = connect(vulnLdapUrl);
vulnSvc.bind(SVC_DN, SVC_PASSWORD);

// AD group (full DN, never just the name) → app role
const GROUP_ROLES = {
  [group("Portal-Users")]: "user",
  [group("Portal-Admins")]: "admin",
};
const AD_REASONS = { "52e": "wrong password", "525": "no such user", "533": "account disabled", "775": "account locked",
  "532": "password expired", "701": "account expired", "773": "must change password" };

// shortcut: in-memory Maps. A real app uses tables (users, sessions) and Redis for the rate-limit counters.
const localUsers = new Map(); // id -> { id, adGuid, username, name, roles, createdAt, lastLoginAt }
const byGuid = new Map();     // AD objectGUID -> local id
const sessions = new Map();   // sha256(sid) -> { userId, adGuid, expiresAt }
const failures = new Map();   // username -> { count, resetAt }

const APP_FAIL_LIMIT = 3;                 // lower than AD's lockout (5), so our login form can't lock anyone out
const FAIL_WINDOW_MS = 15 * 60 * 1000;
const SESSION_MS = 8 * 60 * 60 * 1000;    // one working day
const USERNAME_RE = /^[a-zA-Z0-9._-]{1,64}$/;

const sha256 = (v) => crypto.createHash("sha256").update(v).digest("hex");
const str = (v) => (typeof v === "string" ? v : undefined);

// STEP 5: follow nested groups (IT-Leads → Portal-Admins → Portal-Users)
// AD can also do this in one search with the "in chain" rule: (memberOf:1.2.840.113556.1.4.1941:=<group DN>)
function allGroups(directGroups) {
  const seen = new Set();
  const queue = [...directGroups];
  while (queue.length && seen.size < 200) { // the cap protects against huge or looping group trees
    const dn = queue.shift();
    if (seen.has(dn.toLowerCase())) continue;
    seen.add(dn.toLowerCase());
    const [g] = svc.search(dn, { scope: "base", filter: "(objectClass=group)", attributes: ["memberOf"] });
    queue.push(...(g?.memberOf ?? []));
  }
  return seen;
}

const app = express();
app.use(express.json({ limit: "10kb" }));
app.use((req, res, next) => {
  res.set("Cache-Control", "no-store");
  next();
});

app.get("/", (req, res) => res.json({
  app: "ChaiPortal (logs in with Active Directory)",
  vulnerable: ["POST /vulnerable/login", "GET /vulnerable/people?q="],
  safe: ["POST /login", "GET /me", "GET /admin", "GET /people?q="],
  demo: ["POST /demo/ad/disable/:username (pretend IT disabled the account in AD)"],
}));

// ======================================================================
// ❌ VULNERABLE versions
// ======================================================================

// Bugs: plain ldap://, filter built by string concatenation (injection), empty password accepted (unauthenticated
// bind), raw AD errors sent to the browser (they say WHY the login failed), no limit (anyone can lock accounts).
app.post("/vulnerable/login", (req, res) => {
  const username = String(req.body?.username ?? "");
  const password = String(req.body?.password ?? "");
  const filter = `(&(objectClass=user)(sAMAccountName=${username}))`; // ❌ "*" matches everyone
  const [user] = vulnSvc.search(BASE_DN, { filter, attributes: ["cn", "memberOf"] }); // ❌ takes the first match
  if (!user) return res.status(401).json({ error: "No such user" });                  // ❌ enumeration
  try {
    connect(vulnLdapUrl).bind(user.dn, password); // ❌ password "" → "success"
  } catch (e) {
    return res.status(401).json({ error: e.message }); // ❌ "data 52e" vs "data 533" vs "data 775"
  }
  res.json({ message: `Welcome, ${user.cn}`, groups: user.memberOf });
});

// The developer DID limit the returned attributes, but the filter is still glued together from user input,
// so an attacker can add their own conditions (on any attribute) and learn from "results / no results".
app.get("/vulnerable/people", (req, res) => {
  const q = String(req.query.q ?? "");
  const filter = `(&(objectClass=user)(cn=${q}))`; // ❌ no escaping, and no login needed
  const found = vulnSvc.search(BASE_DN, { filter, attributes: ["cn", "mail", "title", "department"] }); // ❌ whole domain
  res.json(found);
});

// ======================================================================
// ✅ SAFE versions
// ======================================================================

app.post("/login", (req, res) => {
  const username = str(req.body?.username)?.trim().toLowerCase();
  const password = str(req.body?.password);

  // STEP 2: validate input. An empty password must never reach bind() (it would "succeed" as anonymous).
  if (!username || !USERNAME_RE.test(username)) return res.status(400).json({ error: "Username can only use letters, digits, dot, dash and underscore" });
  if (!password || password.length > 256) return res.status(400).json({ error: "Password is required" });

  // STEP 2: our own limit per username, below the AD lockout threshold
  const now = Date.now();
  let f = failures.get(username);
  if (!f || f.resetAt < now) f = { count: 0, resetAt: now + FAIL_WINDOW_MS };
  if (f.count >= APP_FAIL_LIMIT) {
    res.set("Retry-After", String(Math.ceil((f.resetAt - now) / 1000)));
    return res.status(429).json({ error: "Too many attempts. Try again in 15 minutes." });
  }
  const fail = (why) => {
    f.count++;
    failures.set(username, f);
    console.log(`🔐 login failed for "${username}": ${why} (the user only sees "Wrong username or password")`);
    return res.status(401).json({ error: "Wrong username or password" });
  };

  // STEP 3: search for the user with the SERVICE account, the filter value escaped
  const found = svc.search(PEOPLE, {
    filter: `(&(objectClass=user)(sAMAccountName=${escapeFilter(username)}))`,
    attributes: ["cn", "objectGUID", "memberOf"],
    sizeLimit: 2, // we need exactly one; asking for 2 tells us if there are more
  });
  // shortcut: "no such user" skips the bind, so it answers a little faster (topic 51). A real app binds a dummy DN too.
  if (found.length !== 1) return fail(found.length ? "more than one match" : "no such user");
  const entry = found[0];

  // STEP 4: bind AS THE USER on a NEW connection. AD checks the password; we never see or store it.
  try {
    connect(LDAP_URL).bind(entry.dn, password);
  } catch (e) {
    if (e.code !== 49) throw e;
    const sub = /data ([0-9a-f]{3})/.exec(e.message)?.[1];
    return fail(`AD said data ${sub} = ${AD_REASONS[sub] ?? "unknown"}`);
  }
  failures.delete(username);

  // STEP 5: AD groups → app roles. Not everyone in the company may use this app.
  const groups = allGroups(entry.memberOf ?? []);
  const roles = Object.entries(GROUP_ROLES).filter(([dn]) => groups.has(dn.toLowerCase())).map(([, role]) => role);
  if (!roles.includes("user")) {
    console.log(`🚫 "${username}" has the right password but is not in Portal-Users`);
    return res.status(403).json({ error: "Your account isn't allowed to use ChaiPortal. Ask IT to add you to Portal-Users." });
  }

  // STEP 6: just-in-time (JIT) provisioning. First login creates the local user, keyed by objectGUID (never changes).
  let id = byGuid.get(entry.objectGUID);
  if (!id) {
    id = crypto.randomUUID();
    byGuid.set(entry.objectGUID, id);
    localUsers.set(id, { id, adGuid: entry.objectGUID, createdAt: new Date().toISOString() });
    console.log(`🆕 JIT: created local user ${id} for ${entry.dn}`);
  }
  Object.assign(localUsers.get(id), { username, name: entry.cn, roles, lastLoginAt: new Date().toISOString() }); // refresh from AD

  // STEP 7: the app's own session. AD is not asked again on every request for the password.
  const sid = crypto.randomBytes(32).toString("base64url");
  sessions.set(sha256(sid), { userId: id, adGuid: entry.objectGUID, expiresAt: now + SESSION_MS });
  // shortcut: no Secure flag because the demo is http://localhost. Production: Secure + https (topic 10).
  res.cookie("sid", sid, { httpOnly: true, sameSite: "lax", path: "/", maxAge: SESSION_MS });
  res.json({ message: `Welcome, ${entry.cn}`, roles });
});

// STEP 8: every request checks the session AND that the AD account is still enabled
function requireSession(req, res, next) {
  const sid = /(?:^|;\s*)sid=([^;]+)/.exec(req.headers.cookie ?? "")?.[1];
  const key = sid && sha256(sid);
  const s = key && sessions.get(key);
  if (!s || s.expiresAt < Date.now()) return res.status(401).json({ error: "Log in first" });
  // shortcut: one directory search per request. A real app caches this for a few minutes, or gets a SCIM push (topic 62).
  const [entry] = svc.search(BASE_DN, { filter: `(objectGUID=${escapeFilter(s.adGuid)})`, attributes: ["userAccountControl"] });
  if (!entry || Number(entry.userAccountControl) & UAC_DISABLED) {
    sessions.delete(key);
    return res.status(401).json({ error: "Your account was disabled or removed. Log in again." });
  }
  req.user = localUsers.get(s.userId);
  next();
}

app.get("/me", requireSession, (req, res) => res.json(req.user));

app.get("/admin", requireSession, (req, res) => {
  if (!req.user.roles.includes("admin")) return res.status(403).json({ error: "Admins only (AD group Portal-Admins)" });
  res.json({ message: "🛠️ Admin panel", localUsers: [...localUsers.values()].map((u) => u.username) });
});

// Escaped, logged in, only the People OU, only public attributes, and a size limit
app.get("/people", requireSession, (req, res) => {
  const q = str(req.query.q) ?? "";
  if (q.length < 2 || q.length > 64) return res.status(400).json({ error: "Search needs 2 to 64 characters" });
  const found = svc.search(PEOPLE, {
    filter: `(&(objectClass=user)(cn=${escapeFilter(q)}*))`, // our own * after the escaped text = "starts with"
    attributes: ["cn", "mail", "title", "department"],
    sizeLimit: 20,
  });
  res.json(found.map(({ cn, mail, title, department }) => ({ name: cn, mail, title, department })));
});

// Demo only: pretend an IT admin clicked "Disable Account" in Active Directory Users and Computers
app.post("/demo/ad/disable/:username", (req, res) => {
  const e = entries.find((x) => sameDn(String(x.attrs.sAMAccountName ?? ""), req.params.username));
  if (!e) return res.status(404).json({ error: "No such AD user" });
  e.attrs.userAccountControl = String(Number(e.attrs.userAccountControl) | UAC_DISABLED);
  res.json({ message: `AD: ${e.dn} is now disabled (userAccountControl=${e.attrs.userAccountControl})` });
});

app.use((req, res) => res.status(404).json({ error: "Not found" }));

// Errors (bad JSON, body too big, directory errors, bugs) come here. Never send the stack trace to the client.
app.use((err, req, res, next) => {
  if (err.type === "entity.parse.failed") return res.status(400).json({ error: "Body must be valid JSON" });
  if (err.type === "entity.too.large") return res.status(413).json({ error: "Request body too large" });
  console.error(err);
  if (err instanceof LdapError) return res.status(502).json({ error: "Directory error" });
  res.status(500).json({ error: "Something went wrong" });
});

app.listen(PORT, () => {
  console.log(`🏢 ChaiPortal on ${BASE_URL}, users come from the (fake) AD domain chaicorp.local`);
});
