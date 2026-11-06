const express = require("express");
const crypto = require("crypto");
const fs = require("fs");

// One file plays THREE machines, so you can follow every message:
//   PART 2: the KDC (in a company: the Active Directory domain controller, port 88)
//   PART 3: the payroll web service (HTTP/payroll.chaiwala.corp)
//   PART 4: the client tools kinit / klist / kvno (what Windows does for you at logon)
// shortcut: real Kerberos speaks binary ASN.1 over TCP/UDP port 88. Here the KDC speaks JSON over HTTP
// (MS-KKDCP, "Kerberos over HTTPS", really exists for remote users). The steps and the checks are the real ones.
const PORT = Number(process.env.PORT) || 3000;
const BASE_URL = `http://localhost:${PORT}`;
const REALM = "CHAIWALA.CORP";
const TGS_NAME = `krbtgt/${REALM}`;          // the Ticket Granting Service's own principal
const PAYROLL_SPN = "HTTP/payroll.chaiwala.corp";
const MAX_SKEW_MS = 5 * 60 * 1000;           // clocks may differ by 5 minutes, no more (the Kerberos default)
const TICKET_LIFETIME_MS = 10 * 60 * 60 * 1000; // 10 h, a working day (the Windows default)

// =====================================================================================
// PART 1: crypto shared by everyone
// =====================================================================================
const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");
const b64 = (buf) => buf.toString("base64url");
const unb64 = (s) => Buffer.from(s, "base64url");
const str = (v) => (typeof v === "string" && v.length <= 8000 ? v : undefined);

// STEP 1: a password becomes a KEY. The salt is realm + name, so two users with the same password get different keys.
// shortcut: AES Kerberos (RFC 3962) uses PBKDF2-HMAC-SHA1 with 4096 rounds plus one more derive step. Same idea.
const stringToKey = (password, principal) => crypto.pbkdf2Sync(password, REALM + principal, 4096, 32, "sha256");

// Kerberos "key usage" numbers (RFC 4120 §7.5.1). They are mixed into every encryption, so a blob made for one
// purpose (say, the AS-REP) can never be cut out and pasted in as another (say, an authenticator).
const USAGE = { PA_TIMESTAMP: 1, TICKET: 2, AS_REP: 3, TGS_AUTHENTICATOR: 7, TGS_REP: 8, AP_AUTHENTICATOR: 11, AP_REP: 12 };

// shortcut: AES-256-GCM instead of Kerberos' AES-CTS + HMAC-SHA1-96. Both encrypt AND detect tampering.
function seal(key, usage, obj) {
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv("aes-256-gcm", key, iv);
  c.setAAD(Buffer.from(`usage:${usage}`));
  const ct = Buffer.concat([c.update(JSON.stringify(obj)), c.final()]);
  return b64(Buffer.concat([iv, c.getAuthTag(), ct]));
}

// Returns null for a wrong key, a wrong usage or a single flipped bit. Never throws.
function unseal(key, usage, blob) {
  try {
    const buf = unb64(blob);
    const d = crypto.createDecipheriv("aes-256-gcm", key, buf.subarray(0, 12));
    d.setAAD(Buffer.from(`usage:${usage}`));
    d.setAuthTag(buf.subarray(12, 28));
    return JSON.parse(Buffer.concat([d.update(buf.subarray(28)), d.final()]).toString("utf8"));
  } catch {
    return null;
  }
}

// =====================================================================================
// PART 2: the KDC (Key Distribution Center) = AS (Authentication Service) + TGS (Ticket Granting Service)
// =====================================================================================
// shortcut: in-memory Map. In Active Directory this is the domain database (ntds.dit) on every domain controller.
const principals = new Map(); // name -> { key, groups? }   The KDC knows EVERY key in the realm.
const addUser = (name, password, groups) => principals.set(name, { key: stringToKey(password, name), groups });
addUser("rahul", "chai-and-code-42", ["Employees"]);
addUser("priya", "priya-hr-2026!", ["Employees", "HR"]);
// krbtgt: a random key. Whoever steals it can forge a TGT for anyone ("golden ticket"). Rotate it twice after a breach.
principals.set(TGS_NAME, { key: crypto.randomBytes(32) });
// ✅ A service with a RANDOM key (a keytab / gMSA). Kerberoasting it is hopeless.
principals.set(PAYROLL_SPN, { key: crypto.randomBytes(32) });
// ❌ A service whose key comes from a human-chosen password (an old SQL Server service account). Kerberoastable.
principals.set("MSSQLSvc/db.chaiwala.corp", { key: stringToKey("Chai@2024", "MSSQLSvc/db.chaiwala.corp") });

// Replay caches: an authenticator is accepted once. It only has to be remembered for the skew window,
// because an older one fails the time check anyway.
const kdcReplayCache = new Map();     // sha256(blob) -> forget after (ms)
const payrollReplayCache = new Map();

const isFresh = (ms) => typeof ms === "number" && Math.abs(Date.now() - ms) <= MAX_SKEW_MS;
function seenBefore(cache, blob) {
  const k = sha256(blob);
  if (cache.has(k)) return true;
  cache.set(k, Date.now() + 2 * MAX_SKEW_MS);
  return false;
}

const krbError = (res, code, message) => res.status(401).json({ error: code, message });

// Checks an authenticator against the ticket it came with. Shared by the TGS and by every service.
// The ticket proves "the KDC says this session key belongs to rahul". The authenticator proves "I HAVE that key, right now".
function checkAuthenticator(ticket, usage, blob, cache) {
  const a = blob && unseal(unb64(ticket.sessionKey), usage, blob);
  if (!a) return { err: ["KRB_AP_ERR_MODIFIED", "Authenticator doesn't decrypt with the ticket's session key"] };
  if (a.cname !== ticket.cname) return { err: ["KRB_AP_ERR_BADMATCH", "Authenticator and ticket name different users"] };
  if (!isFresh(a.ctime)) return { err: ["KRB_AP_ERR_SKEW", "Clock skew too great (more than 5 minutes)"] };
  if (seenBefore(cache, blob)) return { err: ["KRB_AP_ERR_REPEAT", "This authenticator was already used (replay)"] };
  return { a };
}

const app = express();
app.use(express.json({ limit: "10kb" }));
app.use((req, res, next) => {
  res.set("Cache-Control", "no-store"); // tickets and session keys must never sit in a cache
  next();
});

// STEP 2: AS-REQ → AS-REP. "I'm rahul" + proof of the password → a TGT (Ticket Granting Ticket).
// The password never travels. Only the current time, encrypted with the password's key (pre-authentication).
app.post("/kdc/as", (req, res) => {
  const cname = str(req.body?.cname)?.trim().toLowerCase();
  const nonce = str(req.body?.nonce);
  const padata = str(req.body?.padata);
  if (!cname || !nonce || nonce.length > 64) return res.status(400).json({ error: "cname and nonce are required" });

  const user = !cname.includes("/") && principals.get(cname);
  // Real KDCs answer like this, which tells an attacker which usernames exist (tools like kerbrute rely on it).
  if (!user) return krbError(res, "KDC_ERR_C_PRINCIPAL_UNKNOWN", `No user ${cname}@${REALM}`);
  // ✅ Pre-auth required. Without it, ANYONE could ask for rahul's AS-REP and crack it offline ("AS-REP roasting").
  if (!padata) return krbError(res, "KDC_ERR_PREAUTH_REQUIRED", "Send PA-ENC-TIMESTAMP: the current time encrypted with your password's key");
  const pa = unseal(user.key, USAGE.PA_TIMESTAMP, padata);
  if (!pa) {
    // shortcut: AD also counts these failures towards account lockout (topic 52)
    console.log(`🚫 KDC  AS-REQ: ${cname} pre-auth failed (wrong password)`);
    return krbError(res, "KDC_ERR_PREAUTH_FAILED", "Pre-authentication failed (wrong password)");
  }
  if (!isFresh(pa.ts)) return krbError(res, "KRB_AP_ERR_SKEW", "Clock skew too great (more than 5 minutes)");
  if (seenBefore(kdcReplayCache, padata)) return krbError(res, "KRB_AP_ERR_REPEAT", "This pre-auth timestamp was already used");

  const sessionKey = b64(crypto.randomBytes(32)); // rahul ↔ TGS, fresh for this logon
  const authtime = Date.now();
  const endtime = authtime + TICKET_LIFETIME_MS;
  // The TGT is locked with the krbtgt key: rahul carries it but can't read or change it.
  // `groups` plays the PAC (Privilege Attribute Certificate): AD puts the user's group SIDs here.
  const ticket = seal(principals.get(TGS_NAME).key, USAGE.TICKET, { cname, crealm: REALM, sname: TGS_NAME, sessionKey, authtime, endtime, groups: user.groups });
  // The session key for rahul, locked with HIS key: only the real rahul can open it.
  const encPart = seal(user.key, USAGE.AS_REP, { sessionKey, nonce, sname: TGS_NAME, authtime, endtime });
  console.log(`🎫 KDC  AS-REQ: ${cname} pre-auth OK → TGT until ${new Date(endtime).toISOString()}`);
  res.json({ cname, crealm: REALM, ticket, encPart });
});

// STEP 3: TGS-REQ → TGS-REP. TGT + authenticator + "I want HTTP/payroll" → a service ticket. No password needed.
app.post("/kdc/tgs", (req, res) => {
  const tgtBlob = str(req.body?.ticket);
  const authBlob = str(req.body?.authenticator);
  const sname = str(req.body?.sname);
  const nonce = str(req.body?.nonce);
  if (!tgtBlob || !authBlob || !sname || !nonce || nonce.length > 64) return res.status(400).json({ error: "ticket, authenticator, sname and nonce are required" });

  const tgt = unseal(principals.get(TGS_NAME).key, USAGE.TICKET, tgtBlob);
  if (!tgt || tgt.sname !== TGS_NAME) return krbError(res, "KRB_AP_ERR_MODIFIED", "Not a TGT from this KDC (or tampered)");
  if (Date.now() > tgt.endtime) return krbError(res, "KRB_AP_ERR_TKT_EXPIRED", "TGT expired: run kinit again");
  const { err } = checkAuthenticator(tgt, USAGE.TGS_AUTHENTICATOR, authBlob, kdcReplayCache);
  if (err) return krbError(res, ...err);

  const service = sname.includes("/") && principals.get(sname);
  if (!service) return krbError(res, "KDC_ERR_S_PRINCIPAL_UNKNOWN", `No service ${sname}`);
  // ⚠️ The KDC does NOT ask "may rahul use this service?". ANY user gets a ticket for ANY service.
  // Authorization is the service's job (it reads the groups). That's also why Kerberoasting works.

  const tgtSessionKey = unb64(tgt.sessionKey);
  const sessionKey = b64(crypto.randomBytes(32)); // rahul ↔ payroll
  const endtime = tgt.endtime;                     // a service ticket never outlives the TGT
  const ticket = seal(service.key, USAGE.TICKET, { cname: tgt.cname, crealm: REALM, sname, sessionKey, authtime: tgt.authtime, endtime, groups: tgt.groups });
  const encPart = seal(tgtSessionKey, USAGE.TGS_REP, { sessionKey, nonce, sname, endtime });
  console.log(`🎟️  KDC  TGS-REQ: ${tgt.cname} → service ticket for ${sname}`);
  res.json({ cname: tgt.cname, ticket, encPart });
});

// =====================================================================================
// PART 3: the payroll service. It knows ONE key: its own (from its keytab). It never talks to the KDC.
// =====================================================================================
// shortcut: same process, so we read the key from the Map. In real life the admin exports it once into a keytab
// file (ktpass / msktutil) on the payroll server, readable only by the service.
const PAYROLL_KEYTAB = principals.get(PAYROLL_SPN).key;
const SALARIES = { rahul: "₹18,00,000", priya: "₹21,00,000" };

// STEP 4: AP-REQ. Browsers send it as `Authorization: Negotiate <token>` (SPNEGO, RFC 4559).
// shortcut: a real SPNEGO token is base64 of binary ASN.1. Ours is base64url of { ticket, authenticator }.
function requireKerberos(req, res, next) {
  const m = /^Negotiate ([\w-]{1,8000})$/.exec(req.get("authorization") ?? "");
  if (!m) return res.set("WWW-Authenticate", "Negotiate").status(401).json({ error: "Kerberos ticket required (Authorization: Negotiate …)" });
  let ap = null;
  try { ap = JSON.parse(unb64(m[1]).toString("utf8")); } catch { /* handled below */ }

  // Only the payroll key opens a payroll ticket. A ticket for another service, or one with a flipped bit, fails here.
  const ticket = str(ap?.ticket) && unseal(PAYROLL_KEYTAB, USAGE.TICKET, ap.ticket);
  if (!ticket || ticket.sname !== PAYROLL_SPN) return krbError(res, "KRB_AP_ERR_MODIFIED", "Ticket isn't for this service, or was tampered with");
  if (Date.now() > ticket.endtime) return krbError(res, "KRB_AP_ERR_TKT_EXPIRED", "Ticket expired");
  const { a, err } = checkAuthenticator(ticket, USAGE.AP_AUTHENTICATOR, str(ap.authenticator), payrollReplayCache);
  if (err) return krbError(res, ...err);

  // STEP 5: mutual authentication. Only the real payroll server could open the ticket and learn the session key,
  // so echoing the client's time back, sealed with that key, proves the SERVER is genuine too.
  res.set("WWW-Authenticate", `Negotiate ${seal(unb64(ticket.sessionKey), USAGE.AP_REP, { ctime: a.ctime })}`);
  req.krb = ticket;
  console.log(`🔐 PAYROLL: ${ticket.cname}@${ticket.crealm} verified with the keytab alone (no call to the KDC)`);
  next();
}

app.get("/payroll/me", requireKerberos, (req, res) => {
  // Kerberos said WHO. Deciding WHAT they may see is ours (authorization), here from the PAC groups.
  res.json({ service: PAYROLL_SPN, user: `${req.krb.cname}@${req.krb.crealm}`, groups: req.krb.groups, salary: SALARIES[req.krb.cname] ?? null });
});

app.get("/payroll/all", requireKerberos, (req, res) => {
  if (!req.krb.groups?.includes("HR")) return res.status(403).json({ error: "Only the HR group can see everyone's salary" });
  res.json({ salaries: SALARIES });
});

app.use((req, res) => res.status(404).json({ error: "Not found" }));

// Errors (bad JSON, body too big, bugs) come here. Never send the stack trace to the client.
app.use((err, req, res, next) => {
  if (err.type === "entity.parse.failed") return res.status(400).json({ error: "Body must be valid JSON" });
  if (err.type === "entity.too.large") return res.status(413).json({ error: "Request body too large" });
  console.error(err);
  res.status(500).json({ error: "Something went wrong" });
});

// =====================================================================================
// PART 4: the client tools, like MIT Kerberos' kinit / klist / kvno. Run them in a second terminal:
//   node server.js kinit rahul.ccache rahul <password>     log in, get a TGT
//   node server.js klist rahul.ccache                      show the tickets
//   node server.js kvno  rahul.ccache <service>            get a service ticket
//   node server.js ap-req rahul.ccache <service> [minutes] print an AP-REQ for curl (minutes = fake clock offset)
//   node server.js roast rahul.ccache <service>            Kerberoasting: crack the service ticket offline
// The .ccache file is the ticket cache (/tmp/krb5cc_1000 on Linux, LSA memory on Windows). It holds the
// tickets AND their session keys, but never the password. Anyone who copies it can use them ("pass-the-ticket").
// =====================================================================================
const readCache = (file) => JSON.parse(fs.readFileSync(file, "utf8"));
const writeCache = (file, cache) => fs.writeFileSync(file, JSON.stringify(cache, null, 2), { mode: 0o600 });
const nonce = () => b64(crypto.randomBytes(12));

async function callKdc(path, body) {
  const r = await fetch(BASE_URL + path, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
  const json = await r.json();
  if (!r.ok) throw new Error(`${json.error}: ${json.message ?? ""}`);
  return json;
}

async function kinit(file, cname, password) {
  if (!file || !cname || !password) throw new Error("usage: kinit <ccache> <user> <password>");
  const key = stringToKey(password, cname); // the password is turned into a key and then forgotten
  const n = nonce();
  const rep = await callKdc("/kdc/as", { cname, nonce: n, padata: seal(key, USAGE.PA_TIMESTAMP, { ts: Date.now() }) });
  const enc = unseal(key, USAGE.AS_REP, rep.encPart);
  // The nonce must come back: proves this AS-REP answers OUR request, not an old one replayed by someone.
  if (!enc || enc.nonce !== n) throw new Error("AS-REP doesn't open with my key or has the wrong nonce: is this my KDC?");
  writeCache(file, { principal: `${rep.cname}@${rep.crealm}`, cname: rep.cname, tickets: { [TGS_NAME]: { ticket: rep.ticket, sessionKey: enc.sessionKey, endtime: enc.endtime } } });
  console.log(`✅ TGT for ${rep.cname}@${rep.crealm} saved in ${file}`);
}

function klist(file) {
  const c = readCache(file);
  console.log(`Ticket cache: ${file}\nDefault principal: ${c.principal}\n\nValid until               Service principal`);
  for (const [sname, t] of Object.entries(c.tickets)) console.log(`${new Date(t.endtime).toISOString()}  ${sname}@${REALM}`);
}

// TGS exchange. Uses the cached ticket while it's valid, like the real client library.
async function getServiceTicket(file, sname) {
  const c = readCache(file);
  if (c.tickets[sname]?.endtime > Date.now()) return { c, t: c.tickets[sname] };
  const tgt = c.tickets[TGS_NAME];
  if (!tgt) throw new Error("No TGT in the cache: run kinit first");
  const tgtKey = unb64(tgt.sessionKey);
  const n = nonce();
  const rep = await callKdc("/kdc/tgs", { ticket: tgt.ticket, sname, nonce: n, authenticator: seal(tgtKey, USAGE.TGS_AUTHENTICATOR, { cname: c.cname, ctime: Date.now() }) });
  const enc = unseal(tgtKey, USAGE.TGS_REP, rep.encPart);
  if (!enc || enc.nonce !== n) throw new Error("TGS-REP doesn't open with my TGT session key or has the wrong nonce");
  c.tickets[sname] = { ticket: rep.ticket, sessionKey: enc.sessionKey, endtime: enc.endtime };
  writeCache(file, c);
  return { c, t: c.tickets[sname] };
}

async function kvno(file, sname) {
  if (!file || !sname) throw new Error("usage: kvno <ccache> <service>");
  await getServiceTicket(file, sname);
  console.log(`✅ service ticket for ${sname}@${REALM} saved in ${file}`);
}

async function apReq(file, sname, offsetMinutes = "0") {
  if (!file || !sname) throw new Error("usage: ap-req <ccache> <service> [minutes]");
  const { c, t } = await getServiceTicket(file, sname);
  const ctime = Date.now() + Number(offsetMinutes) * 60 * 1000; // a wrong clock, to see KRB_AP_ERR_SKEW
  const authenticator = seal(unb64(t.sessionKey), USAGE.AP_AUTHENTICATOR, { cname: c.cname, ctime });
  process.stdout.write(b64(Buffer.from(JSON.stringify({ ticket: t.ticket, authenticator }))));
}

// ATTACK: Kerberoasting. Any logged-in user may get a ticket for any service, and that ticket is encrypted
// with the service's key. If the key comes from a password, guess passwords OFFLINE until one opens the ticket.
// shortcut: a 6-word list. Attackers use hashcat (mode 13100 / 19700) with billions of guesses.
async function roast(file, sname) {
  if (!file || !sname) throw new Error("usage: roast <ccache> <service>");
  const { t } = await getServiceTicket(file, sname);
  const WORDLIST = ["password", "Welcome@123", "Summer2024!", "chaiwala", "Chai@2024", "P@ssw0rd"];
  for (const guess of WORDLIST) {
    const opened = unseal(stringToKey(guess, sname), USAGE.TICKET, t.ticket);
    if (opened) {
      console.log(`💥 Cracked ${sname}: its password is "${guess}"`);
      console.log(`   Inside the ticket: ${JSON.stringify({ cname: opened.cname, groups: opened.groups })}`);
      console.log(`   With this key I can forge tickets for this service as ANY user ("silver ticket").`);
      return;
    }
  }
  console.log(`🛡️  ${WORDLIST.length} guesses, none opened the ticket for ${sname}: its key is random, not a password`);
}

// =====================================================================================
// Start: a tool name runs the client, nothing runs the servers
// =====================================================================================
const TOOLS = { kinit, klist, kvno, "ap-req": apReq, roast };
const [tool, ...args] = process.argv.slice(2);
if (tool) {
  if (!TOOLS[tool]) {
    console.error(`❌ Unknown tool "${tool}". Use one of: ${Object.keys(TOOLS).join(", ")}`);
    process.exit(1);
  }
  Promise.resolve()
    .then(() => TOOLS[tool](...args))
    .catch((e) => {
      console.error(`❌ ${e.code === "ENOENT" ? `No ticket cache ${e.path}: run kinit first` : e.message}`);
      process.exit(1);
    });
} else {
  // Express 5 passes a listen error (like "port already in use") to this callback instead of crashing
  app.listen(PORT, (err) => {
    if (err) throw err;
    console.log(`🏢 Realm ${REALM}: KDC at ${BASE_URL}/kdc, payroll service at ${BASE_URL}/payroll`);
  });

  // Forget replay-cache entries once the skew window has passed (an older authenticator fails the time check anyway)
  setInterval(() => {
    const now = Date.now();
    for (const cache of [kdcReplayCache, payrollReplayCache]) for (const [k, until] of cache) if (until < now) cache.delete(k);
  }, 60_000).unref();
}
