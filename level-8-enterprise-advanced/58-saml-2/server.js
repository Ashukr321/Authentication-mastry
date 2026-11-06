const express = require("express");
const crypto = require("crypto");
const zlib = require("zlib");
const { SignedXml } = require("xml-crypto");             // XML signatures (used by node-saml / passport-saml)
const { DOMParser, onErrorStopParsing } = require("@xmldom/xmldom");

const PORT = Number(process.env.PORT) || 3000;
const BASE_URL = `http://localhost:${PORT}`;

// One process plays BOTH sides so you can run the demo with one command:
//   /idp/*  = "ChaiCorp ID", the company's Identity Provider (think Okta, Azure AD / Entra ID, Keycloak)
//   /sp/*   = "PaisaTrack", an expense app, the Service Provider
// In real life they are different companies on different domains. They only share METADATA (step 1).
const IDP_ENTITY_ID = `${BASE_URL}/idp/metadata`;
const SP_ENTITY_ID = `${BASE_URL}/sp/metadata`;
const SP_ACS_URL = `${BASE_URL}/sp/acs`;

const NS = {
  samlp: "urn:oasis:names:tc:SAML:2.0:protocol",
  saml: "urn:oasis:names:tc:SAML:2.0:assertion",
  md: "urn:oasis:names:tc:SAML:2.0:metadata",
  ds: "http://www.w3.org/2000/09/xmldsig#",
};
const SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success";
const EXC_C14N = "http://www.w3.org/2001/10/xml-exc-c14n#";
const ASSERTION_LIFETIME_MS = 5 * 60 * 1000; // an assertion is a one-shot ticket: minutes, not hours
const CLOCK_SKEW_MS = 2 * 60 * 1000;         // IdP and SP clocks are never exactly in sync
const IDP_SESSION_MS = 8 * 60 * 60 * 1000;   // the IdP login lasts a work day: that's what makes SSO "single"

// ---------- Helpers ----------
const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");
const randomToken = () => crypto.randomBytes(32).toString("base64url");
const samlId = () => "_" + crypto.randomBytes(16).toString("hex"); // XML IDs must not start with a digit
const iso = (ms) => new Date(ms).toISOString().replace(/\.\d{3}Z$/, "Z");
const str = (v) => (typeof v === "string" ? v : undefined);
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
const parseCookies = (req) => Object.fromEntries((req.headers.cookie ?? "").split(";").filter((c) => c.includes("="))
  .map((c) => [c.slice(0, c.indexOf("=")).trim(), c.slice(c.indexOf("=") + 1).trim()]));

class SamlError extends Error {}

// Untrusted XML from the network: refuse DOCTYPE/ENTITY outright (XXE, "billion laughs"), stop on any parse error
function parseXml(xml) {
  if (/<!DOCTYPE|<!ENTITY/i.test(xml)) throw new SamlError("DOCTYPE / ENTITY is not allowed");
  try {
    return new DOMParser({ onError: onErrorStopParsing }).parseFromString(xml, "text/xml");
  } catch {
    throw new SamlError("Malformed XML");
  }
}
const children = (el, ns, name) => Array.from(el.childNodes).filter((n) => n.nodeType === 1 && n.namespaceURI === ns && n.localName === name);
const child = (el, ns, name) => children(el, ns, name)[0];

// =====================================================================================
//  IDENTITY PROVIDER: "ChaiCorp ID"
// =====================================================================================

// The IdP's signing key. The PRIVATE key never leaves the IdP; the PUBLIC key goes into its metadata.
// shortcut: a fresh key on every start, in memory. A real IdP keeps it in a KMS/HSM and rotates it with overlap (topic 54).
const IDP_KEYS = crypto.generateKeyPairSync("rsa", {
  modulusLength: 2048,
  publicKeyEncoding: { type: "spki", format: "pem" },
  privateKeyEncoding: { type: "pkcs8", format: "pem" },
});

// shortcut: in-memory Maps, lost on restart. A real IdP uses its user directory (LDAP / AD, topic 63) and tables.
const idpUsers = new Map();    // email -> { email, name, groups, salt, passwordHash }
const idpSessions = new Map(); // sha256(sid) -> { email, authnInstant, sessionIndex }
const DUMMY_SALT = crypto.randomBytes(16);
for (const [email, name, groups, password] of [
  ["rahul@chaicorp.com", "Rahul Sharma", ["finance", "employees"], "chai-and-code-42"],
  ["vikram@chaicorp.com", "Vikram Singh", ["engineering", "employees"], "vikram-pass-99"],
]) {
  const salt = crypto.randomBytes(16);
  idpUsers.set(email, { email, name, groups, salt, passwordHash: crypto.scryptSync(password, salt, 64) });
}

function checkPassword(email, password) {
  const user = email ? idpUsers.get(email) : undefined;
  const hash = crypto.scryptSync(password ?? "", user?.salt ?? DUMMY_SALT, 64); // same work for unknown emails (topic 51)
  return user && crypto.timingSafeEqual(hash, user.passwordHash) ? user : null;
}

// STEP 1 (IdP side): the apps the admin has connected. Each SP's entityID and ACS URL come from ITS metadata.
// The IdP only ever sends assertions to the ACS URL registered here, never to one written in the request.
const registeredSps = new Map([
  [SP_ENTITY_ID, { name: "PaisaTrack", acsUrl: SP_ACS_URL }],
  ["hr-portal.chaicorp.example", { name: "HR Portal", acsUrl: "https://hr-portal.chaicorp.example/saml/acs" }],
]);

function getIdpSession(req) {
  const sid = parseCookies(req).idp_sid;
  const s = sid && idpSessions.get(sha256(sid));
  if (!s) return null;
  if (Date.now() - s.authnInstant > IDP_SESSION_MS) { idpSessions.delete(sha256(sid)); return null; }
  return s;
}

// STEP 3 (IdP side): read the AuthnRequest that arrived in the URL (HTTP-Redirect binding = deflate + base64 + URL-encode)
function readAuthnRequest(samlRequest) {
  if (!samlRequest || samlRequest.length > 10_000) throw new SamlError("Missing or oversized SAMLRequest");
  let xml;
  try {
    xml = zlib.inflateRawSync(Buffer.from(samlRequest, "base64"), { maxOutputLength: 20_000 }).toString("utf8");
  } catch {
    throw new SamlError("SAMLRequest is not valid deflate + base64");
  }
  const req = parseXml(xml).documentElement;
  if (req?.namespaceURI !== NS.samlp || req.localName !== "AuthnRequest") throw new SamlError("Not an AuthnRequest");
  const issuer = child(req, NS.saml, "Issuer")?.textContent.trim();
  const sp = issuer && registeredSps.get(issuer);
  if (!sp) throw new SamlError("Unknown service provider");
  const acs = req.getAttribute("AssertionConsumerServiceURL");
  // ❌ Never post an assertion to an ACS URL just because the request asked for it: that hands Rahul's login to the attacker
  if (acs && acs !== sp.acsUrl) throw new SamlError("AssertionConsumerServiceURL is not registered for this SP");
  const id = req.getAttribute("ID");
  if (!/^[A-Za-z_][\w.-]{0,99}$/.test(id)) throw new SamlError("Bad AuthnRequest ID");
  return { id, spEntityId: issuer, sp };
}

// STEP 4 (IdP side): build the SAML Response with ONE assertion about the user, then sign the assertion
function buildSignedResponse({ spEntityId, sp, user, session, inResponseTo }) {
  const now = Date.now();
  const expires = iso(now + ASSERTION_LIFETIME_MS);
  const irt = inResponseTo ? ` InResponseTo="${esc(inResponseTo)}"` : ""; // missing = IdP-initiated ("unsolicited")
  const attr = (name, values) =>
    `      <saml:Attribute Name="${name}">${values.map((v) => `<saml:AttributeValue>${esc(v)}</saml:AttributeValue>`).join("")}</saml:Attribute>`;

  const xml = `<samlp:Response xmlns:samlp="${NS.samlp}" xmlns:saml="${NS.saml}" ID="${samlId()}" Version="2.0" IssueInstant="${iso(now)}" Destination="${esc(sp.acsUrl)}"${irt}>
  <saml:Issuer>${esc(IDP_ENTITY_ID)}</saml:Issuer>
  <samlp:Status><samlp:StatusCode Value="${SUCCESS}"/></samlp:Status>
  <saml:Assertion ID="${samlId()}" Version="2.0" IssueInstant="${iso(now)}">
    <saml:Issuer>${esc(IDP_ENTITY_ID)}</saml:Issuer>
    <saml:Subject>
      <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">${esc(user.email)}</saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData Recipient="${esc(sp.acsUrl)}" NotOnOrAfter="${expires}"${irt}/>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="${iso(now)}" NotOnOrAfter="${expires}">
      <saml:AudienceRestriction><saml:Audience>${esc(spEntityId)}</saml:Audience></saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AuthnStatement AuthnInstant="${iso(session.authnInstant)}" SessionIndex="${session.sessionIndex}">
      <saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext>
    </saml:AuthnStatement>
    <saml:AttributeStatement>
${attr("email", [user.email])}
${attr("displayName", [user.name])}
${attr("groups", user.groups)}
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>`;

  // Enveloped XML signature over the <Assertion>: RSA-SHA256, exclusive canonicalization (so whitespace and
  // namespace placement are normalized before hashing). The <ds:Signature> goes right after the assertion's <Issuer>.
  const sig = new SignedXml({
    privateKey: IDP_KEYS.privateKey,
    signatureAlgorithm: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
    canonicalizationAlgorithm: EXC_C14N,
  });
  sig.addReference({
    xpath: "//*[local-name(.)='Assertion']",
    digestAlgorithm: "http://www.w3.org/2001/04/xmlenc#sha256",
    transforms: ["http://www.w3.org/2000/09/xmldsig#enveloped-signature", EXC_C14N],
  });
  sig.computeSignature(xml, { prefix: "ds", location: { reference: "//*[local-name(.)='Assertion']/*[local-name(.)='Issuer']", action: "after" } });
  return sig.getSignedXml();
}

// HTTP-POST binding: the browser carries the response to the SP in a self-submitting form
function postForm(acsUrl, samlResponseXml, relayState) {
  const b64 = Buffer.from(samlResponseXml).toString("base64");
  return `<!doctype html><html><body onload="document.forms[0].submit()">
<form method="post" action="${esc(acsUrl)}">
<input type="hidden" name="SAMLResponse" value="${esc(b64)}">
${relayState ? `<input type="hidden" name="RelayState" value="${esc(relayState)}">` : ""}
<noscript><button>Continue to the app</button></noscript>
</form></body></html>`;
}

// =====================================================================================
//  SERVICE PROVIDER: "PaisaTrack"
// =====================================================================================

// STEP 1 (SP side): what the SP knows about the IdP, copied from the IdP's metadata ONCE when the admin sets up SSO.
// ✅ The signing key comes from HERE, never from the <KeyInfo> inside an incoming response (the attacker writes that).
const TRUSTED_IDP = { entityId: IDP_ENTITY_ID, ssoUrl: `${BASE_URL}/idp/sso`, signingKey: IDP_KEYS.publicKey };

// shortcut: in-memory Maps, lost on restart. A real SP uses tables (or Redis) and shares them across instances.
const pendingRequests = new Map(); // AuthnRequest ID -> expiresAt  (for the InResponseTo check)
const usedAssertions = new Map();  // Assertion ID -> expiresAt     (replay cache)
const relayStates = new Map();     // opaque RelayState key -> { returnTo, expiresAt }
const spSessions = new Map();      // sha256(sid) -> { email, name, groups, sessionIndex, createdAt }
const SP_COOKIE = { httpOnly: true, sameSite: "lax", path: "/sp" }; // shortcut: add `secure: true` in production (HTTPS)

// Only our own paths, so a login link can't bounce Rahul to evil.example afterwards (open redirect)
const safeReturnTo = (v) => (/^\/sp\/[\w/-]{0,60}$/.test(v ?? "") ? v : "/sp/me");

// STEP 5 (SP side): every check an ACS must do. Any failure = no login.
function validateSamlResponse(b64) {
  if (!b64 || b64.length > 40_000) throw new SamlError("Missing or oversized SAMLResponse");
  const xml = Buffer.from(b64, "base64").toString("utf8");
  const doc = parseXml(xml);
  const res = doc.documentElement;
  if (res?.namespaceURI !== NS.samlp || res.localName !== "Response") throw new SamlError("Not a SAML Response");

  // a) The IdP said "Success"? (Unsigned, but we only use it to REJECT, so that's fine.)
  const status = child(child(res, NS.samlp, "Status") ?? res, NS.samlp, "StatusCode")?.getAttribute("Value");
  if (status !== SUCCESS) throw new SamlError(`IdP returned status ${status ?? "missing"}`);

  // b) Exactly one assertion, and it carries a signature. Extra assertions are how wrapping attacks hide (topic 59).
  const assertions = doc.getElementsByTagNameNS(NS.saml, "Assertion");
  if (assertions.length !== 1) throw new SamlError("Expected exactly one Assertion");
  const sigNode = child(assertions[0], NS.ds, "Signature");
  if (!sigNode) throw new SamlError("Assertion is not signed");

  // c) Verify the signature with the IdP key from our config, then read values ONLY from what was signed.
  //    getSignedReferences() returns the canonical XML that the signature actually covers. Reading the
  //    original document instead is exactly the bug that XML Signature Wrapping exploits (topic 59).
  const sig = new SignedXml({ publicCert: TRUSTED_IDP.signingKey });
  let valid = false;
  try {
    sig.loadSignature(sigNode);
    valid = sig.checkSignature(xml);
  } catch {
    valid = false; // a wrong SignatureValue throws; treat every crypto error as "invalid"
  }
  const signed = valid ? sig.getSignedReferences() : [];
  if (signed.length !== 1) throw new SamlError("Invalid signature");
  const a = parseXml(signed[0]).documentElement;
  if (a.namespaceURI !== NS.saml || a.localName !== "Assertion") throw new SamlError("Signature does not cover an Assertion");

  // d) Issued by the IdP we trust
  if (child(a, NS.saml, "Issuer")?.textContent.trim() !== TRUSTED_IDP.entityId) throw new SamlError("Wrong Issuer");

  // e) Issued FOR us. An assertion for the HR portal must not log you into PaisaTrack.
  const conditions = child(a, NS.saml, "Conditions");
  const audiences = conditions ? children(conditions, NS.saml, "AudienceRestriction").flatMap((r) => children(r, NS.saml, "Audience")) : [];
  if (!audiences.some((el) => el.textContent.trim() === SP_ENTITY_ID)) throw new SamlError("Audience is not this SP");

  // f) Bearer confirmation: meant to be delivered to OUR ACS URL
  const subject = child(a, NS.saml, "Subject");
  const conf = subject && children(subject, NS.saml, "SubjectConfirmation").find((c) => c.getAttribute("Method") === "urn:oasis:names:tc:SAML:2.0:cm:bearer");
  const data = conf && child(conf, NS.saml, "SubjectConfirmationData");
  if (!data || data.getAttribute("Recipient") !== SP_ACS_URL) throw new SamlError("Recipient is not this ACS");

  // g) Still valid (with a little clock skew)
  const now = Date.now();
  const notBefore = Date.parse(conditions.getAttribute("NotBefore"));
  const notOnOrAfter = Math.min(Date.parse(conditions.getAttribute("NotOnOrAfter")), Date.parse(data.getAttribute("NotOnOrAfter")));
  if (!(now + CLOCK_SKEW_MS >= notBefore && now - CLOCK_SKEW_MS < notOnOrAfter)) throw new SamlError("Assertion expired or not yet valid");

  // h) Not seen before. A bearer assertion is like cash: whoever holds it can spend it, so spend it once.
  const assertionId = a.getAttribute("ID");
  if (!assertionId || usedAssertions.has(assertionId)) throw new SamlError("Assertion already used (replay)");

  // i) An answer to a request WE sent (SP-initiated). No InResponseTo = IdP-initiated ("unsolicited"):
  //    we refuse those, because we can't tell an IdP tile click from an assertion someone injected (topic 47 login CSRF).
  const inResponseTo = data.getAttribute("InResponseTo");
  if (!inResponseTo) throw new SamlError("Unsolicited response (IdP-initiated SSO is disabled)");
  const pending = pendingRequests.get(inResponseTo);
  if (!pending || pending < now) throw new SamlError("InResponseTo does not match a pending request");

  // All good: burn the request and the assertion so neither works twice
  pendingRequests.delete(inResponseTo);
  usedAssertions.set(assertionId, notOnOrAfter + CLOCK_SKEW_MS);

  const attrs = {};
  for (const st of children(a, NS.saml, "AttributeStatement")) {
    for (const at of children(st, NS.saml, "Attribute")) {
      attrs[at.getAttribute("Name")] = children(at, NS.saml, "AttributeValue").map((v) => v.textContent);
    }
  }
  return {
    email: child(subject, NS.saml, "NameID")?.textContent.trim(),
    name: attrs.displayName?.[0] ?? null,
    groups: attrs.groups ?? [],
    sessionIndex: child(a, NS.saml, "AuthnStatement")?.getAttribute("SessionIndex") ?? null, // needed for Single Logout (topic 61)
  };
}

// =====================================================================================
//  App
// =====================================================================================
const app = express();
app.use(express.json({ limit: "10kb" }));
app.use(express.urlencoded({ extended: false, limit: "50kb" })); // a signed SAMLResponse is a few KB of base64
app.use((req, res, next) => {
  res.set("Cache-Control", "no-store"); // login pages and assertions must never sit in a cache
  next();
});

// ---------- STEP 1: metadata (exchanged once, by the admins) ----------
app.get("/idp/metadata", (req, res) => {
  const jwk = crypto.createPublicKey(IDP_KEYS.publicKey).export({ format: "jwk" });
  const b64 = (v) => Buffer.from(v, "base64url").toString("base64");
  // shortcut: real metadata carries an X.509 certificate (<ds:X509Data>), usually self-signed with `openssl req -x509`.
  // Node can't create certificates without a library, so we publish the raw RSA public key (<ds:KeyValue>), which XML-DSig also allows.
  res.type("application/samlmetadata+xml").send(`<md:EntityDescriptor xmlns:md="${NS.md}" xmlns:ds="${NS.ds}" entityID="${IDP_ENTITY_ID}">
  <md:IDPSSODescriptor WantAuthnRequestsSigned="false" protocolSupportEnumeration="${NS.samlp}">
    <md:KeyDescriptor use="signing">
      <ds:KeyInfo><ds:KeyValue><ds:RSAKeyValue><ds:Modulus>${b64(jwk.n)}</ds:Modulus><ds:Exponent>${b64(jwk.e)}</ds:Exponent></ds:RSAKeyValue></ds:KeyValue></ds:KeyInfo>
    </md:KeyDescriptor>
    <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="${BASE_URL}/idp/sso"/>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>
`);
});

app.get("/sp/metadata", (req, res) => {
  res.type("application/samlmetadata+xml").send(`<md:EntityDescriptor xmlns:md="${NS.md}" entityID="${SP_ENTITY_ID}">
  <md:SPSSODescriptor AuthnRequestsSigned="false" WantAssertionsSigned="true" protocolSupportEnumeration="${NS.samlp}">
    <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>
    <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="${SP_ACS_URL}" index="0"/>
  </md:SPSSODescriptor>
</md:EntityDescriptor>
`);
});

// ---------- STEP 2: SP-initiated login. Rahul opens PaisaTrack, PaisaTrack sends him to the IdP ----------
app.get("/sp/login", (req, res) => {
  const id = samlId();
  pendingRequests.set(id, Date.now() + ASSERTION_LIFETIME_MS); // remember it for the InResponseTo check (step 5i)
  const xml = `<samlp:AuthnRequest xmlns:samlp="${NS.samlp}" xmlns:saml="${NS.saml}" ID="${id}" Version="2.0" IssueInstant="${iso(Date.now())}" Destination="${TRUSTED_IDP.ssoUrl}" AssertionConsumerServiceURL="${SP_ACS_URL}" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"><saml:Issuer>${SP_ENTITY_ID}</saml:Issuer><samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress" AllowCreate="true"/></samlp:AuthnRequest>`;
  const samlRequest = zlib.deflateRawSync(xml).toString("base64");
  // RelayState travels through the IdP and the browser UNSIGNED, so it carries an opaque key, not the URL itself
  const relayState = crypto.randomBytes(16).toString("base64url");
  relayStates.set(relayState, { returnTo: safeReturnTo(str(req.query.returnTo)), expiresAt: Date.now() + ASSERTION_LIFETIME_MS });
  console.log(`➡️  SP: AuthnRequest ${id} → IdP`);
  res.redirect(`${TRUSTED_IDP.ssoUrl}?SAMLRequest=${encodeURIComponent(samlRequest)}&RelayState=${encodeURIComponent(relayState)}`);
});

// ---------- STEP 3 + 4: the IdP authenticates the user and answers ----------
app.get("/idp/sso", (req, res) => {
  const ar = readAuthnRequest(str(req.query.SAMLRequest));
  const relayState = str(req.query.RelayState)?.slice(0, 80);
  const session = getIdpSession(req);
  if (session) {
    // ✅ SSO: already logged in at the IdP (maybe for another app this morning), so no password prompt
    console.log(`🔁 IdP: ${session.email} already signed in, assertion for ${ar.sp.name}`);
    return res.type("html").send(postForm(ar.sp.acsUrl, buildSignedResponse({ ...ar, user: idpUsers.get(session.email), session, inResponseTo: ar.id }), relayState));
  }
  // The login form posts back to this same URL, so the AuthnRequest travels along in the query string
  res.type("html").send(`<!doctype html><html><body><h1>ChaiCorp ID</h1><p>Sign in to continue to <b>${esc(ar.sp.name)}</b></p>
<form method="post"><input name="email" type="email" placeholder="you@chaicorp.com"><input name="password" type="password"><button>Sign in</button></form></body></html>`);
});

app.post("/idp/sso", (req, res) => {
  const ar = readAuthnRequest(str(req.query.SAMLRequest));
  const relayState = str(req.query.RelayState)?.slice(0, 80);
  const user = checkPassword(str(req.body?.email)?.trim().toLowerCase(), str(req.body?.password));
  if (!user) return res.status(401).json({ error: "Wrong email or password" });
  // shortcut: password only. A real IdP adds MFA here (topic 45), which is a big reason companies centralize login.
  const sid = randomToken();
  const session = { email: user.email, authnInstant: Date.now(), sessionIndex: samlId() };
  idpSessions.set(sha256(sid), session);
  res.cookie("idp_sid", sid, { httpOnly: true, sameSite: "lax", path: "/idp" });
  console.log(`🔐 IdP: ${user.email} signed in, assertion for ${ar.sp.name}`);
  res.type("html").send(postForm(ar.sp.acsUrl, buildSignedResponse({ ...ar, user, session, inResponseTo: ar.id }), relayState));
});

// IdP-initiated SSO: the user clicks an app tile on the IdP dashboard. No AuthnRequest, so no InResponseTo.
app.post("/idp/launch", (req, res) => {
  const session = getIdpSession(req);
  if (!session) return res.status(401).json({ error: "Sign in to ChaiCorp ID first" });
  const spEntityId = str(req.body?.sp);
  const sp = spEntityId && registeredSps.get(spEntityId);
  if (!sp) return res.status(404).json({ error: "Unknown app" });
  console.log(`🧩 IdP: ${session.email} launched ${sp.name} (IdP-initiated)`);
  res.type("html").send(postForm(sp.acsUrl, buildSignedResponse({ spEntityId, sp, user: idpUsers.get(session.email), session })));
});

// ---------- STEP 5: the SP's Assertion Consumer Service (ACS) ----------
app.post("/sp/acs", (req, res) => {
  let user;
  try {
    user = validateSamlResponse(str(req.body?.SAMLResponse));
  } catch (err) {
    if (!(err instanceof SamlError)) throw err;
    console.log(`⛔ SP: rejected SAMLResponse: ${err.message}`);
    return res.status(401).json({ error: `SAML login failed: ${err.message}` });
  }
  // STEP 6: the assertion is used ONCE to create the SP's own session. From now on the app uses its cookie, not SAML.
  const sid = randomToken(); // always a fresh id at login (topic 50)
  spSessions.set(sha256(sid), { ...user, createdAt: Date.now() });
  res.cookie("sp_sid", sid, SP_COOKIE);
  console.log(`✅ SP: ${user.email} signed in to PaisaTrack`);
  const rs = str(req.body?.RelayState);
  const returnTo = (rs && relayStates.get(rs)?.returnTo) ?? "/sp/me";
  if (rs) relayStates.delete(rs);
  res.redirect(returnTo);
});

function getSpSession(req) {
  const sid = parseCookies(req).sp_sid;
  return (sid && spSessions.get(sha256(sid))) || null;
}

app.get("/sp/me", (req, res) => {
  const s = getSpSession(req);
  if (!s) return res.status(401).json({ error: "Not signed in", login: `${BASE_URL}/sp/login` });
  res.json({ app: "💸 PaisaTrack", email: s.email, name: s.name, groups: s.groups, sessionIndex: s.sessionIndex });
});

// Authorization stays in the SP: the IdP says WHO you are and which groups you're in, the app decides what that allows
app.get("/sp/approvals", (req, res) => {
  const s = getSpSession(req);
  if (!s) return res.status(401).json({ error: "Not signed in", login: `${BASE_URL}/sp/login?returnTo=/sp/approvals` });
  if (!s.groups.includes("finance")) return res.status(403).json({ error: "Only the finance group can approve expenses" });
  res.json({ pending: [{ id: 1, by: "Vikram Singh", amount: "₹4,200", for: "Client lunch, Bengaluru" }] });
});

// Local logout only: ends PaisaTrack's session, the IdP session lives on (Single Logout is topic 61)
app.post("/sp/logout", (req, res) => {
  const sid = parseCookies(req).sp_sid;
  if (sid) spSessions.delete(sha256(sid));
  res.clearCookie("sp_sid", SP_COOKIE);
  res.json({ message: "Logged out of PaisaTrack (still signed in at ChaiCorp ID)" });
});

app.use((req, res) => res.status(404).json({ error: "Not found" }));

// Errors (bad JSON, body too big, bad SAMLRequest, bugs) come here. Never send the stack trace to the client.
app.use((err, req, res, next) => {
  if (err instanceof SamlError) return res.status(400).json({ error: err.message });
  if (err.type === "entity.parse.failed") return res.status(400).json({ error: "Body must be valid JSON" });
  if (err.type === "entity.too.large") return res.status(413).json({ error: "Request body too large" });
  console.error(err);
  res.status(500).json({ error: "Something went wrong" });
});

// Express 5 passes a listen error (like "port already in use") to this callback instead of crashing
app.listen(PORT, (err) => {
  if (err) throw err;
  console.log(`🪪 ChaiCorp ID (IdP) on ${BASE_URL}/idp   💸 PaisaTrack (SP) on ${BASE_URL}/sp`);
});

// Sweep expired pending requests and replay-cache entries so the Maps don't grow forever
setInterval(() => {
  const now = Date.now();
  for (const m of [pendingRequests, usedAssertions, relayStates]) for (const [k, v] of m) if ((v.expiresAt ?? v) < now) m.delete(k);
}, 60_000).unref();
