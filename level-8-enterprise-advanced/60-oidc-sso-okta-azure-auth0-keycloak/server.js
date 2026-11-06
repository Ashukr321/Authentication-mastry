const express = require("express");
const crypto = require("crypto");

const APP_PORT = Number(process.env.PORT) || 3000; // KaamKaro: a B2B SaaS app. Every customer company brings its OWN identity provider
const IDP_PORT = APP_PORT + 1;                     // MOCK Okta, Entra ID, Auth0 and Keycloak, all on one port
const APP_URL = `http://localhost:${APP_PORT}`;    // URLs from config, never from the Host header
const IDP_URL = `http://localhost:${IDP_PORT}`;
const REDIRECT_URI = `${APP_URL}/sso/callback`;    // ONE callback for every customer: the state says which connection it was

// ---------- Shared helpers ----------
const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");
const randomToken = (bytes = 32) => crypto.randomBytes(bytes).toString("base64url");
const safeEqual = (a, b) => crypto.timingSafeEqual(Buffer.from(sha256(String(a))), Buffer.from(sha256(String(b))));
const str = (v) => (typeof v === "string" ? v : undefined); // query/body values can be arrays or objects: accept strings only
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
const pkceChallenge = (verifier) => crypto.createHash("sha256").update(verifier).digest("base64url");
const b64json = (obj) => Buffer.from(JSON.stringify(obj)).toString("base64url");
const parseCookies = (req) => Object.fromEntries((req.headers.cookie ?? "").split(";").filter((c) => c.includes("="))
  .map((c) => [c.slice(0, c.indexOf("=")).trim(), c.slice(c.indexOf("=") + 1).trim()]));

function newApp() {
  const app = express();
  app.use(express.json({ limit: "10kb" }));
  app.use(express.urlencoded({ extended: false, limit: "10kb" }));
  app.use((req, res, next) => { res.set("Cache-Control", "no-store"); next(); });
  return app;
}
function finish(app) {
  app.use((req, res) => res.status(404).json({ error: "Not found" }));
  // Errors (bad JSON, body too big, bugs) come here. Never send the stack trace to the client.
  app.use((err, req, res, next) => {
    if (err.type === "entity.parse.failed") return res.status(400).json({ error: "Body must be valid JSON" });
    if (err.type === "entity.too.large") return res.status(413).json({ error: "Request body too large" });
    console.error(err);
    res.status(500).json({ error: "Something went wrong" });
  });
}

// =====================================================================================
// PART 1: MOCK IDENTITY PROVIDERS. All four speak the SAME protocol (OpenID Connect, topic 36).
// What differs is the issuer URL shape and where they put groups/roles in the ID token.
// shortcut: no real login page, a link lets you pick a test user. Real IdPs need an app registration (see README).
// =====================================================================================
const CONTOSO_TID = "9188040d-6c67-4c5b-b112-36a304b66dad"; // Contoso's Entra tenant id
const IDPS = [
  { // Okta: issuer = your Okta domain + authorization server ("default"). Groups need a "groups" claim set up by the admin.
    name: "okta", issuer: `${IDP_URL}/okta/oauth2/default`,
    authorize: "/okta/oauth2/default/v1/authorize", token: "/okta/oauth2/default/v1/token", jwks: "/okta/oauth2/default/v1/keys",
    clients: { "0oa4kaamkaro8x7": "okta-demo-secret" },
    users: {
      rahul: { sub: "00u8rahul1a2b3c4d5", name: "Rahul Sharma", email: "rahul@acme.example", email_verified: true, groups: ["Everyone", "KaamKaro-Admins"] },
      amit:  { sub: "00u8amit9z8y7x6w5", name: "Amit Verma", email: "amit@acme.example", email_verified: true, groups: ["Everyone"] },
    },
  },
  { // Microsoft Entra ID: issuer contains the TENANT id. Endpoints are NOT under the issuer path. App roles arrive in "roles".
    name: "entra", issuer: `${IDP_URL}/entra/${CONTOSO_TID}/v2.0`,
    authorize: `/entra/${CONTOSO_TID}/oauth2/v2.0/authorize`, token: `/entra/${CONTOSO_TID}/oauth2/v2.0/token`, jwks: `/entra/${CONTOSO_TID}/discovery/v2.0/keys`,
    clients: { "b7e1c9a0-2f4d-4e8b-9c1a-kaamkaro0001": "entra-demo-secret" },
    users: { // no "email" claim unless the admin adds it as an optional claim. sub is per-app; oid is the user's id in the tenant.
      priya: { sub: "Xq3vPriyaPairwiseSubForKaamKaro01", oid: "6f1c2e3d-4b5a-4c6d-8e7f-000000000101", tid: CONTOSO_TID, name: "Priya Nair", preferred_username: "priya@contoso.example", roles: ["KaamKaro.Admin"] },
    },
  },
  { // Auth0: issuer is the tenant domain WITH a trailing slash. Custom claims must be namespaced (a URL).
    name: "auth0", issuer: `${IDP_URL}/auth0/`,
    authorize: "/auth0/authorize", token: "/auth0/oauth/token", jwks: "/auth0/.well-known/jwks.json",
    clients: { "Gx7kaamkaroAuth0ClientId": "auth0-demo-secret" },
    users: {
      sneha: { sub: "auth0|65a1f0c2b3d4sneha", name: "Sneha Iyer", email: "sneha@globex.example", email_verified: true, "https://kaamkaro.example/roles": ["member"] },
    },
  },
  { // Keycloak: issuer = server + /realms/<realm>. Roles live in realm_access.roles.
    name: "keycloak-initech", issuer: `${IDP_URL}/keycloak/realms/initech`,
    authorize: "/keycloak/realms/initech/protocol/openid-connect/auth", token: "/keycloak/realms/initech/protocol/openid-connect/token", jwks: "/keycloak/realms/initech/protocol/openid-connect/certs",
    clients: { kaamkaro: "keycloak-initech-secret" },
    users: {
      arjun: { sub: "f3b9c1d2-4e5f-4a6b-8c7d-0000000a7c01", name: "Arjun Mehta", preferred_username: "arjun", email: "arjun@initech.example", email_verified: true, realm_access: { roles: ["default-roles-initech", "kaamkaro-admin"] } },
    },
  },
  { // Shady Ltd ALSO signed up for KaamKaro and connected its own Keycloak. Its admin controls every claim in it.
    name: "keycloak-shady", issuer: `${IDP_URL}/keycloak/realms/shady`,
    authorize: "/keycloak/realms/shady/protocol/openid-connect/auth", token: "/keycloak/realms/shady/protocol/openid-connect/token", jwks: "/keycloak/realms/shady/protocol/openid-connect/certs",
    clients: { kaamkaro: "keycloak-shady-secret" },
    users: { // Vikram made a user that claims to be Acme's admin. email_verified: true costs him one checkbox.
      vikram: { sub: "0b6e7d8c-1111-4222-8333-0000000bad01", name: "Rahul Sharma", email: "rahul@acme.example", email_verified: true, realm_access: { roles: ["kaamkaro-admin"] } },
    },
  },
];

const idpCodes = new Map(); // code -> { idp, clientId, user, nonce, challenge, expiresAt }
const idp = newApp();
for (const p of IDPS) {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  p.privateKey = privateKey;
  p.kid = `${p.name}-${randomToken(4)}`;
  const jwk = { ...publicKey.export({ format: "jwk" }), kid: p.kid, alg: "RS256", use: "sig" };

  // Discovery lives at issuer (without trailing slash) + /.well-known/openid-configuration
  idp.get(`${new URL(p.issuer).pathname.replace(/\/$/, "")}/.well-known/openid-configuration`, (req, res) => res.json({
    issuer: p.issuer, authorization_endpoint: IDP_URL + p.authorize, token_endpoint: IDP_URL + p.token, jwks_uri: IDP_URL + p.jwks,
    response_types_supported: ["code"], id_token_signing_alg_values_supported: ["RS256"], code_challenge_methods_supported: ["S256"],
    token_endpoint_auth_methods_supported: ["client_secret_basic"], scopes_supported: ["openid", "profile", "email"],
  }));
  idp.get(p.jwks, (req, res) => res.json({ keys: [jwk] }));

  idp.get(p.authorize, (req, res) => {
    const q = Object.fromEntries(["client_id", "redirect_uri", "state", "nonce", "code_challenge", "code_challenge_method", "mock_user"].map((k) => [k, str(req.query[k])]));
    // An unknown client or redirect_uri gets an error page, NEVER a redirect (open redirect, topic 33)
    if (!p.clients[q.client_id] || q.redirect_uri !== REDIRECT_URI) return res.status(400).send("Unknown client_id or redirect_uri. Not redirecting.");
    if (!q.mock_user) {
      const links = Object.keys(p.users).map((u) => `<li><a href="${esc(`${req.originalUrl}&mock_user=${u}`)}">Continue as ${esc(u)}</a></li>`).join("");
      return res.send(`<!doctype html><meta charset="utf-8"><title>Mock ${esc(p.name)}</title><body style="font-family:system-ui;max-width:520px;margin:40px auto">
        <h2>Mock ${esc(p.name)} login</h2><p>A real IdP shows its own login page here (password, MFA, company policies).</p><ul>${links}</ul>`);
    }
    if (!p.users[q.mock_user]) return res.status(400).send("Unknown mock user");
    const back = (params) => res.redirect(`${REDIRECT_URI}?${new URLSearchParams({ ...params, ...(q.state && { state: q.state }) })}`);
    if (q.code_challenge_method !== "S256" || !q.code_challenge) return back({ error: "invalid_request", error_description: "PKCE (S256) required" });
    const code = randomToken();
    idpCodes.set(code, { idp: p.name, clientId: q.client_id, user: q.mock_user, nonce: q.nonce, challenge: q.code_challenge, expiresAt: Date.now() + 60_000 });
    back({ code });
  });

  idp.post(p.token, (req, res) => {
    // client_secret_basic: Authorization: Basic base64(urlencode(id):urlencode(secret))
    const [id, secret] = Buffer.from((req.headers.authorization ?? "").replace(/^Basic /, ""), "base64").toString().split(":").map((s) => decodeURIComponent(s ?? ""));
    if (!p.clients[id] || !safeEqual(p.clients[id], secret ?? "")) return res.status(401).json({ error: "invalid_client" });
    const b = req.body ?? {};
    const rec = idpCodes.get(str(b.code));
    if (str(b.grant_type) !== "authorization_code" || !rec || rec.idp !== p.name || rec.clientId !== id || rec.expiresAt < Date.now() ||
        str(b.redirect_uri) !== REDIRECT_URI || pkceChallenge(str(b.code_verifier) ?? "") !== rec.challenge) return res.status(400).json({ error: "invalid_grant" });
    idpCodes.delete(str(b.code)); // codes are one-time
    const now = Math.floor(Date.now() / 1000);
    const claims = { iss: p.issuer, aud: id, iat: now, exp: now + 300, auth_time: now, ...(rec.nonce && { nonce: rec.nonce }), ...p.users[rec.user] };
    const header = b64json({ alg: "RS256", typ: "JWT", kid: p.kid });
    const body = `${header}.${b64json(claims)}`;
    const idToken = `${body}.${crypto.sign("sha256", Buffer.from(body), p.privateKey).toString("base64url")}`;
    res.json({ token_type: "Bearer", expires_in: 3600, access_token: randomToken(), id_token: idToken });
  });
}
finish(idp);

// =====================================================================================
// PART 2: KAAMKARO, the relying party (the "SP" from topic 57).
// =====================================================================================

// Step 1: one SSO CONNECTION per customer org. A customer admin fills this in on a settings page:
// issuer URL + client id + secret from their IdP, plus which group means "admin".
// shortcut: hard-coded and secrets in code. Real apps: an org_connections table, secrets encrypted / in a vault (topic 54).
const ORGS = {
  acme:     { name: "Acme Corp",  domains: ["acme.example"],     enforceSso: true,
              sso: { profile: "okta",     issuer: `${IDP_URL}/okta/oauth2/default`,        clientId: "0oa4kaamkaro8x7", clientSecret: "okta-demo-secret", adminGroup: "KaamKaro-Admins" } },
  contoso:  { name: "Contoso",    domains: ["contoso.example"],  enforceSso: true,
              sso: { profile: "entra",    issuer: `${IDP_URL}/entra/${CONTOSO_TID}/v2.0`,  clientId: "b7e1c9a0-2f4d-4e8b-9c1a-kaamkaro0001", clientSecret: "entra-demo-secret", adminGroup: "KaamKaro.Admin" } },
  globex:   { name: "Globex",     domains: ["globex.example"],   enforceSso: true,
              sso: { profile: "auth0",    issuer: `${IDP_URL}/auth0/`,                     clientId: "Gx7kaamkaroAuth0ClientId", clientSecret: "auth0-demo-secret", adminGroup: "admin" } },
  initech:  { name: "Initech",    domains: ["initech.example"],  enforceSso: false, // still rolling SSO out: passwords allowed too
              sso: { profile: "keycloak", issuer: `${IDP_URL}/keycloak/realms/initech`,    clientId: "kaamkaro", clientSecret: "keycloak-initech-secret", adminGroup: "kaamkaro-admin" } },
  shady:    { name: "Shady Ltd",  domains: ["shady.example"],    enforceSso: false,
              sso: { profile: "keycloak", issuer: `${IDP_URL}/keycloak/realms/shady`,      clientId: "kaamkaro", clientSecret: "keycloak-shady-secret", adminGroup: "kaamkaro-admin" } },
  umbrella: { name: "Umbrella",   domains: ["umbrella.example"], enforceSso: true, // its admin pasted the Auth0 issuer WITHOUT the trailing slash
              sso: { profile: "auth0",    issuer: `${IDP_URL}/auth0`,                      clientId: "Gx7kaamkaroAuth0ClientId", clientSecret: "auth0-demo-secret", adminGroup: "admin" } },
};
// Domains are only listed here AFTER the org proved it owns them (a DNS TXT record, see README).
// Without that, Shady Ltd could just type "acme.example" into its own settings.

// Step 4: CLAIM PROFILES. Same protocol, different places for the user id, email and groups.
const CLAIM_PROFILES = {
  okta:     (c) => ({ subject: c.sub, email: c.email, groups: c.groups }),
  entra:    (c) => ({ subject: c.oid, email: c.email ?? c.preferred_username, groups: c.roles }), // oid = the user in the tenant. preferred_username is the UPN, whose domain Entra makes the tenant verify
  auth0:    (c) => ({ subject: c.sub, email: c.email, groups: c["https://kaamkaro.example/roles"] }),
  keycloak: (c) => ({ subject: c.sub, email: c.email, groups: c.realm_access?.roles }),
};

const emailDomain = (email) => email.slice(email.lastIndexOf("@") + 1).toLowerCase();
const orgIdForEmail = (email) => Object.keys(ORGS).find((id) => ORGS[id].domains.includes(emailDomain(email)));

// Step 2: DISCOVERY. The connection only stores the issuer; everything else is read from the IdP.
const discoveryCache = new Map(); // issuer -> discovery document. shortcut: cached forever; refresh daily in a real app
async function discover(issuer) {
  if (!discoveryCache.has(issuer)) {
    const doc = await (await fetch(`${issuer.replace(/\/$/, "")}/.well-known/openid-configuration`)).json();
    // The document's issuer must be EXACTLY what the admin configured (OIDC Discovery 1.0, section 4.3). One "/" counts.
    if (doc.issuer !== issuer) throw new Error(`issuer mismatch: configured "${issuer}", IdP says "${doc.issuer}"`);
    discoveryCache.set(issuer, doc);
  }
  return discoveryCache.get(issuer);
}

// Step 5: validate the ID token. Every check is against the CONNECTION we started with, never against the token's own claims.
const jwksCache = new Map(); // jwks_uri -> Map(kid -> public key)
async function verifyIdToken(token, { conn, doc, nonce }) {
  const parts = String(token).split(".");
  if (parts.length !== 3) throw new Error("malformed id_token");
  const header = JSON.parse(Buffer.from(parts[0], "base64url"));
  if (header.alg !== "RS256") throw new Error(`alg ${header.alg} not allowed`); // pinned: never "none", never HS256 (topic 53)
  if (!jwksCache.get(doc.jwks_uri)?.has(header.kid)) { // unknown kid = the IdP rotated its key: refetch once
    const { keys } = await (await fetch(doc.jwks_uri)).json();
    jwksCache.set(doc.jwks_uri, new Map(keys.map((k) => [k.kid, crypto.createPublicKey({ key: k, format: "jwk" })])));
  }
  const key = jwksCache.get(doc.jwks_uri).get(header.kid);
  if (!key) throw new Error("unknown kid");
  if (!crypto.verify("sha256", Buffer.from(`${parts[0]}.${parts[1]}`), key, Buffer.from(parts[2], "base64url"))) throw new Error("bad signature");
  const c = JSON.parse(Buffer.from(parts[1], "base64url"));
  const now = Math.floor(Date.now() / 1000);
  const aud = [].concat(c.aud);
  if (c.iss !== conn.issuer) throw new Error(`iss ${c.iss} is not this connection's issuer`);
  if (!aud.includes(conn.clientId) || (aud.length > 1 && c.azp !== conn.clientId)) throw new Error("token is for another app (aud)");
  if (!(c.exp > now - 30) || c.iat > now + 30) throw new Error("expired or not yet valid");
  if (!c.nonce || !safeEqual(c.nonce, nonce)) throw new Error("nonce mismatch");
  return c;
}

// ---------- Users and sessions ----------
// shortcut: in-memory Maps, lost on restart. Real apps: users, sso_identities(org_id, subject UNIQUE), sessions tables.
const users = new Map();         // userId -> { id, orgId, email, name, role, passwordHash? }
const usersByEmail = new Map();  // email -> userId
const ssoIdentities = new Map(); // `${orgId}|${subject}` -> userId
const sessions = new Map();      // sid -> { pending: Map(state -> {orgId, nonce, verifier, expiresAt}), userId, via }

const hashPassword = (pw, salt = randomToken(16)) => `${salt}:${crypto.scryptSync(pw, salt, 32).toString("hex")}`;
function checkPassword(pw, stored) {
  const [salt, hash] = stored.split(":");
  return crypto.timingSafeEqual(Buffer.from(hash, "hex"), crypto.scryptSync(pw, salt, 32));
}
const DUMMY_HASH = hashPassword("not-a-real-password"); // same work for unknown emails (topic 51)
function addUser(u) { const user = { id: `usr_${randomToken(4)}`, ...u }; users.set(user.id, user); usersByEmail.set(user.email, user.id); return user; }
// Rahul had a password account BEFORE Acme switched to SSO. Meera's company has no SSO at all.
addUser({ orgId: "acme", email: "rahul@acme.example", name: "Rahul Sharma", role: "member", passwordHash: hashPassword("old-acme-pass-1") });
addUser({ orgId: null, email: "meera@freelance.example", name: "Meera Joshi", role: "member", passwordHash: hashPassword("meera-chai-2026") });

const app = newApp();
function session(req, res) {
  let sid = parseCookies(req).kk_sid;
  if (!sid || !sessions.has(sid)) {
    sid = randomToken();
    sessions.set(sid, { pending: new Map(), userId: null });
    res.append("Set-Cookie", `kk_sid=${sid}; HttpOnly; SameSite=Lax; Path=/`);
  }
  return { sid, s: sessions.get(sid) };
}
function startSession(res, oldSid, userId, via) {
  sessions.delete(oldSid); // new session id after login (topic 50)
  const sid = randomToken();
  sessions.set(sid, { pending: new Map(), userId, via });
  res.set("Set-Cookie", `kk_sid=${sid}; HttpOnly; SameSite=Lax; Path=/`);
}

app.get("/", (req, res) => {
  session(req, res);
  res.send(`<!doctype html><meta charset="utf-8"><title>KaamKaro</title><body style="font-family:system-ui;max-width:520px;margin:40px auto">
    <h2>🗂️ KaamKaro</h2><p>Enter your work email. If your company uses SSO, we send you to its login page.</p>
    <form method="post" action="/sso/start"><input name="email" placeholder="rahul@acme.example" size="30"> <button>Continue</button></form>
    <p>Test emails: rahul@ / amit@acme.example (Okta), priya@contoso.example (Entra ID), sneha@globex.example (Auth0),
    arjun@initech.example (Keycloak), vikram@shady.example, ceo@umbrella.example</p>
    <p><a href="/me">Who am I?</a></p>`);
});

// Step 3: HOME REALM DISCOVERY. The email domain picks the org, the org picks the IdP.
app.post("/sso/start", async (req, res) => {
  const email = str(req.body?.email)?.trim().toLowerCase();
  if (!email || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) return res.status(400).json({ error: "Enter a valid email" });
  const orgId = orgIdForEmail(email);
  if (!orgId) return res.json({ next: "password", message: `No SSO set up for ${emailDomain(email)}. Log in with your password.` });
  const org = ORGS[orgId];
  let doc;
  try {
    doc = await discover(org.sso.issuer);
  } catch (e) {
    console.log(`🚨 ${org.name}: SSO misconfigured: ${e.message}`);
    return res.status(502).json({ error: `Single sign-on for ${org.name} is misconfigured. Ask your IT admin.` });
  }
  const { s } = session(req, res);
  const state = randomToken(16), nonce = randomToken(16), verifier = randomToken(32);
  // The pending login remembers WHICH org's connection it started with. The callback trusts only this.
  s.pending.set(state, { orgId, nonce, verifier, expiresAt: Date.now() + 10 * 60 * 1000 });
  const params = new URLSearchParams({ response_type: "code", client_id: org.sso.clientId, redirect_uri: REDIRECT_URI, scope: "openid profile email",
    state, nonce, code_challenge: pkceChallenge(verifier), code_challenge_method: "S256", login_hint: email });
  console.log(`➡️  ${email} → ${org.name} (${org.sso.profile})`);
  res.redirect(303, `${doc.authorization_endpoint}?${params}`);
});

// Step 6: the callback. One URL for every customer.
app.get("/sso/callback", async (req, res) => {
  const { sid, s } = session(req, res);
  const [code, state, error] = ["code", "state", "error"].map((k) => str(req.query[k]));
  const pending = state ? s.pending.get(state) : null;
  if (state) s.pending.delete(state); // one use
  if (!pending || pending.expiresAt < Date.now()) return res.status(400).json({ error: "This login didn't start here (state mismatch)" });
  const org = ORGS[pending.orgId];
  const conn = org.sso;
  if (error) return res.status(400).json({ error: `${org.name}'s IdP said: ${error}` });
  if (!code) return res.status(400).json({ error: "Missing code" });

  let claims;
  try {
    const doc = await discover(conn.issuer);
    const basic = Buffer.from(`${encodeURIComponent(conn.clientId)}:${encodeURIComponent(conn.clientSecret)}`).toString("base64");
    const tokens = await (await fetch(doc.token_endpoint, { method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded", Accept: "application/json", Authorization: `Basic ${basic}` },
      body: new URLSearchParams({ grant_type: "authorization_code", code, redirect_uri: REDIRECT_URI, code_verifier: pending.verifier }) })).json();
    if (!tokens.id_token) throw new Error(`token exchange: ${tokens.error}`);
    claims = await verifyIdToken(tokens.id_token, { conn, doc, nonce: pending.nonce });
  } catch (e) {
    console.log(`🚨 ${org.name} login failed: ${e.message}`);
    return res.status(400).json({ error: `Sign-in with ${org.name} failed` });
  }

  // Step 7: TRUST BOUNDARY. A valid token only proves "Acme's IdP said so". Each IdP may speak ONLY for its org's verified domains.
  const id = CLAIM_PROFILES[conn.profile](claims);
  const email = typeof id.email === "string" ? id.email.toLowerCase() : null;
  if (!id.subject || !email) return res.status(403).json({ error: `${org.name}'s IdP sent no user id or email. Ask your admin to release the email claim.` });
  if (!org.domains.includes(emailDomain(email))) {
    console.log(`🚨 ${org.name}'s IdP asserted ${email}: ${emailDomain(email)} is not one of its verified domains. Refused.`);
    return res.status(403).json({ error: `${org.name}'s sign-in can't be used for ${emailDomain(email)} accounts` });
  }

  // Step 8: find the user by (org, subject). First time? Link a pre-SSO account in the same org by email, or create one (JIT).
  const role = (id.groups ?? []).includes(conn.adminGroup) ? "admin" : "member"; // re-synced from the IdP on EVERY login
  const key = `${pending.orgId}|${id.subject}`;
  let user = users.get(ssoIdentities.get(key));
  let how = "👋 returning";
  if (!user) {
    const existing = users.get(usersByEmail.get(email));
    // Safe to link: the email is in a domain this org PROVED it owns, and the IdP is that org's own.
    if (existing && existing.orgId === pending.orgId) { user = existing; how = "🔗 linked to existing account"; }
    else if (existing) return res.status(409).json({ error: "This email belongs to an account outside your organization. Contact support." });
    else { user = addUser({ orgId: pending.orgId, email, name: claims.name ?? email }); how = "🆕 created (JIT)"; }
    ssoIdentities.set(key, user.id);
  }
  Object.assign(user, { name: claims.name ?? user.name, role });
  console.log(`${how}: ${user.email} → ${user.id} in ${org.name} via ${conn.profile}, subject ${id.subject}, role ${role}`);

  startSession(res, sid, user.id, `sso:${conn.profile}`);
  res.redirect(303, "/me");
});

// Passwords still exist for orgs without SSO, and for orgs that haven't enforced it yet.
app.post("/login/password", (req, res) => {
  const email = str(req.body?.email)?.trim().toLowerCase();
  const password = str(req.body?.password);
  if (!email || !password) return res.status(400).json({ error: "email and password are required" });
  const orgId = orgIdForEmail(email);
  // Step 9: ENFORCE SSO. Otherwise a fired employee (disabled in Okta) keeps logging in with an old password.
  if (orgId && ORGS[orgId].enforceSso) return res.status(403).json({ error: `${ORGS[orgId].name} requires single sign-on`, next: "/sso/start" });
  const user = users.get(usersByEmail.get(email));
  const ok = checkPassword(password, user?.passwordHash ?? DUMMY_HASH) && Boolean(user?.passwordHash);
  if (!ok) return res.status(401).json({ error: "Wrong email or password" });
  startSession(res, session(req, res).sid, user.id, "password");
  res.json({ message: `Logged in as ${user.email}` });
});

app.get("/me", (req, res) => {
  const { s } = session(req, res);
  const user = users.get(s.userId);
  if (!user) return res.status(401).json({ error: "Not logged in. Open / and enter your work email" });
  const { passwordHash, ...profile } = user;
  res.json({ ...profile, org: user.orgId && ORGS[user.orgId].name, loggedInVia: s.via });
});
finish(app);

idp.listen(IDP_PORT, () => console.log(`🧪 Mock Okta / Entra ID / Auth0 / Keycloak on ${IDP_URL}`));
app.listen(APP_PORT, () => console.log(`🗂️  KaamKaro on ${APP_URL}  ← open this one`));
