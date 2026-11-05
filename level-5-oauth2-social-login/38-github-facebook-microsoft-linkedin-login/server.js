const express = require("express");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");

const APP_PORT = Number(process.env.PORT) || 3000; // PrintKaro: one app, four "Log in with ..." buttons
const MOCK_PORT = APP_PORT + 1;                     // MOCK versions of GitHub, Facebook, Microsoft and LinkedIn
const APP_URL = `http://localhost:${APP_PORT}`;     // URLs from config, never from the Host header
const MOCK_URL = `http://localhost:${MOCK_PORT}`;

// ---------- Shared helpers ----------
const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");
const randomToken = (bytes = 32) => crypto.randomBytes(bytes).toString("base64url");
const safeEqual = (a, b) => crypto.timingSafeEqual(Buffer.from(sha256(a)), Buffer.from(sha256(b)));
const str = (v) => (typeof v === "string" ? v : undefined); // query/body values can be arrays: accept strings only
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
const pkceChallenge = (verifier) => crypto.createHash("sha256").update(verifier).digest("base64url");
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
// PART 1: MOCK PROVIDERS. Small fakes of the real services, with each one's real-world QUIRKS.
// shortcut: no real login or consent: a page lets you pick a test user. Real providers need app registration (see README).
// =====================================================================================
// Each provider registered PrintKaro once, and gave it a client id + secret (demo values)
const MOCK_CLIENTS = {
  github:    { id: "gh-printkaro",   secret: "gh-demo-secret" },
  facebook:  { id: "1234567890",     secret: "fb-demo-secret" },
  microsoft: { id: "a1b2c3d4-0000-4000-8000-printkaro0001", secret: "ms-demo-secret" },
  linkedin:  { id: "86printkaro",    secret: "li-demo-secret" },
};
const CONTOSO = "72f988bf-86f1-41af-91ab-2d7cd011db47";  // Rahul's company tenant
const FABRIKAM = "f00dcafe-1111-4222-8333-444455556666"; // a tenant Vikram created himself, in five minutes
const MOCK_USERS = {
  github: {
    rahul:  { id: 583231, login: "rahul-dev", name: "Rahul Sharma", emails: [{ email: "rahul@example.com", primary: true, verified: true }] },
    // Vikram added RAHUL's email to his GitHub account. GitHub lists it, but marks it unverified.
    vikram: { id: 990017, login: "vikram-x", name: "Vikram", emails: [{ email: "rahul@example.com", primary: true, verified: false }] },
  },
  facebook: {
    rahul: { id: "10229384756", name: "Rahul Sharma", email: "rahul@example.com" },
    priya: { id: "10229380001", name: "Priya Nair" }, // signed up with a phone number: Facebook has NO email for her
  },
  microsoft: {
    rahul:  { oid: "0f1e2d3c-aaaa-4bbb-8ccc-000000000001", tid: CONTOSO, name: "Rahul Sharma", preferred_username: "rahul@contoso.example", email: "rahul@contoso.example" },
    // In his own tenant, Vikram can set the "email" attribute to ANY address, unverified ("nOAuth")
    vikram: { oid: "0f1e2d3c-aaaa-4bbb-8ccc-000000000666", tid: FABRIKAM, name: "Vikram", preferred_username: "vikram@fabrikam.example", email: "rahul@example.com" },
  },
  linkedin: {
    rahul: { sub: "yW3Lk9ZqP0", name: "Rahul Sharma", given_name: "Rahul", email: "rahul@example.com", email_verified: true },
  },
};
// Microsoft and LinkedIn sign OpenID Connect ID tokens with RS256 (topic 36). Each has its own key and JWKS.
const KEYS = Object.fromEntries(["microsoft", "linkedin"].map((p) => {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  const kid = `${p}-${randomToken(4)}`;
  return [p, { privateKey, kid, jwk: { ...publicKey.export({ format: "jwk" }), kid, alg: "RS256", use: "sig" } }];
}));

const mockCodes = new Map();  // code -> { provider, who, nonce, challenge, redirectUri, expiresAt }
const mockTokens = new Map(); // access token -> { provider, who }
const mock = newApp();

function mockAuthorize(provider, req, res) {
  const q = Object.fromEntries(["client_id", "redirect_uri", "state", "nonce", "code_challenge", "code_challenge_method", "mock_user"].map((k) => [k, str(req.query[k])]));
  const redirectUri = `${APP_URL}/callback/${provider}`;
  if (q.client_id !== MOCK_CLIENTS[provider].id || q.redirect_uri !== redirectUri) return res.status(400).send("Unknown client or redirect_uri. Not redirecting.");
  const users = MOCK_USERS[provider];
  if (!q.mock_user) {
    // The "login page": pick who you are
    const links = Object.keys(users).map((u) => `<li><a href="${esc(`${req.originalUrl}&mock_user=${u}`)}">Continue as ${esc(u)}</a></li>`).join("");
    return res.send(`<!doctype html><meta charset="utf-8"><title>Mock ${provider}</title><body style="font-family:system-ui;max-width:520px;margin:40px auto">
      <h2>Mock ${esc(provider)} login</h2><p>A real provider shows its own login and consent pages here.</p><ul>${links}</ul>`);
  }
  if (!users[q.mock_user]) return res.status(400).send("Unknown mock user");
  const back = (params) => res.redirect(`${redirectUri}?${new URLSearchParams({ ...params, ...(q.state && { state: q.state }) })}`);
  if (provider === "microsoft" && (q.code_challenge_method !== "S256" || !q.code_challenge)) return back({ error: "invalid_request", error_description: "PKCE required" });
  const code = randomToken();
  mockCodes.set(code, { provider, who: q.mock_user, nonce: q.nonce, challenge: q.code_challenge, redirectUri, expiresAt: Date.now() + 60_000 });
  back({ code });
}

// Redeem a code: same rules everywhere, every provider just reports errors in its own way
function redeem(provider, p) {
  const client = MOCK_CLIENTS[provider];
  if (p.client_id !== client.id || p.client_secret !== client.secret) return "client authentication failed";
  const record = mockCodes.get(p.code);
  if (!record || record.provider !== provider || record.expiresAt < Date.now() || record.redirectUri !== p.redirect_uri) return "bad or expired code";
  if (record.challenge && (!p.code_verifier || pkceChallenge(p.code_verifier) !== record.challenge)) return "PKCE verification failed";
  mockCodes.delete(p.code);
  const accessToken = randomToken();
  mockTokens.set(accessToken, { provider, who: record.who });
  return { record, accessToken };
}
const fields = (body) => Object.fromEntries(["client_id", "client_secret", "code", "redirect_uri", "code_verifier"].map((k) => [k, str(body?.[k])]));

function idToken(provider, claims, nonce) {
  const { privateKey, kid } = KEYS[provider];
  return jwt.sign({ ...claims, ...(nonce && { nonce }) }, privateKey, { algorithm: "RS256", keyid: kid, audience: MOCK_CLIENTS[provider].id, expiresIn: "1h" });
}

// --- GitHub (real: github.com/login/oauth/..., api.github.com) ---
mock.get("/github/login/oauth/authorize", (req, res) => mockAuthorize("github", req, res));
mock.post("/github/login/oauth/access_token", (req, res) => {
  const r = redeem("github", fields(req.body));
  // QUIRK: errors come back as HTTP 200 with an "error" field
  if (typeof r === "string") return res.status(200).json({ error: "bad_verification_code", error_description: r });
  const body = { access_token: r.accessToken, token_type: "bearer", scope: "read:user,user:email" };
  // QUIRK: form-encoded unless you send Accept: application/json
  if ((req.get("Accept") ?? "").includes("application/json")) return res.json(body);
  res.type("application/x-www-form-urlencoded").send(new URLSearchParams(body).toString());
});
function mockBearer(provider, req) {
  const [, token] = (req.headers.authorization ?? "").split(" ");
  const t = token && mockTokens.get(token);
  return t && t.provider === provider ? MOCK_USERS[provider][t.who] : null;
}
mock.get("/github/api/user", (req, res) => {
  const u = mockBearer("github", req);
  if (!u) return res.status(401).json({ message: "Bad credentials" });
  res.json({ id: u.id, login: u.login, name: u.name, email: null }); // QUIRK: email is null unless the user made it public
});
mock.get("/github/api/user/emails", (req, res) => {
  const u = mockBearer("github", req);
  if (!u) return res.status(401).json({ message: "Bad credentials" });
  res.json(u.emails);
});

// --- Facebook (real: facebook.com/v19.0/dialog/oauth, graph.facebook.com) ---
mock.get("/facebook/dialog/oauth", (req, res) => mockAuthorize("facebook", req, res));
mock.get("/facebook/graph/oauth/access_token", (req, res) => { // QUIRK: the code exchange can be a GET with query parameters
  const r = redeem("facebook", fields(req.query));
  // QUIRK: Facebook's own error shape
  if (typeof r === "string") return res.status(400).json({ error: { message: r, type: "OAuthException", code: 100 } });
  res.json({ access_token: r.accessToken, token_type: "bearer", expires_in: 5183944 }); // about 60 days, no refresh token
});
mock.get("/facebook/graph/me", (req, res) => {
  const u = mockBearer("facebook", req);
  if (!u) return res.status(400).json({ error: { message: "Invalid OAuth access token", type: "OAuthException", code: 190 } });
  const wanted = (str(req.query.fields) ?? "id,name").split(","); // QUIRK: you only get the fields you ask for
  res.json(Object.fromEntries(wanted.filter((f) => u[f] !== undefined).map((f) => [f, u[f]])));
});

// --- Microsoft identity platform (real: login.microsoftonline.com/common/oauth2/v2.0/...) ---
mock.get("/microsoft/common/oauth2/v2.0/authorize", (req, res) => mockAuthorize("microsoft", req, res));
mock.post("/microsoft/common/oauth2/v2.0/token", (req, res) => {
  const r = redeem("microsoft", fields(req.body));
  if (typeof r === "string") return res.status(400).json({ error: "invalid_grant", error_description: r });
  const u = MOCK_USERS.microsoft[r.record.who];
  // QUIRK: one "common" endpoint, but the issuer contains the user's TENANT id. sub is pairwise (different per app).
  const claims = { ver: "2.0", iss: `${MOCK_URL}/microsoft/${u.tid}/v2.0`, tid: u.tid, oid: u.oid, sub: sha256(`${u.oid}|${MOCK_CLIENTS.microsoft.id}`).slice(0, 43),
    name: u.name, preferred_username: u.preferred_username, email: u.email };
  res.json({ token_type: "Bearer", scope: "openid profile email", expires_in: 3600, access_token: r.accessToken, id_token: idToken("microsoft", claims, r.record.nonce) });
});
mock.get("/microsoft/common/discovery/v2.0/keys", (req, res) => res.json({ keys: [KEYS.microsoft.jwk] }));

// --- LinkedIn, "Sign In with LinkedIn using OpenID Connect" (real: linkedin.com/oauth/v2/...) ---
mock.get("/linkedin/oauth/v2/authorization", (req, res) => mockAuthorize("linkedin", req, res));
mock.post("/linkedin/oauth/v2/accessToken", (req, res) => {
  const r = redeem("linkedin", fields(req.body));
  if (typeof r === "string") return res.status(400).json({ error: "invalid_request", error_description: r });
  const u = MOCK_USERS.linkedin[r.record.who];
  const claims = { iss: `${MOCK_URL}/linkedin`, sub: u.sub, name: u.name, given_name: u.given_name, email: u.email, email_verified: u.email_verified };
  res.json({ access_token: r.accessToken, expires_in: 5183999, scope: "openid,profile,email", token_type: "Bearer", id_token: idToken("linkedin", claims, r.record.nonce) });
});
mock.get("/linkedin/oauth/openid/jwks", (req, res) => res.json({ keys: [KEYS.linkedin.jwk] }));
finish(mock);

// =====================================================================================
// PART 2: PRINTKARO. One login flow, four ADAPTERS that turn each provider's answer into the same shape:
// { provider, providerUserId, name, email, emailVerified }
// =====================================================================================
const client = (p) => ({ clientId: MOCK_CLIENTS[p].id, clientSecret: MOCK_CLIENTS[p].secret }); // shortcut: real ones come from env / a secret store
const redirectFor = (p) => `${APP_URL}/callback/${p}`;
const postForm = async (url, body, headers = {}) => (await fetch(url, { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded", Accept: "application/json", ...headers }, body: new URLSearchParams(body) })).json();

const jwksCache = new Map(); // jwksUri -> Map(kid -> KeyObject)
async function verifyIdToken(token, { jwksUri, audience, nonce, checkIssuer }) {
  const kid = jwt.decode(token, { complete: true })?.header?.kid; // decode ONLY to pick the key
  if (!jwksCache.get(jwksUri)?.has(kid)) {
    const { keys } = await (await fetch(jwksUri)).json();
    jwksCache.set(jwksUri, new Map(keys.map((k) => [k.kid, crypto.createPublicKey({ key: k, format: "jwk" })])));
  }
  const key = jwksCache.get(jwksUri).get(kid);
  if (!key) throw new Error("unknown kid");
  const claims = jwt.verify(token, key, { algorithms: ["RS256"], audience, clockTolerance: 30 });
  if (!checkIssuer(claims)) throw new Error(`unexpected issuer ${claims.iss}`);
  if (!claims.nonce || !safeEqual(claims.nonce, nonce)) throw new Error("nonce mismatch");
  return claims;
}

// Optional: only let users from these Microsoft tenants in (a work app for one company). Empty = any tenant.
const ALLOWED_MS_TENANTS = (process.env.ALLOWED_MS_TENANTS ?? "").split(",").filter(Boolean);

const PROVIDERS = {
  github: {
    label: "GitHub", oidc: false, pkce: false,
    authorizeUrl: `${MOCK_URL}/github/login/oauth/authorize`, scope: "read:user user:email",
    async identify({ code }) {
      const tokens = await postForm(`${MOCK_URL}/github/login/oauth/access_token`, { ...pick(client("github")), code, redirect_uri: redirectFor("github") });
      if (tokens.error || !tokens.access_token) throw new Error(`token exchange: ${tokens.error_description ?? tokens.error}`); // 200 can still be an error
      const auth = { headers: { Authorization: `Bearer ${tokens.access_token}`, Accept: "application/vnd.github+json" } };
      const user = await (await fetch(`${MOCK_URL}/github/api/user`, auth)).json();
      const emails = await (await fetch(`${MOCK_URL}/github/api/user/emails`, auth)).json();
      const best = emails.find((e) => e.primary && e.verified) ?? null; // only a VERIFIED email counts
      // The numeric id is permanent. The login ("rahul-dev") can be renamed, and someone else can take the old name.
      return { providerUserId: String(user.id), name: user.name ?? user.login, email: best?.email ?? null, emailVerified: Boolean(best) };
    },
  },
  facebook: {
    label: "Facebook", oidc: false, pkce: false,
    authorizeUrl: `${MOCK_URL}/facebook/dialog/oauth`, scope: "public_profile email",
    async identify({ code }) {
      const params = new URLSearchParams({ ...pick(client("facebook")), code, redirect_uri: redirectFor("facebook") });
      const tokens = await (await fetch(`${MOCK_URL}/facebook/graph/oauth/access_token?${params}`)).json();
      if (tokens.error || !tokens.access_token) throw new Error(`token exchange: ${tokens.error?.message}`);
      const me = await (await fetch(`${MOCK_URL}/facebook/graph/me?fields=id,name,email`, { headers: { Authorization: `Bearer ${tokens.access_token}` } })).json();
      if (!me.id) throw new Error(`profile: ${me.error?.message}`);
      // The id is "app-scoped": the same person has a DIFFERENT id in every Facebook app. Email may be missing.
      return { providerUserId: me.id, name: me.name, email: me.email ?? null, emailVerified: false }; // Facebook doesn't say "verified": treat as unverified
    },
  },
  microsoft: {
    label: "Microsoft", oidc: true, pkce: true,
    authorizeUrl: `${MOCK_URL}/microsoft/common/oauth2/v2.0/authorize`, scope: "openid profile email",
    async identify({ code, pending }) {
      const tokens = await postForm(`${MOCK_URL}/microsoft/common/oauth2/v2.0/token`, { ...pick(client("microsoft")), code, redirect_uri: redirectFor("microsoft"), grant_type: "authorization_code", code_verifier: pending.verifier });
      if (!tokens.id_token) throw new Error(`token exchange: ${tokens.error_description ?? tokens.error}`);
      const claims = await verifyIdToken(tokens.id_token, {
        jwksUri: `${MOCK_URL}/microsoft/common/discovery/v2.0/keys`, audience: client("microsoft").clientId, nonce: pending.nonce,
        // "common" means many issuers: the iss must be the template filled in with the token's OWN tenant id
        checkIssuer: (c) => c.iss === `${MOCK_URL}/microsoft/${c.tid}/v2.0` && (!ALLOWED_MS_TENANTS.length || ALLOWED_MS_TENANTS.includes(c.tid)),
      });
      // Identity = tenant + object id. NEVER the email / preferred_username: tenant admins can set them to anything.
      return { providerUserId: `${claims.tid}:${claims.oid}`, name: claims.name, email: claims.email ?? null, emailVerified: false };
    },
  },
  linkedin: {
    label: "LinkedIn", oidc: true, pkce: false,
    authorizeUrl: `${MOCK_URL}/linkedin/oauth/v2/authorization`, scope: "openid profile email",
    async identify({ code, pending }) {
      const tokens = await postForm(`${MOCK_URL}/linkedin/oauth/v2/accessToken`, { ...pick(client("linkedin")), code, redirect_uri: redirectFor("linkedin"), grant_type: "authorization_code" });
      if (!tokens.id_token) throw new Error(`token exchange: ${tokens.error_description ?? tokens.error}`);
      const claims = await verifyIdToken(tokens.id_token, {
        jwksUri: `${MOCK_URL}/linkedin/oauth/openid/jwks`, audience: client("linkedin").clientId, nonce: pending.nonce,
        checkIssuer: (c) => c.iss === `${MOCK_URL}/linkedin`,
      });
      return { providerUserId: claims.sub, name: claims.name, email: claims.email ?? null, emailVerified: claims.email_verified === true };
    },
  },
};
function pick({ clientId, clientSecret }) { return { client_id: clientId, client_secret: clientSecret }; }

// shortcut: in-memory Maps, lost on restart. Real apps: users + user_identities(provider, provider_user_id UNIQUE) tables.
const accounts = new Map(); // `${provider}|${providerUserId}` -> account
const sessions = new Map(); // sid -> { pending: Map(state -> { provider, nonce, verifier, expiresAt }), accountKey }
const app = newApp();

function session(req, res) {
  let sid = parseCookies(req).pk_sid;
  if (!sid || !sessions.has(sid)) {
    sid = randomToken();
    sessions.set(sid, { pending: new Map(), accountKey: null });
    res.append("Set-Cookie", `pk_sid=${sid}; HttpOnly; SameSite=Lax; Path=/`);
  }
  return { sid, s: sessions.get(sid) };
}

app.get("/", (req, res) => {
  session(req, res);
  res.send(`<!doctype html><meta charset="utf-8"><title>PrintKaro</title><body style="font-family:system-ui;max-width:520px;margin:40px auto">
    <h2>🖨️ PrintKaro</h2><p>Log in with:</p>
    ${Object.entries(PROVIDERS).map(([k, p]) => `<p><a href="/login/${k}">${esc(p.label)}</a></p>`).join("")}
    <p><a href="/me">Who am I?</a></p>`);
});

// Step 1: the SAME start for every provider: state always, nonce for OIDC ones, PKCE where the provider supports it
app.get("/login/:provider", (req, res) => {
  const provider = PROVIDERS[req.params.provider];
  if (!provider) return res.status(404).json({ error: "Unknown provider" });
  const { s } = session(req, res);
  const state = randomToken(16), nonce = randomToken(16), verifier = randomToken(32);
  // The pending login remembers WHICH provider it was started with (stops "mix-up" attacks)
  s.pending.set(state, { provider: req.params.provider, nonce, verifier, expiresAt: Date.now() + 10 * 60 * 1000 });
  const params = new URLSearchParams({ response_type: "code", client_id: client(req.params.provider).clientId, redirect_uri: redirectFor(req.params.provider), scope: provider.scope, state });
  if (provider.oidc) params.set("nonce", nonce);
  if (provider.pkce) { params.set("code_challenge", pkceChallenge(verifier)); params.set("code_challenge_method", "S256"); }
  res.redirect(`${provider.authorizeUrl}?${params}`);
});

// Step 2: one callback per provider: check state, let the ADAPTER do the provider-specific part, then one account model
app.get("/callback/:provider", async (req, res) => {
  const name = req.params.provider;
  const provider = PROVIDERS[name];
  if (!provider) return res.status(404).json({ error: "Unknown provider" });
  const { sid, s } = session(req, res);
  const [code, state, error] = ["code", "state", "error"].map((k) => str(req.query[k]));
  const pending = state ? s.pending.get(state) : null;
  if (state) s.pending.delete(state);
  if (!pending || pending.expiresAt < Date.now() || pending.provider !== name) return res.status(400).json({ error: "This login didn't start here (state mismatch)" });
  if (error) return res.status(400).json({ error: `${provider.label} said: ${error}` });
  if (!code) return res.status(400).json({ error: "Missing code" });

  let identity;
  try {
    identity = { provider: name, ...(await provider.identify({ code, pending })) };
  } catch (e) {
    console.log(`🚨 ${provider.label} login failed: ${e.message}`);
    return res.status(400).json({ error: `${provider.label} login failed` });
  }

  // Step 3: the account is keyed by (provider, providerUserId). Email is a profile field, not the key.
  const key = `${name}|${identity.providerUserId}`;
  const isNew = !accounts.has(key);
  if (isNew) accounts.set(key, { id: `acct_${randomToken(4)}`, createdAt: new Date().toISOString() });
  const account = Object.assign(accounts.get(key), identity); // profile fields are a copy, refreshed on every login
  console.log(`${isNew ? "🆕" : "👋"} ${provider.label}: ${identity.name} → ${account.id} (id ${identity.providerUserId})` +
    (identity.email ? `, email ${identity.email} ${identity.emailVerified ? "✅ verified" : "⚠️ NOT verified: never use it to match accounts"}` : ", no email"));

  sessions.delete(sid); // new session id after login (topic 50)
  const newSid = randomToken();
  sessions.set(newSid, { pending: new Map(), accountKey: key });
  res.set("Set-Cookie", `pk_sid=${newSid}; HttpOnly; SameSite=Lax; Path=/`);
  res.redirect(303, "/me");
});

app.get("/me", (req, res) => {
  const { s } = session(req, res);
  const account = s.accountKey && accounts.get(s.accountKey);
  if (!account) return res.status(401).json({ error: "Not logged in. Open / and pick a provider" });
  res.json(account);
});
finish(app);

mock.listen(MOCK_PORT, () => console.log(`🧪 Mock GitHub / Facebook / Microsoft / LinkedIn on ${MOCK_URL}`));
app.listen(APP_PORT, () => console.log(`🖨️  PrintKaro on ${APP_URL}  ← open this one`));
