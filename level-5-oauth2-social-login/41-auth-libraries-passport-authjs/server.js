const express = require("express");
const crypto = require("crypto");
const session = require("express-session");
const passport = require("passport");
const client = require("openid-client");
const { Strategy: OidcStrategy } = require("openid-client/passport");
const { ExpressAuth, getSession } = require("@auth/express"); // an ES module: Node 22+ can require() it

const APP_PORT = Number(process.env.PORT) || 3000; // PrintKaro, logging in through two libraries
const MOCK_PORT = APP_PORT + 1;                     // KaroID: a small mock OpenID Connect provider
const APP_URL = `http://localhost:${APP_PORT}`;     // URLs from config, never from the Host header
const MOCK_URL = `http://localhost:${MOCK_PORT}`;
const CLIENT_ID = "printkaro";
const CLIENT_SECRET = "karoid-demo-secret"; // shortcut: real secrets come from env / a secret store (topic 54)

// ---------- Shared helpers ----------
const randomToken = (bytes = 32) => crypto.randomBytes(bytes).toString("base64url");
const str = (v) => (typeof v === "string" ? v : undefined); // query/body values can be arrays: accept strings only
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);

function newApp() {
  const app = express();
  app.use(express.json({ limit: "10kb" }));
  app.use(express.urlencoded({ extended: false, limit: "10kb" }));
  app.use((req, res, next) => { res.set("Cache-Control", "no-store"); next(); });
  return app;
}
function finish(app) {
  app.use((req, res) => res.status(404).json({ error: "Not found" }));
  // Errors (bad JSON, body too big, bugs, library errors) come here. Never send the stack trace to the client.
  app.use((err, req, res, next) => {
    if (err.type === "entity.parse.failed") return res.status(400).json({ error: "Body must be valid JSON" });
    if (err.type === "entity.too.large") return res.status(413).json({ error: "Request body too large" });
    console.error(`💥 ${err.name}: ${err.message}`);
    res.status(500).json({ error: "Something went wrong" });
  });
}

// =====================================================================================
// PART 1: KAROID, a mock OpenID Connect provider (a compact version of topic 36's).
// It LOGS what each library sends, so you can see what the library does for you.
// shortcut: no real login page: a link per test user.
// =====================================================================================
const MOCK_USERS = {
  rahul: { sub: "kr_7Hq2LmV9", name: "Rahul Sharma", email: "rahul@example.com", email_verified: true },
  priya: { sub: "kr_P4n8XcQ1", name: "Priya Nair", email: "priya@example.com", email_verified: true },
};
const REDIRECT_URIS = [`${APP_URL}/passport/callback`, `${APP_URL}/auth/callback/karoid`]; // exact matches only
const { privateKey, publicKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
const KID = `karoid-${randomToken(4)}`;
const b64json = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
function signJwt(payload) { // RS256 by hand: header.payload.signature
  const data = `${b64json({ alg: "RS256", typ: "JWT", kid: KID })}.${b64json(payload)}`;
  return `${data}.${crypto.sign("sha256", Buffer.from(data), privateKey).toString("base64url")}`;
}
const mockCodes = new Map();  // code -> { who, redirectUri, nonce, challenge, expiresAt }
const mockTokens = new Map(); // access token -> who
const mock = newApp();

mock.get("/.well-known/openid-configuration", (req, res) => res.json({
  issuer: MOCK_URL,
  authorization_endpoint: `${MOCK_URL}/authorize`,
  token_endpoint: `${MOCK_URL}/token`,
  userinfo_endpoint: `${MOCK_URL}/userinfo`,
  jwks_uri: `${MOCK_URL}/jwks`,
  response_types_supported: ["code"],
  subject_types_supported: ["public"],
  id_token_signing_alg_values_supported: ["RS256"],
  scopes_supported: ["openid", "profile", "email"],
  token_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post"],
  code_challenge_methods_supported: ["S256"], // libraries read this to decide whether to use PKCE
}));
mock.get("/jwks", (req, res) => res.json({ keys: [{ ...publicKey.export({ format: "jwk" }), kid: KID, alg: "RS256", use: "sig" }] }));

mock.get("/authorize", (req, res) => {
  const q = Object.fromEntries(["client_id", "redirect_uri", "response_type", "scope", "state", "nonce", "code_challenge", "code_challenge_method", "mock_user"].map((k) => [k, str(req.query[k])]));
  if (q.client_id !== CLIENT_ID || !REDIRECT_URIS.includes(q.redirect_uri)) return res.status(400).send("Unknown client or redirect_uri. Not redirecting.");
  if (!q.mock_user) {
    const who = q.redirect_uri.includes("/passport/") ? "Passport + openid-client" : "Auth.js";
    const links = Object.keys(MOCK_USERS).map((u) => `<li><a href="${esc(`${req.originalUrl}&mock_user=${u}`)}">Continue as ${esc(u)}</a></li>`).join("");
    return res.send(`<!doctype html><meta charset="utf-8"><title>KaroID</title><body style="font-family:system-ui;max-width:520px;margin:40px auto">
      <h2>🔑 KaroID login</h2><p>Logging in to PrintKaro (via ${esc(who)})</p><ul>${links}</ul>`);
  }
  if (!MOCK_USERS[q.mock_user]) return res.status(400).send("Unknown mock user");
  const via = q.redirect_uri.includes("/passport/") ? "Passport + openid-client" : "Auth.js";
  console.log(`🔎 ${via} sent: scope="${q.scope}", state ${q.state ? "✓" : "✗"}, nonce ${q.nonce ? "✓" : "✗"}, PKCE ${q.code_challenge_method === "S256" ? "✓ S256" : "✗"}`);
  const back = (params) => res.redirect(`${q.redirect_uri}?${new URLSearchParams({ ...params, ...(q.state && { state: q.state }), iss: MOCK_URL })}`);
  if (q.response_type !== "code") return back({ error: "unsupported_response_type" });
  if (q.code_challenge_method !== "S256" || !q.code_challenge) return back({ error: "invalid_request", error_description: "PKCE (S256) required" });
  const code = randomToken();
  mockCodes.set(code, { who: q.mock_user, redirectUri: q.redirect_uri, nonce: q.nonce, challenge: q.code_challenge, expiresAt: Date.now() + 60_000 });
  back({ code });
});

mock.post("/token", (req, res) => {
  // Client authentication: HTTP Basic (client_secret_basic) or form fields (client_secret_post)
  const [scheme, b64] = (req.headers.authorization ?? "").split(" ");
  const [basicId, basicSecret] = scheme === "Basic" && b64 ? Buffer.from(b64, "base64").toString().split(":").map(decodeURIComponent) : [];
  const id = basicId ?? str(req.body?.client_id), secret = basicSecret ?? str(req.body?.client_secret);
  if (id !== CLIENT_ID || secret !== CLIENT_SECRET) return res.status(401).json({ error: "invalid_client" });
  const [grantType, code, redirectUri, verifier] = ["grant_type", "code", "redirect_uri", "code_verifier"].map((k) => str(req.body?.[k]));
  const record = mockCodes.get(code);
  mockCodes.delete(code); // single use
  if (grantType !== "authorization_code" || !record || record.expiresAt < Date.now() || record.redirectUri !== redirectUri) return res.status(400).json({ error: "invalid_grant" });
  if (!verifier || crypto.createHash("sha256").update(verifier).digest("base64url") !== record.challenge) return res.status(400).json({ error: "invalid_grant", error_description: "PKCE verification failed" });
  console.log(`🔎 token request: client auth ${basicId ? "client_secret_basic" : "client_secret_post"}, code_verifier ✓`);
  const accessToken = randomToken();
  mockTokens.set(accessToken, record.who);
  const u = MOCK_USERS[record.who];
  const now = Math.floor(Date.now() / 1000);
  const idToken = signJwt({ iss: MOCK_URL, aud: CLIENT_ID, sub: u.sub, iat: now, exp: now + 300, ...(record.nonce && { nonce: record.nonce }), name: u.name, email: u.email, email_verified: u.email_verified });
  res.json({ access_token: accessToken, token_type: "Bearer", expires_in: 3600, scope: "openid profile email", id_token: idToken });
});
mock.get("/userinfo", (req, res) => {
  const who = mockTokens.get((req.headers.authorization ?? "").replace(/^Bearer /, ""));
  if (!who) return res.status(401).json({ error: "invalid_token" });
  res.json(MOCK_USERS[who]);
});
finish(mock);

// =====================================================================================
// PART 2: YOUR code, the same for any library: the account model from topic 40.
// The library proves WHO it is. Which PrintKaro account that is stays your job.
// shortcut: in-memory Maps, lost on restart. Real apps: users + user_identities tables.
// =====================================================================================
const users = new Map();      // id -> { id, name, email }
const identities = new Map(); // `${provider}|${sub}` -> userId
function findOrCreateUser({ provider, sub, name, email }, via) {
  const key = `${provider}|${sub}`;
  let user = users.get(identities.get(key));
  const isNew = !user;
  if (isNew) {
    user = { id: `acct_${randomToken(4)}`, name: name ?? null, email: email ?? null, createdAt: new Date().toISOString() };
    users.set(user.id, user);
    identities.set(key, user.id);
  }
  console.log(`${isNew ? "🆕" : "👋"} [${via}] ${provider} ${sub} → ${user.id} (${user.name})`);
  return user;
}

// =====================================================================================
// PART 3: PASSPORT.JS + openid-client's strategy, mounted at /passport
// =====================================================================================
async function mountPassport(app) {
  // Step 1: discovery. openid-client reads KaroID's metadata (endpoints, keys, PKCE support).
  // allowInsecureRequests: ONLY because the mock is plain http on localhost. Never in production.
  const config = await client.discovery(new URL(MOCK_URL), CLIENT_ID, CLIENT_SECRET, undefined, { execute: [client.allowInsecureRequests] });

  // Step 2: the strategy. It builds the login URL (PKCE etc.), keeps the pending login in the session,
  // swaps the code and verifies the ID token. Your "verify" function gets the result.
  passport.use("karoid", new OidcStrategy({ config, scope: "openid profile email", callbackURL: `${APP_URL}/passport/callback` },
    (tokens, verified) => {
      const claims = tokens.claims(); // ID token claims, ALREADY checked: signature, iss, aud, exp (and nonce if used)
      verified(null, findOrCreateUser({ provider: "karoid", sub: claims.sub, name: claims.name, email: claims.email }, "Passport"));
    }));
  // Step 3: what goes into the session cookie (just the id) and how to load the user on each request
  passport.serializeUser((user, done) => done(null, user.id));
  passport.deserializeUser((id, done) => done(null, users.get(id) ?? false));

  // Passport needs a server-side session. Cookie limited to /passport so the two demos don't mix.
  app.use("/passport", session({
    name: "pk.sid",
    secret: process.env.SESSION_SECRET ?? randomToken(), // shortcut: set SESSION_SECRET for real; a random one logs everyone out on restart
    resave: false,
    saveUninitialized: false, // no session (and no cookie) until there's something to store
    cookie: { httpOnly: true, sameSite: "lax", secure: false, path: "/passport", maxAge: 8 * 3600_000 }, // secure: true in production (HTTPS)
    // shortcut: the default MemoryStore leaks memory and is single-process. Use Redis/Postgres stores in production.
  }), passport.session());

  app.get("/passport/login", passport.authenticate("karoid"));
  // Passport 0.6+ regenerates the session id on login (session fixation, topic 50)
  app.get("/passport/callback", passport.authenticate("karoid", { successRedirect: "/passport/me", failureRedirect: "/passport/failed" }));
  app.get("/passport/failed", (req, res) => res.status(401).json({ error: "Login failed" }));
  app.get("/passport/me", (req, res) => {
    if (!req.isAuthenticated()) return res.status(401).json({ error: "Not logged in (Passport)" });
    res.json({ via: "Passport", user: req.user });
  });
  app.post("/passport/logout", (req, res, next) => {
    req.logout((err) => { // 0.6+: async, and it also regenerates the session
      if (err) return next(err);
      res.json({ loggedOut: true });
    });
  });
}

// =====================================================================================
// PART 4: AUTH.JS (@auth/express), mounted at /auth
// =====================================================================================
const authConfig = {
  // Encrypts the session cookie (a JWE) and signs the CSRF token. shortcut: set AUTH_SECRET for real.
  secret: process.env.AUTH_SECRET ?? randomToken(),
  // Auth.js builds its URLs (redirect_uri, error pages) from the request's Host / X-Forwarded-Host.
  // trustHost: true is ONLY safe because pinHost() below overwrites those headers with our fixed APP_URL.
  trustHost: true,
  providers: [{
    id: "karoid", name: "KaroID", type: "oidc", // "oidc": Auth.js uses discovery and verifies the ID token
    issuer: MOCK_URL, clientId: CLIENT_ID, clientSecret: CLIENT_SECRET,
    checks: ["pkce", "state", "nonce"], // the default is ["pkce"]; extra checks cost nothing
  }],
  callbacks: {
    // Runs when a JWT session is created/read. `account` + `profile` only exist right after sign-in.
    async jwt({ token, account, profile }) {
      if (account && profile) token.appUserId = findOrCreateUser({ provider: account.provider, sub: profile.sub, name: profile.name, email: profile.email }, "Auth.js").id;
      return token;
    },
    // What /auth/session (and getSession) returns: expose YOUR user id, nothing secret
    async session({ session, token }) {
      session.user.id = token.appUserId;
      return session;
    },
  },
};

const app = newApp();
app.get("/", (req, res) => res.send(`<!doctype html><meta charset="utf-8"><title>PrintKaro</title><body style="font-family:system-ui;max-width:520px;margin:40px auto">
  <h2>🖨️ PrintKaro: two libraries, one provider</h2>
  <p><a href="/passport/login">Log in with KaroID via <b>Passport</b></a> → <a href="/passport/me">/passport/me</a></p>
  <p><a href="/auth/signin">Log in with KaroID via <b>Auth.js</b></a> (its built-in page) → <a href="/authjs/me">/authjs/me</a></p>`));

// Never let a request choose our hostname (a forged Host would put evil.example into redirect URLs)
const pinHost = (req, res, next) => {
  req.headers.host = new URL(APP_URL).host;
  delete req.headers["x-forwarded-host"];
  delete req.headers["x-forwarded-proto"];
  next();
};
app.use("/auth", pinHost, ExpressAuth(authConfig)); // all of /auth/*: signin, callback, signout, session, csrf, providers
app.get("/authjs/me", async (req, res, next) => {
  try {
    const s = await getSession(req, authConfig);
    if (!s?.user) return res.status(401).json({ error: "Not logged in (Auth.js)" });
    res.json({ via: "Auth.js", user: users.get(s.user.id) ?? null, expires: s.expires });
  } catch (e) { next(e); }
});

mock.listen(MOCK_PORT, async () => {
  console.log(`🔑 KaroID (mock OIDC provider) on ${MOCK_URL}`);
  await mountPassport(app); // discovery needs the provider running first
  finish(app);
  app.listen(APP_PORT, () => console.log(`🖨️  PrintKaro on ${APP_URL}  ← open this one`));
});
