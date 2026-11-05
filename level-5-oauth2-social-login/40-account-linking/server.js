const express = require("express");
const crypto = require("crypto");

const APP_PORT = Number(process.env.PORT) || 3000; // PrintKaro: password login + "Log in with ..." + "Connect ..."
const MOCK_PORT = APP_PORT + 1;                     // MOCK Google, GitHub and Microsoft
const APP_URL = `http://localhost:${APP_PORT}`;     // URLs from config, never from the Host header
const MOCK_URL = `http://localhost:${MOCK_PORT}`;
const REAUTH_MS = (Number(process.env.REAUTH_SECONDS) || 300) * 1000; // "recent login" window for linking/unlinking

// ---------- Shared helpers ----------
const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");
const randomToken = (bytes = 32) => crypto.randomBytes(bytes).toString("base64url");
const safeEqual = (a, b) => crypto.timingSafeEqual(Buffer.from(sha256(a)), Buffer.from(sha256(b)));
const str = (v) => (typeof v === "string" ? v : undefined); // body/query values can be arrays or objects: accept strings only
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
const normEmail = (e) => (typeof e === "string" ? e.trim().toLowerCase() : null);
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
// PART 1: MOCK PROVIDERS. Topics 37-39 showed each provider's real answer and how to verify it.
// shortcut: here every mock already returns the NORMALIZED identity (topic 38's adapter output), so we can focus on linking.
// =====================================================================================
const MOCK_SECRET = "mock-demo-secret";
const MOCK_USERS = {
  google: {
    rahul: { sub: "107691503500061507151", name: "Rahul Sharma", email: "rahul@gmail.com", emailVerified: true },
    priya: { sub: "113322190045123987654", name: "Priya Nair", email: "priya@gmail.com", emailVerified: true },
  },
  github: {
    rahul: { sub: "583231", name: "Rahul Sharma", email: "rahul@gmail.com", emailVerified: true },
  },
  microsoft: {
    rahul: { sub: "9188040d-6c67-4c5b-b112-36a304b66dad:00000000-0000-0000-66f3-3332eca7ea81", name: "Rahul Sharma", email: "rahul@gmail.com", emailVerified: false },
    // Vikram's own tenant, email claim set to Rahul's address (nOAuth, topic 38)
    vikram: { sub: "f00dcafe-1111-4222-8333-444455556666:0f1e2d3c-aaaa-4bbb-8ccc-000000000666", name: "Vikram", email: "rahul@gmail.com", emailVerified: false },
  },
};
const mockCodes = new Map();  // code -> { provider, who, redirectUri, expiresAt }
const mockTokens = new Map(); // access token -> { provider, who }
const mock = newApp();

mock.get("/:provider/authorize", (req, res) => {
  const users = MOCK_USERS[req.params.provider];
  const [redirectUri, state, who] = ["redirect_uri", "state", "mock_user"].map((k) => str(req.query[k]));
  if (!users || redirectUri !== `${APP_URL}/callback/${req.params.provider}`) return res.status(400).send("Unknown provider or redirect_uri. Not redirecting.");
  if (!who) {
    const links = Object.keys(users).map((u) => `<li><a href="${esc(`${req.originalUrl}&mock_user=${u}`)}">Continue as ${esc(u)}</a></li>`).join("");
    return res.send(`<!doctype html><meta charset="utf-8"><title>Mock ${esc(req.params.provider)}</title><body style="font-family:system-ui;max-width:520px;margin:40px auto">
      <h2>Mock ${esc(req.params.provider)} login</h2><ul>${links}</ul>`);
  }
  if (!users[who]) return res.status(400).send("Unknown mock user");
  const code = randomToken();
  mockCodes.set(code, { provider: req.params.provider, who, redirectUri, expiresAt: Date.now() + 60_000 });
  res.redirect(`${redirectUri}?${new URLSearchParams({ code, ...(state && { state }) })}`);
});
mock.post("/:provider/token", (req, res) => {
  const [code, secret, redirectUri] = ["code", "client_secret", "redirect_uri"].map((k) => str(req.body?.[k]));
  const record = mockCodes.get(code);
  mockCodes.delete(code);
  if (secret !== MOCK_SECRET || !record || record.provider !== req.params.provider || record.expiresAt < Date.now() || record.redirectUri !== redirectUri) {
    return res.status(400).json({ error: "invalid_grant" });
  }
  const accessToken = randomToken();
  mockTokens.set(accessToken, { provider: record.provider, who: record.who });
  res.json({ access_token: accessToken, token_type: "Bearer" });
});
mock.get("/:provider/userinfo", (req, res) => {
  const t = mockTokens.get((req.headers.authorization ?? "").replace(/^Bearer /, ""));
  if (!t || t.provider !== req.params.provider) return res.status(401).json({ error: "invalid_token" });
  res.json(MOCK_USERS[t.provider][t.who]);
});
finish(mock);

// =====================================================================================
// PART 2: PRINTKARO. One user, many ways in: a password and any number of linked identities.
// =====================================================================================
// trustEmail: do we accept this provider's "email verified" as proof the person owns that inbox?
// Only for providers that really verify, and only for addresses they control. Never for Microsoft's email claim (nOAuth).
const PROVIDERS = {
  google:    { label: "Google",    trustEmail: true },
  github:    { label: "GitHub",    trustEmail: false }, // verifies emails, but we chose not to auto-link on it: proof by password instead
  microsoft: { label: "Microsoft", trustEmail: false },
};

// shortcut: in-memory Maps, lost on restart. Real apps use tables:
//   users(id, email UNIQUE, email_verified, password_hash NULL, name)
//   user_identities(provider, provider_user_id, user_id, email, linked_at)  UNIQUE(provider, provider_user_id)
const users = new Map();      // id -> user
const identities = new Map(); // `${provider}|${providerUserId}` -> { userId, provider, providerUserId, email, emailVerified, linkedAt }
const emailTokens = new Map(); // sha256(token) -> { userId, expiresAt }
const sessions = new Map();   // sid -> { userId, authAt, pending: Map(state -> {...}), pendingLink }
const app = newApp();

// --- Passwords (topic 04): scrypt + timingSafeEqual ---
function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  return `${salt.toString("hex")}:${crypto.scryptSync(password, salt, 64).toString("hex")}`;
}
function checkPassword(password, stored) {
  if (!stored) return false;
  const [salt, hash] = stored.split(":");
  return crypto.timingSafeEqual(crypto.scryptSync(password, Buffer.from(salt, "hex"), 64), Buffer.from(hash, "hex"));
}
const DUMMY_HASH = hashPassword("timing-equalizer"); // so "no such user" takes as long as "wrong password"

const userByEmail = (email) => [...users.values()].find((u) => email && u.email === email); // shortcut: a real DB uses the email index
const identitiesOf = (userId) => [...identities.values()].filter((i) => i.userId === userId);
function createUser({ email, emailVerified, name, passwordHash = null }) {
  const user = { id: `acct_${randomToken(4)}`, email, emailVerified, name, passwordHash, createdAt: new Date().toISOString() };
  users.set(user.id, user);
  return user;
}
function link(user, identity, how) {
  identities.set(`${identity.provider}|${identity.providerUserId}`, { ...identity, userId: user.id, linkedAt: new Date().toISOString() });
  console.log(`🔗 ${PROVIDERS[identity.provider].label} (${identity.providerUserId}) linked to ${user.id} [${how}]`);
  // Always tell the account owner. If it wasn't them, this email is how they find out.
  if (how !== "new account" && user.email && user.emailVerified) console.log(`📧 To: ${user.email}: "${PROVIDERS[identity.provider].label} was connected to your PrintKaro account. Not you? Secure your account."`);
}

// --- Sessions ---
function session(req, res) {
  let sid = parseCookies(req).pk_sid;
  if (!sid || !sessions.has(sid)) {
    sid = randomToken();
    sessions.set(sid, { userId: null, authAt: 0, pending: new Map(), pendingLink: null });
    res.append("Set-Cookie", `pk_sid=${sid}; HttpOnly; SameSite=Lax; Path=/`);
  }
  return { sid, s: sessions.get(sid) };
}
// New session id on every login (topic 50). A pending link survives, because the login is how the user proves ownership.
function logIn(req, res, userId) {
  const { sid, s } = session(req, res);
  sessions.delete(sid);
  const newSid = randomToken();
  sessions.set(newSid, { userId, authAt: Date.now(), pending: new Map(), pendingLink: s.pendingLink });
  res.set("Set-Cookie", `pk_sid=${newSid}; HttpOnly; SameSite=Lax; Path=/`);
  return sessions.get(newSid);
}
const isRecent = (s) => Date.now() - s.authAt < REAUTH_MS;
function me(user) {
  return { id: user.id, name: user.name, email: user.email, emailVerified: user.emailVerified, hasPassword: Boolean(user.passwordHash),
    identities: identitiesOf(user.id).map(({ provider, providerUserId, email, linkedAt }) => ({ provider, providerUserId, email, linkedAt })) };
}

app.get("/", (req, res) => {
  session(req, res);
  const btn = (action, label) => `<form method="post" action="${action}" style="display:inline"><button>${label}</button></form>`;
  res.send(`<!doctype html><meta charset="utf-8"><title>PrintKaro</title><body style="font-family:system-ui;max-width:560px;margin:40px auto">
    <h2>🖨️ PrintKaro</h2>
    <p>Log in with: ${Object.entries(PROVIDERS).map(([k, p]) => btn(`/login/${k}`, esc(p.label))).join(" ")}</p>
    <p>Logged in already? Connect: ${Object.entries(PROVIDERS).map(([k, p]) => btn(`/link/${k}`, esc(p.label))).join(" ")}</p>
    <p><a href="/me">Who am I?</a></p>`);
});

// --- Password accounts (topics 06, 07, 12) ---
app.post("/signup", (req, res) => {
  const email = normEmail(str(req.body?.email)), password = str(req.body?.password), name = str(req.body?.name)?.slice(0, 100);
  if (!email || !/^[^@\s]+@[^@\s]+$/.test(email) || !password || password.length < 8) return res.status(400).json({ error: "Valid email and a password of 8+ characters required" });
  // Same answer whether or not the email is taken (no account enumeration)
  const answer = () => res.status(202).json({ message: "Check your inbox to verify your email" });
  if (userByEmail(email)) { console.log(`📧 To: ${email}: "Someone tried to sign up with your email. If it was you, just log in."`); return answer(); }
  const user = createUser({ email, emailVerified: false, name: name ?? null, passwordHash: hashPassword(password) });
  const token = randomToken();
  emailTokens.set(sha256(token), { userId: user.id, expiresAt: Date.now() + 24 * 3600_000 });
  console.log(`📧 To: ${email}: verify → ${APP_URL}/verify-email?token=${token}`);
  answer();
});
app.get("/verify-email", (req, res) => {
  const token = str(req.query.token);
  const record = token && emailTokens.get(sha256(token));
  if (token) emailTokens.delete(sha256(token));
  const user = record && users.get(record.userId);
  if (!user || record.expiresAt < Date.now() || !user.email) return res.status(400).json({ error: "Invalid or expired link" });
  user.emailVerified = true;
  res.json({ verified: user.email });
});
app.post("/login", (req, res) => {
  const email = normEmail(str(req.body?.email)), password = str(req.body?.password) ?? "";
  const user = userByEmail(email);
  if (!checkPassword(password, user?.passwordHash ?? DUMMY_HASH) || !user?.passwordHash) return res.status(401).json({ error: "Wrong email or password" });
  const s = logIn(req, res, user.id);
  const p = s.pendingLink;
  res.json({ loggedIn: user.id, ...(p && p.userId === user.id && p.expiresAt > Date.now() && {
    pendingLink: `${PROVIDERS[p.identity.provider].label} (${p.identity.email}) wants to connect to this account. POST /link/confirm to connect it.` }) });
});

// --- Step 1: start a provider flow. intent = "login" (logged out) or "link" (logged in, from Settings) ---
function startFlow(intent) {
  return (req, res) => {
    const name = req.params.provider;
    if (!PROVIDERS[name]) return res.status(404).json({ error: "Unknown provider" });
    const { s } = session(req, res);
    if (intent === "link") {
      if (!s.userId) return res.status(401).json({ error: "Log in first, then connect accounts" });
      // Linking adds a new way INTO the account: ask for a recent login, like changing a password (topic 14)
      if (!isRecent(s)) return res.status(401).json({ error: "Please log in again to connect an account (re-authentication required)" });
    }
    const state = randomToken(16);
    // The state remembers the provider, the intent AND which user started a link: a callback can't be replayed into another account
    s.pending.set(state, { provider: name, intent, userId: s.userId, expiresAt: Date.now() + 10 * 60_000 });
    res.redirect(303, `${MOCK_URL}/${name}/authorize?${new URLSearchParams({ response_type: "code", client_id: "printkaro", redirect_uri: `${APP_URL}/callback/${name}`, state })}`);
  };
}
app.post("/login/:provider", startFlow("login"));
// (POST /link/:provider is registered after /link/confirm below, so "confirm" isn't read as a provider name)

// Who is this? (topics 36-38 do the real token checks; the mock hands back the normalized identity)
async function identify(provider, code) {
  const t = await (await fetch(`${MOCK_URL}/${provider}/token`, { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ grant_type: "authorization_code", code, client_id: "printkaro", client_secret: MOCK_SECRET, redirect_uri: `${APP_URL}/callback/${provider}` }) })).json();
  if (!t.access_token) throw new Error(`token exchange: ${t.error}`);
  const u = await (await fetch(`${MOCK_URL}/${provider}/userinfo`, { headers: { Authorization: `Bearer ${t.access_token}` } })).json();
  if (!u.sub) throw new Error("no subject");
  return { provider, providerUserId: u.sub, name: u.name ?? null, email: normEmail(u.email), emailVerified: u.emailVerified === true };
}

// --- Step 2: one callback, two intents ---
app.get("/callback/:provider", async (req, res) => {
  const name = req.params.provider;
  if (!PROVIDERS[name]) return res.status(404).json({ error: "Unknown provider" });
  const { s } = session(req, res);
  const [code, state] = ["code", "state"].map((k) => str(req.query[k]));
  const pending = state ? s.pending.get(state) : null;
  if (state) s.pending.delete(state);
  if (!pending || pending.expiresAt < Date.now() || pending.provider !== name || !code) return res.status(400).json({ error: "This login didn't start here (state mismatch)" });

  let identity;
  try { identity = await identify(name, code); } catch (e) {
    console.log(`🚨 ${PROVIDERS[name].label} failed: ${e.message}`);
    return res.status(400).json({ error: `${PROVIDERS[name].label} login failed` });
  }
  const key = `${name}|${identity.providerUserId}`;
  const existing = identities.get(key);

  // --- Step 3: EXPLICIT linking. The safest kind: the user is logged in and asked for it. ---
  if (pending.intent === "link") {
    // The same user who started it, still logged in (session could have changed in between)
    if (!s.userId || s.userId !== pending.userId) return res.status(400).json({ error: "Session changed during linking. Start again." });
    if (existing && existing.userId !== s.userId) {
      // Never MOVE an identity between accounts: that would hand someone else's login to this account (or the reverse)
      return res.status(409).json({ error: `This ${PROVIDERS[name].label} account is already connected to a different PrintKaro account` });
    }
    if (!existing) link(users.get(s.userId), identity, "explicit, from Settings");
    return res.redirect(303, "/me");
  }

  // --- intent = login ---
  // Step 4: a known identity logs straight into ITS account. Email plays no part.
  if (existing) {
    Object.assign(existing, { email: identity.email, emailVerified: identity.emailVerified }); // profile snapshot, refreshed
    logIn(req, res, existing.userId);
    console.log(`👋 ${PROVIDERS[name].label} → ${existing.userId}`);
    return res.redirect(303, "/me");
  }

  // Step 5: a NEW identity. Is there already an account with this email?
  const owner = userByEmail(identity.email);
  const trusted = PROVIDERS[name].trustEmail && identity.emailVerified; // the provider PROVES this person owns the inbox

  // 5a. Automatic linking: only if BOTH sides proved the same inbox (trusted provider + verified account email)
  if (owner && owner.emailVerified && trusted) {
    link(owner, identity, "automatic: both sides verified the same email");
    logIn(req, res, owner.id);
    return res.redirect(303, "/me");
  }
  // 5b. The account's email is verified, but this provider's claim isn't proof. Make the person prove they own the ACCOUNT.
  if (owner && owner.emailVerified) {
    s.pendingLink = { identity, userId: owner.id, expiresAt: Date.now() + 10 * 60_000 };
    console.log(`⏸️  ${PROVIDERS[name].label} (${identity.providerUserId}) claims ${identity.email}: waiting for the account owner to log in and confirm`);
    // Tradeoff: this says "an account exists". Fine here: the caller already presented that email via a provider.
    return res.status(409).json({ error: "account_exists", message: `An account with ${identity.email} already exists. Log in with your password (POST /login), then POST /link/confirm to connect ${PROVIDERS[name].label}.` });
  }
  // 5c. The account with this email was NEVER verified: whoever made it didn't prove the inbox (maybe an attacker "pre-hijacking").
  //     A trusted, verified provider wins the email; the unverified account loses its claim. NEVER merge into it.
  if (owner && trusted) {
    owner.email = null;
    for (const [k, t] of emailTokens) if (t.userId === owner.id) emailTokens.delete(k); // its old verify links die too
    console.log(`🛡️  Pre-hijack blocked: unverified ${owner.id} loses its claim on ${identity.email}`);
  }
  // 5d. Brand-new account for this identity
  const emailFree = identity.email && !userByEmail(identity.email);
  const user = createUser({ email: emailFree ? identity.email : null, emailVerified: Boolean(emailFree && trusted), name: identity.name });
  link(user, identity, "new account");
  logIn(req, res, user.id);
  res.redirect(303, "/me");
});

// Step 6: finish a pending link, after the owner proved themselves with their password
app.post("/link/confirm", (req, res) => {
  const { s } = session(req, res);
  const p = s.pendingLink;
  s.pendingLink = null; // one try
  if (!s.userId) return res.status(401).json({ error: "Log in first" });
  if (!p || p.expiresAt < Date.now() || p.userId !== s.userId || !isRecent(s)) return res.status(400).json({ error: "Nothing to confirm (expired, or for another account)" });
  if (identities.has(`${p.identity.provider}|${p.identity.providerUserId}`)) return res.status(409).json({ error: "That identity was linked meanwhile" });
  const user = users.get(s.userId);
  link(user, p.identity, "confirmed with password");
  res.json(me(user));
});
app.post("/link/:provider", startFlow("link"));

// Step 7: unlink, but never the last way in
app.delete("/me/identities/:provider", (req, res) => {
  const { s } = session(req, res);
  const user = s.userId && users.get(s.userId);
  if (!user) return res.status(401).json({ error: "Not logged in" });
  if (!isRecent(s)) return res.status(401).json({ error: "Please log in again to disconnect an account (re-authentication required)" });
  const mine = identitiesOf(user.id);
  const toRemove = mine.filter((i) => i.provider === req.params.provider);
  if (!toRemove.length) return res.status(404).json({ error: "Not connected" });
  if (!user.passwordHash && mine.length === toRemove.length) return res.status(400).json({ error: "This is your only way to log in. Set a password or connect another account first." });
  for (const i of toRemove) identities.delete(`${i.provider}|${i.providerUserId}`);
  console.log(`✂️  ${PROVIDERS[req.params.provider]?.label ?? req.params.provider} unlinked from ${user.id}`);
  if (user.email && user.emailVerified) console.log(`📧 To: ${user.email}: "${PROVIDERS[req.params.provider]?.label} was disconnected from your PrintKaro account."`);
  res.json(me(user));
});

app.get("/me", (req, res) => {
  const { s } = session(req, res);
  const user = s.userId && users.get(s.userId);
  if (!user) return res.status(401).json({ error: "Not logged in" });
  res.json(me(user));
});
finish(app);

mock.listen(MOCK_PORT, () => console.log(`🧪 Mock Google / GitHub / Microsoft on ${MOCK_URL}`));
app.listen(APP_PORT, () => console.log(`🖨️  PrintKaro on ${APP_URL}  ← open this one`));
