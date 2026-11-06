const express = require("express");
const crypto = require("crypto");

const PORT = Number(process.env.PORT) || 3000;
const BASE_URL = `http://localhost:${PORT}`;
const ACCESS_TOKEN_TTL_S = 15 * 60; // 15 minutes: also how long an old signing key must keep verifying after a rotation

// ---------- Step 1: secrets come from the environment, and the app refuses to start without them ----------
// Never `const ADMIN_TOKEN = "admin123"` in code: code goes to Git, CI logs, laptops and screenshots.
// ADMIN_TOKENS is a COMMA-SEPARATED list so a shared secret can be rotated with no downtime:
// "old,new" while callers switch over, then just "new" (Step 5).
function requireSecretList(name, minLength = 32) {
  const values = (process.env[name] ?? "").split(",").map((v) => v.trim()).filter(Boolean);
  if (values.length === 0 || values.some((v) => v.length < minLength)) {
    // Fail fast and loud at boot. A server that starts with a missing or weak secret fails later, quietly, in production.
    console.error(`❌ ${name} is missing, or one of its values is shorter than ${minLength} characters. Refusing to start.`);
    process.exit(1);
  }
  return values;
}
// Keep only hashes in memory: they have the same length, so timingSafeEqual can compare them
const ADMIN_TOKEN_HASHES = requireSecretList("ADMIN_TOKENS").map((t) => crypto.createHash("sha256").update(t).digest());

// ---------- "Database" ----------
// shortcut: in-memory Maps, lost on restart. A real app uses database tables.
const users = new Map(); // email -> { email, salt, passwordHash, pan: { keyId, iv, tag, ciphertext } | null }

// ---------- Key rings ----------
// shortcut: keys are generated in this process's memory. A real app keeps them in a KMS or secrets manager
// (AWS KMS / Secrets Manager, GCP KMS, Azure Key Vault, HashiCorp Vault) and never sees the raw key-encryption key.
const signingKeys = new Map(); // kid -> { kid, privateKey, publicKey, createdAt }   (Ed25519, for JWTs)
const dataKeys = new Map();    // id  -> { id, key, createdAt }                     (AES-256-GCM, for data at rest)
let currentSigningKid = null;
let currentDataKeyId = null;
let signingCounter = 0;
let dataCounter = 0;

// Step 3: a new signing key becomes "current" (signs new tokens). The old one stays to VERIFY tokens it already signed.
function rotateSigningKey() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  const kid = `sig-${++signingCounter}`; // real kids are often random or dated; short ones are easier to follow here
  signingKeys.set(kid, { kid, privateKey, publicKey, createdAt: new Date().toISOString() });
  currentSigningKid = kid;
  return kid;
}

// Step 4: a new data key encrypts everything written from now on. Old rows still name the key that can open them.
function rotateDataKey() {
  const id = `data-${++dataCounter}`;
  dataKeys.set(id, { id, key: crypto.randomBytes(32), createdAt: new Date().toISOString() });
  currentDataKeyId = id;
  return id;
}

rotateSigningKey();
rotateDataKey();

// ---------- Helpers ----------
const b64u = (value) => Buffer.from(value).toString("base64url");
const str = (v) => (typeof v === "string" ? v : undefined);
const bearer = (req) => req.get("authorization")?.match(/^Bearer (\S+)$/)?.[1];

// Step 3: every token says WHICH key signed it (the `kid` header), so verification picks the right key from the ring
function signJwt(payload) {
  const key = signingKeys.get(currentSigningKid);
  const data = `${b64u(JSON.stringify({ alg: "EdDSA", typ: "JWT", kid: key.kid }))}.${b64u(JSON.stringify(payload))}`;
  return `${data}.${b64u(crypto.sign(null, Buffer.from(data), key.privateKey))}`;
}

function verifyJwt(token) {
  const parts = token.split(".");
  if (parts.length !== 3) return { error: "Malformed token" };
  let header, payload;
  try {
    header = JSON.parse(Buffer.from(parts[0], "base64url"));
    payload = JSON.parse(Buffer.from(parts[1], "base64url"));
  } catch {
    return { error: "Malformed token" };
  }
  if (header.alg !== "EdDSA") return { error: "Unexpected alg" }; // never let the token choose the algorithm (topic 53)
  // The kid only SELECTS a key from OUR ring. It's never a file path, URL or SQL value (topic 53).
  const key = typeof header.kid === "string" ? signingKeys.get(header.kid) : undefined;
  if (!key) return { error: `Unknown or retired signing key: ${header.kid}` };
  const ok = crypto.verify(null, Buffer.from(`${parts[0]}.${parts[1]}`), key.publicKey, Buffer.from(parts[2], "base64url"));
  if (!ok) return { error: "Bad signature" };
  if (typeof payload.exp !== "number" || Date.now() / 1000 > payload.exp) return { error: "Token expired" };
  return { payload, kid: key.kid };
}

// Step 4: AES-256-GCM. The record stores the key ID next to the ciphertext, so rotation never needs a guess.
function encrypt(plaintext, aad) {
  const key = dataKeys.get(currentDataKeyId);
  const iv = crypto.randomBytes(12); // GCM: a fresh 12-byte IV every time, never reused with the same key
  const cipher = crypto.createCipheriv("aes-256-gcm", key.key, iv);
  cipher.setAAD(Buffer.from(aad)); // binds the ciphertext to its row: Rahul's PAN can't be copied into Vikram's row
  const ciphertext = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  return { keyId: key.id, iv: iv.toString("base64"), tag: cipher.getAuthTag().toString("base64"), ciphertext: ciphertext.toString("base64") };
}

function decrypt(record, aad) {
  const key = dataKeys.get(record.keyId);
  if (!key) throw new Error(`Data key ${record.keyId} is gone`); // can't happen: retiring a key in use is refused
  const decipher = crypto.createDecipheriv("aes-256-gcm", key.key, Buffer.from(record.iv, "base64"));
  decipher.setAAD(Buffer.from(aad));
  decipher.setAuthTag(Buffer.from(record.tag, "base64")); // GCM throws if a single bit was changed
  return Buffer.concat([decipher.update(Buffer.from(record.ciphertext, "base64")), decipher.final()]).toString("utf8");
}

const rowsUsingDataKey = (id) => [...users.values()].filter((u) => u.pan?.keyId === id).length;

// Step 2: logs are a classic leak. Mask anything that looks like a secret before it's printed.
// shortcut: shallow, key-name based. A real app uses its logger's redaction (pino `redact`, winston formats).
const SENSITIVE = /pass|token|secret|key|authorization|cookie|pan/i;
const redact = (obj) => Object.fromEntries(Object.entries(obj ?? {}).map(([k, v]) => [k, SENSITIVE.test(k) ? "[REDACTED]" : v]));

const DUMMY_SALT = crypto.randomBytes(16);
// shortcut: test accounts with known passwords. A real app has a signup (topic 06).
for (const [email, password] of [["rahul@mail.com", "chai-and-code-42"], ["priya@mail.com", "masala-dosa-77"]]) {
  const salt = crypto.randomBytes(16);
  users.set(email, { email, salt, passwordHash: crypto.scryptSync(password, salt, 64), pan: null });
}

// ---------- App ----------
const app = express();
app.use(express.json({ limit: "10kb" }));
app.use((req, res, next) => {
  res.set("Cache-Control", "no-store");
  const auth = req.get("authorization") ? " auth=[REDACTED]" : "";
  console.log(`→ ${req.method} ${req.path} ${JSON.stringify(redact(req.body))}${auth}`);
  next();
});

function requireUser(req, res, next) {
  const token = bearer(req);
  if (!token) return res.status(401).json({ error: "Missing Bearer token" });
  const result = verifyJwt(token);
  // shortcut: the reason is sent back so you can learn from it. A real API answers just "Invalid token".
  if (result.error) return res.status(401).json({ error: "Invalid token", reason: result.error });
  req.user = users.get(result.payload.sub);
  req.kid = result.kid;
  if (!req.user) return res.status(401).json({ error: "Invalid token" });
  next();
}

function requireAdmin(req, res, next) {
  const token = bearer(req);
  const hash = token && crypto.createHash("sha256").update(token).digest();
  if (!hash || !ADMIN_TOKEN_HASHES.some((h) => crypto.timingSafeEqual(h, hash))) return res.status(401).json({ error: "Admin token required" });
  next();
}

app.post("/login", (req, res) => {
  const email = str(req.body?.email)?.trim().toLowerCase();
  const user = email ? users.get(email) : undefined;
  // Hash even for unknown emails so the response time doesn't reveal who has an account (topic 51)
  const hash = crypto.scryptSync(str(req.body?.password) ?? "", user?.salt ?? DUMMY_SALT, 64);
  if (!user || !crypto.timingSafeEqual(hash, user.passwordHash)) return res.status(401).json({ error: "Wrong email or password" });
  const now = Math.floor(Date.now() / 1000);
  const accessToken = signJwt({ sub: user.email, iat: now, exp: now + ACCESS_TOKEN_TTL_S, iss: BASE_URL });
  res.json({ accessToken, signedWith: currentSigningKid, expiresIn: ACCESS_TOKEN_TTL_S });
});

app.get("/api/me", requireUser, (req, res) => {
  res.json({ email: req.user.email, tokenSignedWith: req.kid, currentSigningKey: currentSigningKid });
});

// Step 3: other services verify our tokens with PUBLIC keys from here. They never get a private key.
app.get("/.well-known/jwks.json", (req, res) => {
  res.set("Cache-Control", "public, max-age=300"); // verifiers cache this, which is why a new key must be published early
  res.json({
    keys: [...signingKeys.values()].map((k) => ({ ...k.publicKey.export({ format: "jwk" }), kid: k.kid, use: "sig", alg: "EdDSA" })),
  });
});

// Step 4: a sensitive field, encrypted before it's stored
app.put("/api/me/pan", requireUser, (req, res) => {
  const pan = str(req.body?.pan)?.trim().toUpperCase();
  if (!pan || !/^[A-Z]{5}[0-9]{4}[A-Z]$/.test(pan)) return res.status(400).json({ error: "PAN must look like ABCDE1234F" });
  req.user.pan = encrypt(pan, req.user.email);
  // This is what the database row holds: no PAN, just a key ID and ciphertext
  console.log(`💾 users[${req.user.email}].pan = ${JSON.stringify(req.user.pan)}`);
  res.json({ message: "PAN saved, encrypted", encryptedWith: req.user.pan.keyId });
});

app.get("/api/me/pan", requireUser, (req, res) => {
  if (!req.user.pan) return res.status(404).json({ error: "No PAN saved" });
  const pan = decrypt(req.user.pan, req.user.email);
  res.json({ pan: `******${pan.slice(-4)}`, encryptedWith: req.user.pan.keyId }); // show only what the screen needs
});

// ---------- Admin: key rotation (protected by ADMIN_TOKENS) ----------
// Key status only. Key MATERIAL never leaves the server, not even to an admin.
app.get("/admin/keys", requireAdmin, (req, res) => {
  res.json({
    signingKeys: [...signingKeys.values()].map((k) => ({ kid: k.kid, status: k.kid === currentSigningKid ? "current" : "verify-only", createdAt: k.createdAt })),
    dataKeys: [...dataKeys.values()].map((k) => ({ id: k.id, status: k.id === currentDataKeyId ? "current" : "decrypt-only", rows: rowsUsingDataKey(k.id), createdAt: k.createdAt })),
  });
});

app.post("/admin/signing-keys/rotate", requireAdmin, (req, res) => {
  const previous = currentSigningKid;
  const kid = rotateSigningKey();
  console.log(`🔄 Signing key rotated: ${previous} → ${kid}`);
  res.json({ message: `New tokens are signed with ${kid}. ${previous} still verifies old tokens until you retire it.`, current: kid });
});

// Planned: retire once the old key's tokens have expired (ACCESS_TOKEN_TTL_S after rotation).
// Emergency (the key leaked): retire NOW, and every token it signed stops working, attacker's and users' alike.
app.delete("/admin/signing-keys/:kid", requireAdmin, (req, res) => {
  const { kid } = req.params;
  if (!signingKeys.has(kid)) return res.status(404).json({ error: "No such signing key" });
  if (kid === currentSigningKid) return res.status(409).json({ error: "That's the current key. Rotate first, then retire it." });
  signingKeys.delete(kid);
  console.log(`🗑️  Signing key ${kid} retired`);
  res.json({ message: `${kid} retired. Tokens it signed are now rejected.` });
});

app.post("/admin/data-keys/rotate", requireAdmin, (req, res) => {
  const previous = currentDataKeyId;
  const id = rotateDataKey();
  console.log(`🔄 Data key rotated: ${previous} → ${id}`);
  res.json({ message: `New writes use ${id}. ${rowsUsingDataKey(previous)} row(s) still use ${previous} until re-encrypted.`, current: id });
});

// Step 4: the re-encryption job. Decrypt with the old key, encrypt with the current one, row by row.
// shortcut: one loop in memory. A real job runs in batches, is restartable, and only moves rows WHERE key_id != current.
app.post("/admin/data-keys/reencrypt", requireAdmin, (req, res) => {
  let moved = 0;
  for (const user of users.values()) {
    if (!user.pan || user.pan.keyId === currentDataKeyId) continue;
    user.pan = encrypt(decrypt(user.pan, user.email), user.email);
    moved++;
  }
  console.log(`🔁 Re-encrypted ${moved} row(s) with ${currentDataKeyId}`);
  res.json({ message: `Re-encrypted ${moved} row(s) with ${currentDataKeyId}` });
});

app.delete("/admin/data-keys/:id", requireAdmin, (req, res) => {
  const { id } = req.params;
  if (!dataKeys.has(id)) return res.status(404).json({ error: "No such data key" });
  if (id === currentDataKeyId) return res.status(409).json({ error: "That's the current key. Rotate first, then retire it." });
  // Deleting a data key that still has rows = that data is unreadable FOREVER. Refuse.
  const rows = rowsUsingDataKey(id);
  if (rows > 0) return res.status(409).json({ error: `${rows} row(s) are still encrypted with ${id}. Re-encrypt them first, or that data is lost.` });
  dataKeys.delete(id);
  console.log(`🗑️  Data key ${id} retired`);
  res.json({ message: `${id} retired. No data used it.` });
});

app.use((req, res) => res.status(404).json({ error: "Not found" }));

// Errors (bad JSON, body too big, bugs) come here. Never send the stack trace to the client.
app.use((err, req, res, next) => {
  if (err.type === "entity.parse.failed") return res.status(400).json({ error: "Body must be valid JSON" });
  if (err.type === "entity.too.large") return res.status(413).json({ error: "Request body too large" });
  console.error(err.message); // the message, not the whole object: error objects can carry request data and secrets
  res.status(500).json({ error: "Something went wrong" });
});

app.listen(PORT, () => {
  console.log(`💳 PaisaVault on ${BASE_URL}`);
  console.log(`🔑 Signing key ${currentSigningKid} and data key ${currentDataKeyId} ready. ${ADMIN_TOKEN_HASHES.length} admin token(s) loaded (values never logged).`);
});
