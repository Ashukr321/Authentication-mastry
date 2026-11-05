const express = require("express");
const crypto = require("crypto");
const assert = require("assert");

const PORT = Number(process.env.PORT) || 3000;
// The "relying party" (RP) = our website. The RP ID is the DOMAIN passkeys are tied to.
// In production: "printkaro.com" (never "www.printkaro.com": then passkeys work on every subdomain).
const RP_ID = "localhost";
const RP_NAME = "PrintKaro";
// The exact page origin the browser will report in clientDataJSON. Fixed, never taken from the Host header.
const ORIGIN = process.env.ORIGIN || `http://localhost:${PORT}`;
const CHALLENGE_TTL_MS = 5 * 60 * 1000;
const SESSION_TTL_MS = 7 * 24 * 60 * 60 * 1000;
const ALGS = { "-7": "ES256", "-257": "RS256" }; // COSE algorithm ids we accept (ES256 = every authenticator, RS256 = older Windows Hello)

// =====================================================================================
// PART 1: Small helpers: base64url and CBOR (the binary JSON that authenticators speak)
// =====================================================================================
const sha256 = (value) => crypto.createHash("sha256").update(value).digest(); // Buffer
const b64u = (buf) => Buffer.from(buf).toString("base64url");
const randomId = () => crypto.randomBytes(32).toString("base64url");

// Throws an error the error handler turns into { error } with this status
const fail = (status, message) => { throw Object.assign(new Error(message), { status, expose: true }); };
function fromB64u(value, what = "value") {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/.test(value)) fail(400, `${what} must be a base64url string`);
  return Buffer.from(value, "base64url");
}

// CBOR decoder (RFC 8949): returns { value, end } so we know where the next thing starts.
// shortcut: only the types WebAuthn uses (ints, bytes, text, arrays, maps, true/false/null). A real app uses a library.
function cborDecode(buf, pos = 0, depth = 0) {
  if (depth > 8) fail(400, "CBOR nested too deep");
  const need = (n) => { if (pos + n > buf.length) fail(400, "CBOR data is cut short"); };
  need(1);
  const head = buf[pos++], major = head >> 5, info = head & 31;
  let n = info;
  if (info === 24) { need(1); n = buf[pos]; pos += 1; }
  else if (info === 25) { need(2); n = buf.readUInt16BE(pos); pos += 2; }
  else if (info === 26) { need(4); n = buf.readUInt32BE(pos); pos += 4; }
  else if (info > 26) fail(400, "CBOR: unsupported length");
  if (major === 0) return { value: n, end: pos };
  if (major === 1) return { value: -1 - n, end: pos };
  if (major === 2 || major === 3) {
    need(n);
    const bytes = buf.subarray(pos, pos + n);
    return { value: major === 2 ? bytes : bytes.toString("utf8"), end: pos + n };
  }
  if (major === 4 || major === 5) {
    const out = major === 4 ? [] : new Map(); // a Map, because COSE keys are numbers like 1, 3, -1
    for (let i = 0; i < n; i++) {
      const k = cborDecode(buf, pos, depth + 1);
      if (major === 4) { out.push(k.value); pos = k.end; continue; }
      const v = cborDecode(buf, k.end, depth + 1);
      out.set(k.value, v.value);
      pos = v.end;
    }
    return { value: out, end: pos };
  }
  if (major === 7 && info >= 20 && info <= 22) return { value: [false, true, null][info - 20], end: pos };
  fail(400, "CBOR: unsupported type");
}

// CBOR encoder: only the virtual authenticator (PART 2) needs it, to build what a real one would send
function cborEncode(v) {
  const head = (major, n) => {
    if (n < 24) return Buffer.from([(major << 5) | n]);
    if (n < 256) return Buffer.from([(major << 5) | 24, n]);
    const b = Buffer.alloc(3); b[0] = (major << 5) | 25; b.writeUInt16BE(n, 1); return b; // up to 65535: plenty here
  };
  if (Number.isInteger(v)) return v >= 0 ? head(0, v) : head(1, -1 - v);
  if (typeof v === "string") { const b = Buffer.from(v); return Buffer.concat([head(3, b.length), b]); }
  if (Buffer.isBuffer(v)) return Buffer.concat([head(2, v.length), v]);
  if (v instanceof Map) return Buffer.concat([head(5, v.size), ...[...v].flatMap(([k, x]) => [cborEncode(k), cborEncode(x)])]);
  throw new Error("cborEncode: unsupported value");
}

// Self-checks: an example from RFC 8949 Appendix A ({"a": 1, "b": [2, 3]}), and a round trip
assert.deepStrictEqual(cborDecode(Buffer.from("a26161016162820203", "hex")).value, new Map([["a", 1], ["b", [2, 3]]]));
const SAMPLE = new Map([[1, 2], [3, -7], [-1, 1], [-2, Buffer.from("xy")], ["fmt", "none"], ["attStmt", new Map()]]);
assert.deepStrictEqual(cborDecode(cborEncode(SAMPLE)).value, SAMPLE);

// =====================================================================================
// PART 2: A pretend authenticator (fingerprint sensor + secure chip), so you can test with curl.
//   curl ...options... | node server.js authenticator phone.json [origin] > credential.json
// The JSON file plays the "device": it holds the private keys. A real one never lets them out.
// =====================================================================================
if (process.argv[2] === "authenticator") {
  const fs = require("fs");
  const [file = "device.json", origin = ORIGIN] = process.argv.slice(3);
  const die = (msg) => { console.error(`❌ ${msg}`); process.exit(1); };
  let options;
  try { options = JSON.parse(fs.readFileSync(0, "utf8")); } catch { die("Pipe the JSON from /register/options or /login/options into me"); }
  if (!options?.challenge) die(`These aren't WebAuthn options: ${JSON.stringify(options)}`);
  const store = fs.existsSync(file) ? JSON.parse(fs.readFileSync(file, "utf8")) : [];
  const isCreate = Boolean(options.rp);
  const rpId = isCreate ? options.rp.id : options.rpId;

  // The BROWSER does this check, not the website: a page may only ask for passkeys of its OWN domain
  // (or a parent domain). A phishing page on printkaro-login.in can't even ask for printkaro.com's passkey.
  const host = new URL(origin).hostname;
  if (host !== rpId && !host.endsWith(`.${rpId}`)) die(`SecurityError: a page on ${host} can't use passkeys for "${rpId}"`);

  // The browser writes clientDataJSON itself, with the REAL origin of the page. The website can't fake it.
  const clientDataJSON = Buffer.from(JSON.stringify({ type: isCreate ? "webauthn.create" : "webauthn.get", challenge: options.challenge, origin, crossOrigin: false }));
  let out;
  if (isCreate) {
    if (!options.pubKeyCredParams.some((p) => p.alg === -7)) die("NotSupportedError: this authenticator only does ES256");
    const excluded = new Set((options.excludeCredentials ?? []).map((c) => c.id));
    if (store.some((c) => excluded.has(c.id))) die("InvalidStateError: this device already has a passkey for this account");
    const { privateKey, publicKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
    const jwk = publicKey.export({ format: "jwk" });
    const credId = crypto.randomBytes(16);
    // The public key in COSE format: 1 (kty) = 2 (EC), 3 (alg) = -7 (ES256), -1 (curve) = 1 (P-256), -2 = x, -3 = y
    const cose = new Map([[1, 2], [3, -7], [-1, 1], [-2, Buffer.from(jwk.x, "base64url")], [-3, Buffer.from(jwk.y, "base64url")]]);
    const idLen = Buffer.alloc(2); idLen.writeUInt16BE(credId.length);
    // authenticatorData = sha256(rpId) | flags 0x45 (UP + UV + AT) | signCount 0 | AAGUID (zeros) | id length | id | public key
    const authData = Buffer.concat([sha256(rpId), Buffer.from([0x45]), Buffer.alloc(4), Buffer.alloc(16), idLen, credId, cborEncode(cose)]);
    store.push({ id: b64u(credId), rpId, userHandle: options.user.id, userName: options.user.name, signCount: 0, privateKey: privateKey.export({ type: "pkcs8", format: "pem" }) });
    console.error(`👆 Fingerprint OK. New passkey for ${options.user.name} on "${rpId}" saved in ${file}`);
    const attestationObject = cborEncode(new Map([["fmt", "none"], ["attStmt", new Map()], ["authData", authData]]));
    out = { id: b64u(credId), rawId: b64u(credId), type: "public-key", authenticatorAttachment: "platform",
      response: { clientDataJSON: b64u(clientDataJSON), attestationObject: b64u(attestationObject), transports: ["internal"] } };
  } else {
    const allowed = new Set((options.allowCredentials ?? []).map((c) => c.id));
    const cred = store.find((c) => c.rpId === rpId && (allowed.size === 0 || allowed.has(c.id)));
    if (!cred) die(`NotAllowedError: no passkey for "${rpId}" on this device`);
    cred.signCount += 1; // like a hardware security key. Synced passkeys (iCloud, Google) always send 0.
    const count = Buffer.alloc(4); count.writeUInt32BE(cred.signCount);
    const authData = Buffer.concat([sha256(rpId), Buffer.from([0x05]), count]); // flags 0x05 = UP + UV
    // THE proof: sign (authenticatorData + sha256(clientDataJSON)) with the private key. Challenge and origin are inside.
    const signature = crypto.sign("sha256", Buffer.concat([authData, sha256(clientDataJSON)]), cred.privateKey);
    console.error(`👆 Fingerprint OK. Signed the challenge as ${cred.userName} (counter ${cred.signCount})`);
    out = { id: cred.id, rawId: cred.id, type: "public-key", authenticatorAttachment: "platform",
      response: { clientDataJSON: b64u(clientDataJSON), authenticatorData: b64u(authData), signature: b64u(signature), userHandle: cred.userHandle } };
  }
  fs.writeFileSync(file, JSON.stringify(store, null, 2));
  console.log(JSON.stringify(out));
  process.exit(0);
}

// =====================================================================================
// PART 3: The website (relying party): register a passkey, sign in with it, manage them
// =====================================================================================

// ---------- "Database" ----------
// shortcut: in-memory Maps, lost on restart. A real app uses database tables.
const users = new Map();       // email -> { id, email, name, userHandle }
const credentials = new Map(); // credentialId -> { id, userId, publicKey (SPKI DER), alg, signCount, transports, backedUp, label, createdAt, lastUsedAt }
const challenges = new Map();  // sha256(challenge) -> { type, expiresAt, ...who it is for }
const sessions = new Map();    // sha256(sid) -> { userId, expiresAt, amr, authAt }
const findUserById = (id) => [...users.values()].find((u) => u.id === id);
const passkeysOf = (user) => [...credentials.values()].filter((c) => c.userId === user.id);

const parseCookies = (req) => Object.fromEntries((req.headers.cookie ?? "").split(";").filter((c) => c.includes("="))
  .map((c) => [c.slice(0, c.indexOf("=")).trim(), c.slice(c.indexOf("=") + 1).trim()]));
// shortcut: no Secure flag because the demo runs on http://localhost. In production (HTTPS) add `secure: true` (topic 10).
const COOKIE = { httpOnly: true, sameSite: "lax", path: "/" };

function currentSession(req) {
  const sid = parseCookies(req).sid;
  const session = sid && sessions.get(b64u(sha256(sid)));
  const user = session && Date.now() <= session.expiresAt && findUserById(session.userId);
  return user ? { session, user } : null;
}
function requireSession(req, res, next) {
  const found = currentSession(req);
  if (!found) return res.status(401).json({ error: "Not signed in" });
  req.session = found.session;
  req.user = found.user;
  next();
}
function startSession(res, user, amr) {
  const sid = randomId(); // always a NEW id after login (no session fixation, topic 50)
  sessions.set(b64u(sha256(sid)), { userId: user.id, expiresAt: Date.now() + SESSION_TTL_MS, amr, authAt: Date.now() });
  res.cookie("sid", sid, { ...COOKIE, maxAge: SESSION_TTL_MS });
}

// A fresh random challenge, stored so it can be used ONCE (no replay)
function newChallenge(record) {
  // shortcut: a cap instead of real rate limiting (topic 16), because anyone can ask for options
  if (challenges.size > 10_000) fail(503, "Too busy, try again soon");
  const challenge = randomId();
  challenges.set(b64u(sha256(challenge)), { ...record, expiresAt: Date.now() + CHALLENGE_TTL_MS });
  return challenge;
}

// 3a / 5a. clientDataJSON: written by the BROWSER. Check type, challenge (and use it up) and origin.
function checkClientData(clientDataB64, type) {
  const raw = fromB64u(clientDataB64, "clientDataJSON");
  let clientData;
  try { clientData = JSON.parse(raw.toString("utf8")); } catch { fail(400, "clientDataJSON is not JSON"); }
  const key = typeof clientData.challenge === "string" && b64u(sha256(clientData.challenge));
  const record = key && challenges.get(key);
  if (record) challenges.delete(key); // single use, even if a check below fails
  if (!record || Date.now() > record.expiresAt || record.type !== type) fail(400, "Challenge expired or already used");
  if (clientData.type !== type) fail(400, `Expected ${type}`);
  // The origin is what makes passkeys phishing-proof: a look-alike site produces a different origin
  if (clientData.origin !== ORIGIN) fail(400, `Wrong origin: expected ${ORIGIN}, got ${String(clientData.origin).slice(0, 100)}`);
  return { raw, record };
}

// 3b / 5b. authenticatorData: written by the AUTHENTICATOR. Bytes, not JSON.
//   [32 bytes sha256(rpId)] [1 byte flags] [4 bytes signCount] [only when registering: AAGUID, credential id, public key]
function parseAuthData(buf) {
  if (buf.length < 37) fail(400, "authenticatorData is too short");
  const flags = buf[32];
  const data = {
    rpIdHash: buf.subarray(0, 32),
    userPresent: Boolean(flags & 0x01),   // UP: someone touched it
    userVerified: Boolean(flags & 0x04),  // UV: fingerprint / face / PIN matched
    backupEligible: Boolean(flags & 0x08), // BE: a passkey that CAN sync (iCloud Keychain, Google Password Manager)
    backedUp: Boolean(flags & 0x10),       // BS: it IS synced right now
    signCount: buf.readUInt32BE(33),
  };
  if (!crypto.timingSafeEqual(data.rpIdHash, sha256(RP_ID))) fail(400, "This passkey was made for another site (rpIdHash)");
  if (!data.userPresent) fail(400, "User presence flag missing");
  if (!data.userVerified) fail(400, "User verification (fingerprint, face or PIN) is required");
  if (flags & 0x40) { // AT: attested credential data follows (registration only)
    if (buf.length < 55) fail(400, "authenticatorData is too short");
    const idLen = buf.readUInt16BE(53);
    if (55 + idLen > buf.length) fail(400, "authenticatorData is too short");
    data.credentialId = buf.subarray(55, 55 + idLen);
    data.coseKey = cborDecode(buf, 55 + idLen).value;
  }
  return data;
}

// The public key arrives in COSE format (CBOR map). Turn it into a Node KeyObject via JWK.
function coseToPublicKey(cose) {
  if (!(cose instanceof Map)) fail(400, "Public key is not a COSE map");
  const kty = cose.get(1), alg = cose.get(3);
  if (kty === 2 && alg === -7 && cose.get(-1) === 1 && Buffer.isBuffer(cose.get(-2)) && Buffer.isBuffer(cose.get(-3))) {
    return { alg, key: crypto.createPublicKey({ format: "jwk", key: { kty: "EC", crv: "P-256", x: b64u(cose.get(-2)), y: b64u(cose.get(-3)) } }) };
  }
  if (kty === 3 && alg === -257 && Buffer.isBuffer(cose.get(-1)) && Buffer.isBuffer(cose.get(-2))) {
    return { alg, key: crypto.createPublicKey({ format: "jwk", key: { kty: "RSA", n: b64u(cose.get(-1)), e: b64u(cose.get(-2)) } }) };
  }
  fail(400, "Unsupported key: only ES256 and RS256");
}

const label = (req) => String(req.get("user-agent") ?? "unknown device").slice(0, 80);
const publicPasskey = (c) => ({ id: c.id, label: c.label, alg: ALGS[c.alg], synced: c.backedUp, signCount: c.signCount, createdAt: c.createdAt, lastUsedAt: c.lastUsedAt });

// ---------- App ----------
const app = express();
app.use(express.json({ limit: "10kb" })); // JSON only: a cross-site HTML form can't post here
app.use((req, res, next) => { res.set("Cache-Control", "no-store"); next(); });

// 1. REGISTRATION OPTIONS: "please make a key pair for this site and this user"
//    Not signed in → sign up with a passkey (no password at all). Signed in → add another passkey.
app.post("/register/options", (req, res) => {
  const signedIn = currentSession(req);
  let user = signedIn?.user;
  let email, name;
  if (!user) {
    ({ email, name } = req.body ?? {});
    if (typeof email !== "string" || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim()) || email.length > 254) fail(400, "A valid email is required");
    email = email.trim().toLowerCase();
    name = typeof name === "string" && name.trim() ? name.trim().slice(0, 64) : email;
    // shortcut: tells the caller the email is taken (user enumeration, topic 51) and doesn't verify the email (topic 12)
    if (users.has(email)) fail(409, "This email already has an account. Sign in with your passkey, then add a new one.");
  }
  // user.id inside the passkey: random bytes, NOT the email (it's stored on the device and the email can change)
  const userHandle = user ? user.userHandle : b64u(crypto.randomBytes(16));
  const challenge = newChallenge({ type: "webauthn.create", userId: user?.id, email, name, userHandle });
  res.json({
    challenge,
    rp: { id: RP_ID, name: RP_NAME },
    user: { id: userHandle, name: user?.email ?? email, displayName: user?.name ?? name },
    pubKeyCredParams: [{ type: "public-key", alg: -7 }, { type: "public-key", alg: -257 }],
    // residentKey "required" = a DISCOVERABLE credential (a real passkey): login works without typing the email
    authenticatorSelection: { residentKey: "required", userVerification: "required" },
    // Don't make a second passkey on a device that already has one for this account
    excludeCredentials: user ? passkeysOf(user).map((c) => ({ type: "public-key", id: c.id, transports: c.transports })) : [],
    attestation: "none", // we don't need proof of the device model (enterprise apps can ask for "direct")
    timeout: CHALLENGE_TTL_MS,
  });
});

// 3. REGISTRATION VERIFY: check what came back and save the PUBLIC key
app.post("/register/verify", (req, res) => {
  const { id, response } = req.body ?? {};
  const { record } = checkClientData(response?.clientDataJSON, "webauthn.create");

  const attestation = cborDecode(fromB64u(response.attestationObject, "attestationObject")).value;
  if (!(attestation instanceof Map) || !Buffer.isBuffer(attestation.get("authData"))) fail(400, "Bad attestationObject");
  // We asked for attestation "none", so attStmt (fmt "packed", "tpm"...) is ignored: we trust the key, not the device model.
  const authData = parseAuthData(attestation.get("authData"));
  if (!authData.credentialId) fail(400, "No credential in authenticatorData");
  if (b64u(authData.credentialId) !== id) fail(400, "Credential id doesn't match");
  if (credentials.has(id)) fail(409, "This passkey is already registered");
  const { alg, key } = coseToPublicKey(authData.coseKey);

  let user = record.userId && findUserById(record.userId);
  if (!user) {
    if (users.has(record.email)) fail(409, "This email already has an account"); // someone else finished signing up first
    user = { id: crypto.randomUUID(), email: record.email, name: record.name, userHandle: record.userHandle };
    users.set(user.email, user);
  }
  const now = new Date().toISOString();
  const transports = Array.isArray(response.transports) ? response.transports.filter((t) => typeof t === "string").slice(0, 5) : [];
  credentials.set(id, {
    id, userId: user.id, alg, transports, label: label(req), createdAt: now, lastUsedAt: null,
    publicKey: key.export({ type: "spki", format: "der" }), // the ONLY secret-ish thing we store, and it isn't secret
    signCount: authData.signCount, backedUp: authData.backedUp,
  });

  if (!record.userId) startSession(res, user, ["hwk", "mfa"]); // a brand-new account is signed in right away
  res.status(201).json({ message: record.userId ? "Passkey added" : "Account created with a passkey", passkey: publicPasskey(credentials.get(id)) });
});

// 4. LOGIN OPTIONS: just a challenge. No email needed: the device knows which passkeys it has for this site.
app.post("/login/options", (req, res) => {
  res.json({ challenge: newChallenge({ type: "webauthn.get" }), rpId: RP_ID, allowCredentials: [], userVerification: "required", timeout: CHALLENGE_TTL_MS });
});

// 5. LOGIN VERIFY: check the signature with the public key saved at registration
app.post("/login/verify", (req, res) => {
  const { id, response } = req.body ?? {};
  const { raw } = checkClientData(response?.clientDataJSON, "webauthn.get");
  const cred = typeof id === "string" && credentials.get(id);
  if (!cred) fail(401, "Unknown passkey (it was deleted, or it belongs to another site)");
  const user = findUserById(cred.userId);
  if (response.userHandle && response.userHandle !== user.userHandle) fail(401, "This passkey belongs to a different user");

  const authDataBuf = fromB64u(response.authenticatorData, "authenticatorData");
  const authData = parseAuthData(authDataBuf);
  const publicKey = crypto.createPublicKey({ key: cred.publicKey, format: "der", type: "spki" });
  const signedBytes = Buffer.concat([authDataBuf, sha256(raw)]); // the same bytes the authenticator signed
  let valid = false;
  try { valid = crypto.verify("sha256", signedBytes, publicKey, fromB64u(response.signature, "signature")); } catch { /* malformed signature */ }
  if (!valid) fail(401, "Bad signature");

  // signCount: hardware keys count up. If it doesn't go up, two devices may have the same key (a clone).
  // Synced passkeys always send 0, so the check only applies when a counter is in use.
  if ((authData.signCount > 0 || cred.signCount > 0) && authData.signCount <= cred.signCount) {
    console.warn(`⚠️  Possible cloned passkey ${cred.id} for ${user.email}: counter ${authData.signCount} <= ${cred.signCount}`);
    fail(401, "Sign counter went backwards: this passkey may have been cloned");
  }
  cred.signCount = authData.signCount;
  cred.backedUp = authData.backedUp;
  cred.lastUsedAt = new Date().toISOString();

  // amr (RFC 8176): proof of a key (hwk; swk for synced ones) + it counts as MFA because of user verification
  startSession(res, user, [cred.backedUp ? "swk" : "hwk", "mfa"]);
  res.json({ message: `Signed in as ${user.email}`, passkey: cred.label });
});

app.get("/me", requireSession, (req, res) => {
  res.json({ email: req.user.email, name: req.user.name, amr: req.session.amr, authAt: new Date(req.session.authAt).toISOString(), passkeys: passkeysOf(req.user).map(publicPasskey) });
});

// 6. MANAGE PASSKEYS: delete a lost device's passkey, but never the last one (that would lock the account)
app.delete("/passkeys/:id", requireSession, (req, res) => {
  const cred = credentials.get(req.params.id);
  if (!cred || cred.userId !== req.user.id) fail(404, "No such passkey on your account"); // someone else's id → same answer (topic 31)
  if (passkeysOf(req.user).length === 1) fail(409, "This is your only passkey. Add another one first, or you'll be locked out.");
  credentials.delete(cred.id);
  console.log(`\n📧 To: ${req.user.email}\n   Subject: A passkey was removed from your PrintKaro account (${cred.label})\n   Not you? Contact support right away.\n`);
  res.json({ message: "Passkey removed", passkeysLeft: passkeysOf(req.user).length });
});

app.post("/logout", (req, res) => {
  const sid = parseCookies(req).sid;
  if (sid) sessions.delete(b64u(sha256(sid)));
  res.clearCookie("sid", COOKIE);
  res.json({ message: "Logged out" });
});

// A tiny page to try REAL passkeys (Windows Hello, Touch ID, your phone). localhost counts as a secure context.
// shortcut: parseCreationOptionsFromJSON / toJSON need a 2024+ browser. Older ones need manual base64url <-> ArrayBuffer code.
app.get("/", (req, res) => res.type("html").send(`<!doctype html>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>PrintKaro passkeys</title>
<style>body{font:16px system-ui;max-width:640px;margin:2rem auto;padding:0 1rem}input,button{font:inherit;padding:.4rem .7rem;margin:.2rem 0}pre{background:#f3f4f6;padding:1rem;overflow:auto}</style>
<h1>🖨️ PrintKaro passkeys</h1>
<p><input id="email" type="email" placeholder="rahul@mail.com" autocomplete="username webauthn"></p>
<p><button id="signup">Create account with a passkey</button> <button id="login">Sign in with a passkey</button></p>
<p><button id="add">Add another passkey</button> <button id="me">Who am I?</button> <button id="logout">Log out</button></p>
<pre id="out">Ready.</pre>
<script>
const out = document.getElementById("out");
const show = (x) => (out.textContent = JSON.stringify(x, null, 2));
const call = (url, body, method = "POST") => fetch(url, { method, headers: { "Content-Type": "application/json" }, body: body && JSON.stringify(body) }).then((r) => r.json());
async function register() {
  const options = await call("/register/options", { email: document.getElementById("email").value });
  if (options.error) return show(options);
  const credential = await navigator.credentials.create({ publicKey: PublicKeyCredential.parseCreationOptionsFromJSON(options) });
  show(await call("/register/verify", credential.toJSON()));
}
async function login() {
  const options = await call("/login/options", {});
  const credential = await navigator.credentials.get({ publicKey: PublicKeyCredential.parseRequestOptionsFromJSON(options) });
  show(await call("/login/verify", credential.toJSON()));
}
const safe = (fn) => () => fn().catch((e) => show({ error: e.name + ": " + e.message }));
document.getElementById("signup").onclick = safe(register);
document.getElementById("add").onclick = safe(register);
document.getElementById("login").onclick = safe(login);
document.getElementById("me").onclick = safe(async () => show(await call("/me", undefined, "GET")));
document.getElementById("logout").onclick = safe(async () => show(await call("/logout", {})));
</script>`));

app.use((req, res) => res.status(404).json({ error: "Not found" }));

// Errors (bad JSON, body too big, failed checks, bugs) come here. Never send the stack trace to the client.
app.use((err, req, res, next) => {
  if (err.type === "entity.parse.failed") return res.status(400).json({ error: "Body must be valid JSON" });
  if (err.type === "entity.too.large") return res.status(413).json({ error: "Request body too large" });
  if (err.expose && err.status) return res.status(err.status).json({ error: err.message });
  console.error(err);
  res.status(500).json({ error: "Something went wrong" });
});

app.listen(PORT, () => {
  console.log(`🖨️  PrintKaro passkeys on ${ORIGIN}`);
  console.log(`   Open it in a browser to use a real passkey, or follow the curl steps in README.md`);
});

// Every minute, delete expired challenges and sessions
setInterval(() => {
  const now = Date.now();
  for (const [k, c] of challenges) if (now > c.expiresAt) challenges.delete(k);
  for (const [k, s] of sessions) if (now > s.expiresAt) sessions.delete(k);
}, 60_000).unref();
