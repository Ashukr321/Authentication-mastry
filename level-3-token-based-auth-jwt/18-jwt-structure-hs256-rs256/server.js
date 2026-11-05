const express = require("express");
const crypto = require("crypto");
const assert = require("assert");
const jwt = require("jsonwebtoken");

const PORT = Number(process.env.PORT) || 3000;
const BASE_URL = `http://localhost:${PORT}`;
const ISSUER = BASE_URL;          // "iss": who made the token
const AUDIENCE = "demo-api";      // "aud": who the token is for

// ---------- Keys ----------
// shortcut: keys are made fresh at every start, so old tokens die on restart.
// A real app loads them from a secrets manager / env vars (Level 7, topic 54).

// HS256: ONE shared secret. The same secret signs AND verifies, so every verifier could also sign.
const HS_SECRET = crypto.randomBytes(32); // 256 random bits, never a word like "secret"

// RS256: an RSA key pair. Private key signs (only the auth server has it), public key verifies (anyone can have it).
const rsa = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });

// ES256: an elliptic-curve key pair (P-256). Same idea as RS256, but much smaller keys and signatures.
const ec = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });

// Each key has an id ("kid") that goes in the token header, and ONE algorithm it may be used with.
// Pinning the algorithm per key is what stops the "alg: none" and "algorithm confusion" attacks.
const KEYS = {
  "hs-1": { alg: "HS256", signWith: HS_SECRET, verifyWith: HS_SECRET },
  "rs-1": { alg: "RS256", signWith: rsa.privateKey, verifyWith: rsa.publicKey },
  "es-1": { alg: "ES256", signWith: ec.privateKey, verifyWith: ec.publicKey },
};
const KID_FOR_ALG = { HS256: "hs-1", RS256: "rs-1", ES256: "es-1" };

// ---------- JWT helpers ----------
// Step 1: a JWT is three base64url parts joined by dots: header.payload.signature
function splitJwt(token) {
  const parts = typeof token === "string" ? token.split(".") : [];
  if (parts.length !== 3) return null;
  try {
    return {
      header: JSON.parse(Buffer.from(parts[0], "base64url").toString("utf8")),
      payload: JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8")),
      signature: parts[2],
    };
  } catch {
    return null;
  }
}

// Step 3: HS256 by hand. The signature is just HMAC-SHA256("header.payload", secret) in base64url.
// We never use this to verify (the library does it with a timing-safe compare); it's here to show there's no magic.
function hs256SignatureByHand(token, secret) {
  const [header, payload] = token.split(".");
  return crypto.createHmac("sha256", secret).update(`${header}.${payload}`).digest("base64url");
}

function makeToken(alg) {
  const kid = KID_FOR_ALG[alg];
  // Step 2: the payload. Readable by ANYONE who has the token, so no passwords or secrets in here.
  const claims = { name: "Rahul", role: "user" };
  return jwt.sign(claims, KEYS[kid].signWith, {
    algorithm: alg,
    keyid: kid,
    subject: "u_1",      // "sub": who the token is about
    issuer: ISSUER,
    audience: AUDIENCE,
    expiresIn: "15m",    // "exp": short-lived (topic 20)
  });
}

// Step 5: verify. Find the key by "kid", then accept ONLY that key's algorithm.
function verifyToken(token) {
  const parts = splitJwt(token);
  if (!parts) throw new Error("jwt malformed");
  const kid = parts.header?.kid;
  // hasOwn: a kid like "__proto__" must not find a "key" on the object's prototype
  if (typeof kid !== "string" || !Object.hasOwn(KEYS, kid)) throw new Error("unknown key id (kid)");
  const key = KEYS[kid];
  // NEVER trust parts.header.alg to choose the algorithm. The attacker wrote that header.
  return jwt.verify(token, key.verifyWith, { algorithms: [key.alg], issuer: ISSUER, audience: AUDIENCE });
}

// ---------- App ----------
const app = express();
app.use(express.json({ limit: "10kb" }));
app.use((req, res, next) => {
  res.set("Cache-Control", "no-store");
  next();
});

// 1. MAKE a token with the algorithm you pick, and show its three parts.
// shortcut: anyone can get a token here, to keep the topic about the token itself. Topic 19 adds a real login.
app.post("/tokens", (req, res) => {
  const alg = req.body?.alg ?? "HS256";
  if (!KID_FOR_ALG[alg]) return res.status(400).json({ error: "alg must be HS256, RS256 or ES256" });

  const token = makeToken(alg);
  const { header, payload, signature } = splitJwt(token);
  res.status(201).json({
    token,
    header,
    payload,
    signature,
    signatureBytes: Buffer.from(signature, "base64url").length,
    tokenLength: token.length,
  });
});

// 2. DECODE: read a token WITHOUT checking it. Shows that the payload is NOT secret.
app.post("/decode", (req, res) => {
  const parts = splitJwt(req.body?.token);
  if (!parts) return res.status(400).json({ error: "Not a JWT: expected header.payload.signature" });
  res.json({ header: parts.header, payload: parts.payload, warning: "Decoded only, NOT verified. Never trust this for auth." });
});

// 3. VERIFY: check the signature, algorithm, issuer, audience and expiry
app.post("/verify", (req, res) => {
  try {
    const payload = verifyToken(req.body?.token);
    res.json({ valid: true, payload });
  } catch (err) {
    // shortcut: "reason" is shown so you can learn. A real API replies only "Invalid token".
    res.status(401).json({ valid: false, error: "Invalid token", reason: err.message });
  }
});

// 4. JWKS: the PUBLIC keys, so other services can verify RS256/ES256 tokens without being able to make them.
// The HS256 secret is never published: whoever has it can sign tokens.
app.get("/.well-known/jwks.json", (req, res) => {
  const keys = ["rs-1", "es-1"].map((kid) => ({ ...KEYS[kid].verifyWith.export({ format: "jwk" }), kid, alg: KEYS[kid].alg, use: "sig" }));
  res.json({ keys });
});

app.use((req, res) => res.status(404).json({ error: "Not found" }));

// Errors (bad JSON, body too big, bugs) come here. Never send the stack trace to the client.
app.use((err, req, res, next) => {
  if (err.type === "entity.parse.failed") return res.status(400).json({ error: "Body must be valid JSON" });
  if (err.type === "entity.too.large") return res.status(413).json({ error: "Request body too large" });
  console.error(err);
  res.status(500).json({ error: "Something went wrong" });
});

// ---------- Self-check: the attacks from the notes, run at every start ----------
function selfCheck() {
  const rejects = (token) => assert.throws(() => verifyToken(token));
  const hs = makeToken("HS256");
  const [h, p, s] = hs.split(".");
  const b64 = (obj) => Buffer.from(JSON.stringify(obj)).toString("base64url");

  // HS256 really is just HMAC-SHA256 over "header.payload"
  assert.strictEqual(hs256SignatureByHand(hs, HS_SECRET), s);
  // All three algorithms verify
  for (const alg of ["HS256", "RS256", "ES256"]) assert.strictEqual(verifyToken(makeToken(alg)).sub, "u_1");
  // Tampered payload (role: admin) with the old signature → rejected
  rejects(`${h}.${b64({ ...splitJwt(hs).payload, role: "admin" })}.${s}`);
  // "alg": "none" with no signature → rejected
  rejects(`${b64({ alg: "none", typ: "JWT", kid: "hs-1" })}.${p}.`);
  // Algorithm confusion: an HS256 token "signed" with the RSA PUBLIC key, pointing at the RSA kid → rejected
  const pem = rsa.publicKey.export({ type: "spki", format: "pem" });
  const confusedHead = `${b64({ alg: "HS256", typ: "JWT", kid: "rs-1" })}.${p}`;
  rejects(`${confusedHead}.${crypto.createHmac("sha256", pem).update(confusedHead).digest("base64url")}`);
  console.log("✅ Self-check passed: HS256 = HMAC by hand, tampering, alg:none and alg confusion are all rejected");
}
selfCheck();

app.listen(PORT, () => console.log(`JWT structure demo on ${BASE_URL}`));
