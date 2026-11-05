const express = require("express");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");

const PORT = Number(process.env.PORT) || 3000;
const ISSUER = "https://auth.example.com"; // who is allowed to create tokens for us
const AUDIENCE = "orders-api";             // this API's name: tokens must be made FOR us
const ACCESS_TYP = "at+jwt";               // header "typ" for access tokens (RFC 9068)
const CLOCK_TOLERANCE_SECONDS = 30;        // small allowance for clock differences between servers
const MAX_TOKEN_AGE = "1h";                // reject tokens issued more than 1 h ago, whatever their exp says

// RS256 (topic 18): the auth server signs with the PRIVATE key, APIs verify with the PUBLIC key.
// shortcut: a new key pair on every start, and both halves in one process. In real life the private key
// lives only on the auth server, and APIs fetch the public key from its JWKS URL (Level 5).
const { privateKey: PRIVATE_KEY, publicKey: PUBLIC_KEY } = crypto.generateKeyPairSync("rsa", {
  modulusLength: 2048,
  publicKeyEncoding: { type: "spki", format: "pem" },
  privateKeyEncoding: { type: "pkcs8", format: "pem" },
});

const now = () => Math.floor(Date.now() / 1000);
const b64url = (obj) => Buffer.from(JSON.stringify(obj)).toString("base64url");

// ---------- THE VALIDATOR: every check an API should make before trusting a JWT ----------
class ClaimError extends Error {}

function verifyAccessToken(token) {
  // Steps 1–4 are done by the library when you GIVE it the options. Leave one out and that check silently doesn't happen.
  const { header, payload } = jwt.verify(token, PUBLIC_KEY, {
    algorithms: ["RS256"],                   // 1. pin the algorithm: blocks "none" and HS256-signed-with-our-public-key
    issuer: ISSUER,                          // 2. iss: made by OUR auth server (not staging, not another tenant)
    audience: AUDIENCE,                      // 2. aud: made for THIS API (not for reports-api)
    clockTolerance: CLOCK_TOLERANCE_SECONDS, // 3. exp and nbf, with a little clock skew allowed
    maxAge: MAX_TOKEN_AGE,                   // 3. iat: not too old
    complete: true,                          // also return the header, for step 4
  });
  // 4. typ: an ACCESS token, not a refresh token or an ID token that happens to be signed by the same key
  if (header.typ !== ACCESS_TYP) throw new ClaimError(`wrong token type: typ is "${header.typ}", expected "${ACCESS_TYP}"`);
  // 3. iat in the future = a broken or forged clock. The library doesn't check this one.
  if (typeof payload.iat !== "number" || payload.iat > now() + CLOCK_TOLERANCE_SECONDS) throw new ClaimError("iat is missing or in the future");
  // 5. Required claims our code relies on
  if (typeof payload.sub !== "string" || payload.sub.length === 0) throw new ClaimError("sub (the user id) is missing");
  return payload;
}

// ---------- App ----------
const app = express();
app.use(express.json({ limit: "10kb" }));
app.use((req, res, next) => { res.set("Cache-Control", "no-store"); next(); });

function requireAuth(req, res, next) {
  const [scheme, token] = (req.headers.authorization ?? "").split(" ");
  if (scheme !== "Bearer" || !token) return res.status(401).json({ error: "Missing access token" });
  try {
    req.auth = verifyAccessToken(token);
    next();
  } catch (err) {
    // Step 6: the client gets ONE generic message. The exact reason goes to the server log only.
    // (This demo also returns it as "debugReason" outside production, so you can see which check fired.)
    console.log(`❌ rejected token: ${err.message}`);
    res.set("WWW-Authenticate", 'Bearer error="invalid_token"');
    res.status(401).json({ error: "Invalid access token", ...(process.env.NODE_ENV !== "production" && { debugReason: err.message }) });
  }
}

app.get("/orders", requireAuth, (req, res) => {
  res.json({ user: req.auth.sub, orders: [{ id: "ord_1", item: "Masala chai (500 g)", total: "₹240" }] });
});

// ---------- TOKEN LAB: makes tokens with exactly ONE thing wrong ----------
// shortcut: a dev-only route so the demo needs one process. NEVER ship an endpoint that mints tokens on request.
const good = () => ({ iss: ISSUER, aud: AUDIENCE, sub: "u_rahul", iat: now(), exp: now() + 900, jti: crypto.randomUUID() });
const sign = (payload, typ = ACCESS_TYP) => jwt.sign(payload, PRIVATE_KEY, { algorithm: "RS256", header: { typ } }); // keeps our own iat

const LAB = {
  "valid":               ["Nothing. Should be accepted", () => sign(good())],
  "expired-10s-ago":     ["exp was 10 s ago, inside the 30 s clock tolerance: accepted", () => sign({ ...good(), iat: now() - 900, exp: now() - 10 })],
  "expired":             ["exp was 5 minutes ago", () => sign({ ...good(), iat: now() - 1200, exp: now() - 300 })],
  "not-yet-valid":       ["nbf is 10 minutes from now", () => sign({ ...good(), nbf: now() + 600 })],
  "issued-in-future":    ["iat is 10 minutes from now", () => sign({ ...good(), iat: now() + 600, exp: now() + 1500 })],
  "too-old":             ["iat was 2 hours ago, even though exp is still in the future", () => sign({ ...good(), iat: now() - 7200, exp: now() + 3600 })],
  "wrong-audience":      ["aud is reports-api: a token made for another API", () => sign({ ...good(), aud: "reports-api" })],
  "wrong-issuer":        ["iss is the staging auth server", () => sign({ ...good(), iss: "https://auth-staging.example.com" })],
  "refresh-as-access":   ["typ says it's a refresh token, not an access token", () => sign(good(), "refresh+jwt")],
  "missing-sub":         ["No sub claim: who is this?", () => { const { sub, ...rest } = good(); return sign(rest); }],
  "tampered":            ["Payload edited after signing (sub changed to u_admin)", () => {
    const [h, , s] = sign(good()).split(".");
    return `${h}.${b64url({ ...good(), sub: "u_admin" })}.${s}`;
  }],
  "alg-none":            ['alg is "none" and there is no signature at all', () =>
    `${b64url({ alg: "none", typ: ACCESS_TYP })}.${b64url({ ...good(), sub: "u_admin" })}.`],
  "hs256-with-public-key": ["Algorithm confusion: HS256, using our PUBLIC key as the HMAC secret", () => {
    const unsigned = `${b64url({ alg: "HS256", typ: ACCESS_TYP })}.${b64url({ ...good(), sub: "u_admin" })}`;
    return `${unsigned}.${crypto.createHmac("sha256", PUBLIC_KEY).update(unsigned).digest("base64url")}`;
  }],
};

app.get("/lab/cases", (req, res) => res.json(Object.fromEntries(Object.entries(LAB).map(([name, [what]]) => [name, what]))));

app.get("/lab/token/:case", (req, res) => {
  const entry = LAB[req.params.case];
  if (!entry) return res.status(404).json({ error: "Unknown case. See GET /lab/cases" });
  res.json({ case: req.params.case, whatIsWrong: entry[0], token: entry[1]() });
});

// The public key is public: APIs and attackers alike can have it (normally served as JWKS)
app.get("/public-key.pem", (req, res) => res.type("text/plain").send(PUBLIC_KEY));

app.use((req, res) => res.status(404).json({ error: "Not found" }));

// Errors (bad JSON, body too big, bugs) come here. Never send the stack trace to the client.
app.use((err, req, res, next) => {
  if (err.type === "entity.parse.failed") return res.status(400).json({ error: "Body must be valid JSON" });
  if (err.type === "entity.too.large") return res.status(413).json({ error: "Request body too large" });
  console.error(err);
  res.status(500).json({ error: "Something went wrong" });
});

app.listen(PORT, () => console.log(`JWT claims validation lab on http://localhost:${PORT} (iss ${ISSUER}, aud ${AUDIENCE})`));
