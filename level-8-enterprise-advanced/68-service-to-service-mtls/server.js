const express = require("express");
const crypto = require("crypto");
const https = require("https");
const tls = require("tls");
const fs = require("fs");
const path = require("path");
const assert = require("assert");

// Three servers in one file, so the demo runs with a single `node server.js`:
//   PORT     orders-service    plain HTTP, the CALLER. You curl this one.
//   PORT + 1 payments-service HTTPS + mTLS, the service being called.
//   PORT + 2 impostor         a server pretending to be payments (to show the client checking the server).
// shortcut: in real life each service is its own process/pod with its own key, and the key never leaves it.
const PORT = Number(process.env.PORT) || 3000;
const PAYMENTS_PORT = PORT + 1;
const IMPOSTOR_PORT = PORT + 2;
const BASE_URL = `http://localhost:${PORT}`;
const TRUST_DOMAIN = "spiffe://chaipay.internal"; // every service's id looks like spiffe://chaipay.internal/<name>
const CERT_DIR = path.join(__dirname, "certs");

// ============================================================================================
// STEP 1: give every service an identity. Our own tiny internal CA issues short-lived certificates.
// Real life: HashiCorp Vault PKI, SPIRE, cert-manager, AWS Private CA, or the service mesh (Istio/Linkerd) does this.
// Node can READ certificates (crypto.X509Certificate) but can't CREATE them, so we build the X.509 DER by hand.
// You don't need to learn this part: openssl does the same in one command (see README).
// ============================================================================================
function der(tag, ...parts) {
  const body = Buffer.concat(parts);
  let len = Buffer.from([body.length]);
  if (body.length >= 128) {
    const bytes = [];
    for (let n = body.length; n > 0; n >>= 8) bytes.unshift(n & 0xff);
    len = Buffer.from([0x80 | bytes.length, ...bytes]);
  }
  return Buffer.concat([Buffer.from([tag]), len, body]);
}
const seq = (...parts) => der(0x30, ...parts);
const set = (...parts) => der(0x31, ...parts);
const int = (buf) => der(0x02, buf);
const utf8 = (s) => der(0x0c, Buffer.from(s));
const bool = () => der(0x01, Buffer.from([0xff])); // TRUE
const utcTime = (ms) => der(0x17, Buffer.from(new Date(ms).toISOString().replace(/[-:T]/g, "").slice(2, 14) + "Z"));
function oid(dotted) {
  const [a, b, ...rest] = dotted.split(".").map(Number);
  const out = [40 * a + b];
  for (const v of rest) {
    const bytes = [v & 0x7f];
    for (let x = v >> 7; x > 0; x >>= 7) bytes.unshift(0x80 | (x & 0x7f));
    out.push(...bytes);
  }
  return der(0x06, Buffer.from(out));
}
const ECDSA_SHA256 = seq(oid("1.2.840.10045.4.3.2"));
const dn = (cn) => seq(set(seq(oid("2.5.4.10"), utf8("ChaiPay"))), set(seq(oid("2.5.4.3"), utf8(cn)))); // O=ChaiPay, CN=…
const ext = (id, critical, value) => seq(oid(id), ...(critical ? [bool()] : []), der(0x04, value));
const toPem = (buf) => `-----BEGIN CERTIFICATE-----\n${buf.toString("base64").match(/.{1,64}/g).join("\n")}\n-----END CERTIFICATE-----\n`;

function issueCert({ cn, issuer = null, isCA = false, spiffeId = null, from = Date.now() - 60_000, hours = 24 }) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  const signer = issuer ?? { cn, privateKey }; // no issuer = self-signed (a root CA)
  const serial = crypto.randomBytes(16);
  serial[0] = (serial[0] & 0x7f) | 0x01; // positive, no leading zero byte

  const extensions = isCA
    ? [
        ext("2.5.29.19", true, seq(bool())),                      // basicConstraints: CA:TRUE
        ext("2.5.29.15", true, der(0x03, Buffer.from([1, 0x06]))), // keyUsage: keyCertSign, cRLSign
      ]
    : [
        ext("2.5.29.19", true, seq()),                             // basicConstraints: CA:FALSE (can't sign other certs)
        ext("2.5.29.15", true, der(0x03, Buffer.from([7, 0x80]))), // keyUsage: digitalSignature
        // extKeyUsage: serverAuth + clientAuth. A service is a server AND a client, like a SPIFFE X.509-SVID.
        ext("2.5.29.37", false, seq(oid("1.3.6.1.5.5.7.3.1"), oid("1.3.6.1.5.5.7.3.2"))),
        // subjectAltName: DNS:localhost, IP:127.0.0.1 (so it can serve on this laptop) and the SPIFFE ID (WHO it is)
        ext("2.5.29.17", false, seq(der(0x82, Buffer.from("localhost")), der(0x87, Buffer.from([127, 0, 0, 1])), der(0x86, Buffer.from(spiffeId)))),
      ];

  const tbs = seq(
    der(0xa0, int(Buffer.from([2]))), // X.509 v3
    int(serial),
    ECDSA_SHA256,
    dn(signer.cn),                    // issuer
    seq(utcTime(from), utcTime(from + hours * 3600_000)),
    dn(cn),                           // subject
    publicKey.export({ type: "spki", format: "der" }),
    der(0xa3, seq(...extensions)),
  );
  const signature = crypto.sign("sha256", tbs, signer.privateKey); // the CA's signature is what makes the cert trustworthy
  return {
    cn,
    spiffeId,
    privateKey,
    keyPem: privateKey.export({ type: "pkcs8", format: "pem" }),
    certPem: toPem(seq(tbs, ECDSA_SHA256, der(0x03, Buffer.from([0]), signature))),
  };
}

// A NEW CA on every start. shortcut: a real CA key lives in an HSM or Vault and is never regenerated or written to disk.
const CA = issueCert({ cn: "ChaiPay Internal CA", isCA: true, hours: 24 * 365 });
// An attacker's CA with the SAME name but a different key. Copying the name is easy; copying the key is not.
const ROGUE_CA = issueCert({ cn: "ChaiPay Internal CA", isCA: true, hours: 24 * 365 });

const id = (name) => `${TRUST_DOMAIN}/${name}`;
// Short-lived (24 h) certs. Expiry IS the revocation plan: a stolen key is useless by tomorrow (Step 5).
const certs = {
  payments: issueCert({ cn: "payments", issuer: CA, spiffeId: id("payments") }),
  orders: issueCert({ cn: "orders", issuer: CA, spiffeId: id("orders") }),
  analytics: issueCert({ cn: "analytics", issuer: CA, spiffeId: id("analytics") }),
  // An old orders cert that expired yesterday (someone found it in a backup)
  "orders-expired": issueCert({ cn: "orders", issuer: CA, spiffeId: id("orders"), from: Date.now() - 48 * 3600_000, hours: 24 }),
  // A cert that SAYS it's orders, signed by the rogue CA
  "orders-rogue": issueCert({ cn: "orders", issuer: ROGUE_CA, spiffeId: id("orders") }),
};

// Self-check: our certs verify against the CA key, the rogue one doesn't, and Node parses the SPIFFE ID back out
{
  const caKey = new crypto.X509Certificate(CA.certPem).publicKey;
  const orders = new crypto.X509Certificate(certs.orders.certPem);
  assert(orders.verify(caKey) && orders.checkIssued(new crypto.X509Certificate(CA.certPem)));
  assert(!new crypto.X509Certificate(certs["orders-rogue"].certPem).verify(caKey));
  assert(orders.subjectAltName.includes(`URI:${id("orders")}`));
}

// Write them out so you can inspect them with openssl and try them with openssl s_client / curl (see README)
fs.mkdirSync(CERT_DIR, { recursive: true });
fs.writeFileSync(path.join(CERT_DIR, "ca.crt"), CA.certPem);
for (const [name, c] of Object.entries(certs)) {
  fs.writeFileSync(path.join(CERT_DIR, `${name}.crt`), c.certPem);
  fs.writeFileSync(path.join(CERT_DIR, `${name}.key`), c.keyPem, { mode: 0o600 }); // private key: owner-only
}

// "URI:spiffe://chaipay.internal/orders" inside "DNS:localhost, IP Address:127.0.0.1, URI:spiffe://…"
const spiffeIdOf = (cert) => /URI:(spiffe:\/\/[^,\s]+)/.exec(cert?.subjectaltname ?? "")?.[1] ?? null;

// ---------- Shared helpers ----------
const str = (v) => (typeof v === "string" ? v : undefined);
const noStore = (req, res, next) => { res.set("Cache-Control", "no-store"); next(); };

function addFinalHandlers(app) {
  app.use((req, res) => res.status(404).json({ error: "Not found" }));
  // Errors (bad JSON, body too big, bugs) come here. Never send the stack trace to the client.
  app.use((err, req, res, next) => {
    if (err.type === "entity.parse.failed") return res.status(400).json({ error: "Body must be valid JSON" });
    if (err.type === "entity.too.large") return res.status(413).json({ error: "Request body too large" });
    console.error(err);
    res.status(500).json({ error: "Something went wrong" });
  });
}

// ============================================================================================
// payments-service (HTTPS + mTLS)
// ============================================================================================
// shortcut: in-memory Map, lost on restart. A real payments service uses a database table.
const paymentsDb = new Map(); // paymentId -> { id, orderId, amount, status, chargedBy, createdAt }

function charge(body, chargedBy) {
  const orderId = str(body?.orderId);
  const amount = body?.amount;
  if (!orderId || !/^[\w-]{1,40}$/.test(orderId)) return { status: 400, body: { error: "orderId must be 1 to 40 letters, digits, - or _" } };
  if (!Number.isInteger(amount) || amount < 1 || amount > 100_000) return { status: 400, body: { error: "amount must be a whole number of rupees, 1 to 100000" } };
  const payment = { id: `pay_${crypto.randomBytes(4).toString("hex")}`, orderId, amount, status: "captured", chargedBy, createdAt: new Date().toISOString() };
  paymentsDb.set(payment.id, payment);
  console.log(`💳 ₹${amount} charged for ${orderId} by ${chargedBy}`);
  return { status: 201, body: payment };
}

const payments = express();
payments.use(express.json({ limit: "10kb" }));
payments.use(noStore);

// ❌ VULNERABLE: "who is calling?" answered by a HEADER. Anyone who can reach this port can type that header.
// (Same mistake: "it's on the internal network, so it must be one of our services.")
payments.post("/vulnerable/charge", (req, res) => {
  const caller = str(req.get("x-service"));
  if (caller !== "orders") return res.status(403).json({ error: "Only the orders service may charge" });
  const r = charge(req.body, `"${caller}" (said a header)`);
  res.status(r.status).json(r.body);
});

// STEP 2: AUTHENTICATE the caller by its client certificate. TLS already checked the chain and dates in the
// handshake (requestCert + ca below); here we read the result and pull out WHO it is (the SPIFFE ID).
function requireClientCert(req, res, next) {
  const cert = req.socket.getPeerCertificate(); // {} when the client sent no certificate
  if (!cert || Object.keys(cert).length === 0) return res.status(401).json({ error: "No client certificate" });
  if (!req.socket.authorized) {
    // e.g. CERT_HAS_EXPIRED, CERT_SIGNATURE_FAILURE, UNABLE_TO_VERIFY_LEAF_SIGNATURE
    const reason = String(req.socket.authorizationError?.code ?? req.socket.authorizationError);
    console.log(`🚫 Rejected client cert "${cert.subject?.CN}": ${reason}`);
    return res.status(401).json({ error: "Client certificate rejected", reason });
  }
  const spiffeId = spiffeIdOf(cert);
  if (!spiffeId?.startsWith(`${TRUST_DOMAIN}/`)) return res.status(401).json({ error: "Certificate has no SPIFFE ID from our trust domain" });
  // Identity comes from the VERIFIED certificate, never from a header or the request body
  req.service = { spiffeId, name: spiffeId.slice(TRUST_DOMAIN.length + 1), serial: cert.serialNumber, validTo: new Date(cert.valid_to).toISOString() };
  next();
}

// STEP 4: AUTHORIZE by identity. A valid cert only proves WHO you are, not what you may do.
// Every service in the company has a valid cert, so each route lists exactly which services may call it.
const allow = (...names) => (req, res, next) => {
  if (names.includes(req.service.name)) return next();
  console.log(`🚫 ${req.service.spiffeId} tried ${req.method} ${req.path}`);
  res.status(403).json({ error: `${req.service.spiffeId} may not call ${req.method} ${req.route?.path ?? req.path}` });
};

payments.use(requireClientCert); // everything below needs a verified client certificate

payments.get("/whoami", (req, res) => res.json({ youAre: req.service }));

payments.post("/charge", allow("orders"), (req, res) => {
  const r = charge(req.body, req.service.spiffeId);
  res.status(r.status).json(r.body);
});

payments.get("/payments/:id", allow("orders", "analytics"), (req, res) => {
  const p = paymentsDb.get(req.params.id);
  if (!p) return res.status(404).json({ error: "Payment not found" });
  res.json(p);
});

addFinalHandlers(payments);

const paymentsServer = https.createServer(
  {
    key: certs.payments.keyPem,
    cert: certs.payments.certPem,
    ca: [CA.certPem],      // trust ONLY our internal CA for client certs, not the 100+ public CAs
    requestCert: true,     // ask the client for a certificate (the "mutual" in mutual TLS)
    // false = finish the handshake even with a bad/missing cert, so requireClientCert can answer with a readable 401.
    // Production: true, so a bad cert never even reaches Express (one fewer place to forget the check).
    rejectUnauthorized: false,
    minVersion: "TLSv1.2",
  },
  payments,
);
// STEP 5 (rotation): call paymentsServer.setSecureContext({ key, cert, ca }) with a renewed cert. New connections
// use it at once, without a restart. Sidecars and SPIRE agents do this for you every few hours.

// ============================================================================================
// impostor: a real cert from OUR CA (it's analytics' cert), but it is not payments.
// Shows why the client must check WHICH service answered, not only "signed by our CA".
// ============================================================================================
const impostor = express();
impostor.use(express.json({ limit: "10kb" }));
impostor.post("/charge", (req, res) => res.json({ message: "Thanks for the order details 😈" }));
addFinalHandlers(impostor);
const impostorServer = https.createServer({ key: certs.analytics.keyPem, cert: certs.analytics.certPem }, impostor);

// ============================================================================================
// orders-service (the caller). STEP 3: the CLIENT side of mTLS.
// ============================================================================================
function callService({ caller, target = "payments", method = "GET", path: urlPath, body }) {
  const me = certs[caller]; // undefined for "none" (no client certificate)
  const expected = id("payments");
  const data = body === undefined ? undefined : JSON.stringify(body);
  return new Promise((resolve) => {
    const req = https.request(
      {
        host: "localhost",
        port: target === "impostor" ? IMPOSTOR_PORT : PAYMENTS_PORT,
        method,
        path: urlPath,
        key: me?.keyPem,   // our private key: proves we own the certificate
        cert: me?.certPem, // our certificate: says who we are
        ca: [CA.certPem],  // the server must chain to OUR CA (a public-CA cert for "localhost" won't do)
        // Default check = hostname in the cert. We ALSO require the server's SPIFFE ID to be payments:
        // every service has a cert from our CA, so "valid cert" alone would accept any of them.
        checkServerIdentity: (host, cert) => {
          const err = tls.checkServerIdentity(host, cert);
          if (err) return err;
          const got = spiffeIdOf(cert);
          if (got !== expected) return Object.assign(new Error(`Server is ${got}, expected ${expected}`), { code: "ERR_WRONG_SERVICE" });
        },
        agent: false, // shortcut: a fresh connection per call so each demo identity is separate. Real clients reuse an Agent.
        timeout: 5000,
        headers: data ? { "content-type": "application/json", "content-length": Buffer.byteLength(data) } : {},
      },
      (res) => {
        let raw = "";
        res.setEncoding("utf8");
        res.on("data", (chunk) => (raw += chunk));
        res.on("end", () => {
          let parsed = raw;
          try { parsed = JSON.parse(raw); } catch {}
          resolve({ status: res.statusCode, body: parsed });
        });
      },
    );
    req.on("timeout", () => req.destroy(Object.assign(new Error("Timed out"), { code: "ETIMEDOUT" })));
    // A refused handshake ends up here: the request never reached the other side's Express app
    req.on("error", (err) => resolve({ tlsError: err.code ?? "ERROR", message: err.message }));
    req.end(data);
  });
}

const orders = express();
orders.use(express.json({ limit: "10kb" }));
orders.use(noStore);

// The real flow: a customer checks out, orders-service calls payments-service with ITS OWN certificate
orders.post("/checkout", async (req, res) => {
  const r = await callService({ caller: "orders", method: "POST", path: "/charge", body: { orderId: req.body?.orderId, amount: req.body?.amount } });
  if (r.tlsError) return res.status(502).json({ error: "Could not reach payments securely", upstream: r });
  if (r.status !== 201) return res.status(r.status === 400 ? 400 : 502).json({ error: "Payment failed", upstream: r.body });
  res.status(201).json({ message: `Order ${r.body.orderId} paid`, payment: r.body });
});

// 🧪 LAB: make a call to payments presenting any of the demo certificates, so you can see every check fire.
// shortcut: a test harness. In real life only the orders pod holds the orders key; no endpoint picks identities.
const LAB_CALLERS = ["orders", "analytics", "orders-expired", "orders-rogue", "none"];
orders.post("/lab/call", async (req, res) => {
  const caller = str(req.body?.caller);
  const target = str(req.body?.target) ?? "payments";
  const method = str(req.body?.method) ?? "GET";
  const urlPath = str(req.body?.path);
  if (!LAB_CALLERS.includes(caller)) return res.status(400).json({ error: `caller must be one of ${LAB_CALLERS.join(", ")}` });
  if (!["payments", "impostor"].includes(target)) return res.status(400).json({ error: "target must be payments or impostor" });
  if (!["GET", "POST"].includes(method)) return res.status(400).json({ error: "method must be GET or POST" });
  if (!urlPath || !/^\/[\w/-]{0,99}$/.test(urlPath)) return res.status(400).json({ error: "path must look like /charge" });
  res.json({ caller, ...(await callService({ caller, target, method, path: urlPath, body: req.body?.body })) });
});

addFinalHandlers(orders);

// Express 5 passes a listen error (like "port already in use") to this callback instead of crashing
orders.listen(PORT, (err) => {
  if (err) throw err;
  console.log(`🛒 orders-service (caller, plain HTTP)  ${BASE_URL}`);
});
// (Plain Node servers crash with EADDRINUSE on their own if the port is taken.)
paymentsServer.listen(PAYMENTS_PORT, () => {
  console.log(`💳 payments-service (HTTPS + mTLS)     https://localhost:${PAYMENTS_PORT}`);
});
impostorServer.listen(IMPOSTOR_PORT, () => {
  console.log(`😈 impostor (pretends to be payments)  https://localhost:${IMPOSTOR_PORT}`);
  console.log(`🔐 Fresh internal CA + 24 h certs written to ${CERT_DIR} (new ones on every restart)`);
});
