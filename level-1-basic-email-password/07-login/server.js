const http = require("http");
const crypto = require("crypto");
const { promisify } = require("util");

const scrypt = promisify(crypto.scrypt);
const SCRYPT_OPTIONS = { N: 2 ** 17, r: 8, p: 1, maxmem: 256 * 1024 * 1024 };

const users = new Map();    // email -> { id, email, passwordHash }
const sessions = new Map(); // sessionId -> userId

async function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const hash = await scrypt(password, salt, 64, SCRYPT_OPTIONS);
  return `${salt.toString("hex")}:${hash.toString("hex")}`;
}

async function verifyPassword(password, stored) {
  const [saltHex, hashHex] = stored.split(":");
  const attempt = await scrypt(password, Buffer.from(saltHex, "hex"), 64, SCRYPT_OPTIONS);
  return crypto.timingSafeEqual(attempt, Buffer.from(hashHex, "hex")); // safe compare, never ===
}

// Used when the email doesn't exist, so both cases take the same time
const DUMMY_HASH_PROMISE = hashPassword("dummy-password-never-used");

function send(res, status, body, headers = {}) {
  res.writeHead(status, { "Content-Type": "application/json", ...headers });
  res.end(JSON.stringify(body));
}

async function readJson(req) {
  let raw = "";
  for await (const chunk of req) {
    raw += chunk;
    if (raw.length > 10_000) return null;
  }
  try { return JSON.parse(raw); } catch { return null; }
}

const isNonEmptyString = (v) => typeof v === "string" && v.length > 0;

http.createServer(async (req, res) => {
  // ---------- SIGNUP (short version of topic 06) ----------
  if (req.method === "POST" && req.url === "/signup") {
    const { email, password } = (await readJson(req)) ?? {};
    if (!isNonEmptyString(email) || !isNonEmptyString(password) || password.length < 8) {
      return send(res, 400, { error: "Valid email and a password of 8+ characters are required" });
    }
    const normalizedEmail = email.trim().toLowerCase();
    const passwordHash = await hashPassword(password);
    if (users.has(normalizedEmail)) return send(res, 409, { error: "Email already registered" });
    const user = { id: crypto.randomUUID(), email: normalizedEmail, passwordHash };
    users.set(normalizedEmail, user);
    return send(res, 201, { id: user.id, email: user.email });
  }

  // ---------- LOGIN ----------
  if (req.method === "POST" && req.url === "/login") {
    // 1. Validate input
    const { email, password } = (await readJson(req)) ?? {};
    if (!isNonEmptyString(email) || !isNonEmptyString(password)) {
      return send(res, 400, { error: "Email and password are required" });
    }

    // 2. Normalize the email exactly like signup
    const normalizedEmail = email.trim().toLowerCase();

    // 3. Find the user
    const user = users.get(normalizedEmail);

    // 4. ALWAYS verify a hash, even if the user doesn't exist (stops timing attacks)
    const ok = await verifyPassword(password, user ? user.passwordHash : await DUMMY_HASH_PROMISE);

    // Same status + same message for "no such email" and "wrong password"
    if (!user || !ok) return send(res, 401, { error: "Invalid email or password" });

    // 5. Create a NEW random session ID (never reuse one from the client)
    const sessionId = crypto.randomBytes(32).toString("hex");
    sessions.set(sessionId, user.id);

    // Secure is left out so this works on plain http://localhost. ALWAYS add it in production (topic 05)
    const cookie = `sessionId=${sessionId}; HttpOnly; SameSite=Lax; Path=/; Max-Age=3600`;
    return send(res, 200, { id: user.id, email: user.email }, { "Set-Cookie": cookie });
  }

  // ---------- PROTECTED ROUTE ----------
  if (req.method === "GET" && req.url === "/me") {
    const sessionId = (req.headers.cookie || "").match(/(?:^|;\s*)sessionId=([a-f0-9]+)/)?.[1];
    const userId = sessions.get(sessionId);
    const user = [...users.values()].find((u) => u.id === userId);
    if (!user) return send(res, 401, { error: "Please log in" });
    return send(res, 200, { id: user.id, email: user.email });
  }

  send(res, 404, { error: "Not found" });
}).listen(3000, () => console.log("Auth API on http://localhost:3000"));
