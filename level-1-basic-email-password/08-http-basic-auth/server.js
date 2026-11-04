const http = require("http");
const crypto = require("crypto");
const { promisify } = require("util");

const scrypt = promisify(crypto.scrypt);
const SCRYPT_OPTIONS = { N: 2 ** 17, r: 8, p: 1, maxmem: 256 * 1024 * 1024 };
const REALM = 'Basic realm="Admin area", charset="UTF-8"';

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

// Demo users, hashed at startup. Real apps load hashes from a database, never plain passwords from code.
const users = new Map(); // username -> passwordHash
const ready = (async () => {
  users.set("rahul", await hashPassword("correct horse battery"));
  users.set("priya", await hashPassword("pass:with:colons")); // shows why we split at the FIRST colon
})();
const DUMMY_HASH_PROMISE = hashPassword("dummy-password-never-used"); // for unknown usernames (topic 07)

// Read "Authorization: Basic <base64>" and return { username, password }, or null
function parseBasicAuth(header) {
  // 1. Is there a header that starts with "Basic "?
  const match = /^Basic\s+([A-Za-z0-9+/=]+)$/i.exec(header || "");
  if (!match) return null;

  // 2. Base64-decode it: "cmFodWw6..." -> "rahul:correct horse battery"
  const decoded = Buffer.from(match[1], "base64").toString("utf8");

  // 3. Split at the FIRST colon only (passwords may contain colons, usernames can't)
  const colon = decoded.indexOf(":");
  if (colon === -1) return null;
  return { username: decoded.slice(0, colon), password: decoded.slice(colon + 1) };
}

function challenge(res, message) {
  // 401 + WWW-Authenticate makes the browser show its login popup
  res.writeHead(401, { "WWW-Authenticate": REALM, "Content-Type": "text/plain; charset=utf-8" });
  res.end(message + "\n");
}

http.createServer(async (req, res) => {
  if (req.url === "/") {
    res.writeHead(200, { "Content-Type": "text/plain; charset=utf-8" });
    return res.end("This page is public. Try /admin\n");
  }

  if (req.url === "/admin" || req.url.startsWith("/admin/")) {
    await ready;

    // Steps 1-3: parse the header (never log it: it contains the password!)
    const creds = parseBasicAuth(req.headers.authorization);
    if (!creds) return challenge(res, "Please log in");

    // Step 4: verify, with a dummy hash for unknown users so both cases take the same time
    const storedHash = users.get(creds.username);
    const ok = await verifyPassword(creds.password, storedHash ?? (await DUMMY_HASH_PROMISE));
    if (!storedHash || !ok) return challenge(res, "Invalid username or password");

    // Step 5: allowed. Note: this whole check runs again on EVERY request
    res.writeHead(200, { "Content-Type": "text/plain; charset=utf-8" });
    return res.end(`Welcome to the admin area, ${creds.username}!\n`);
  }

  res.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
  res.end("Not found\n");
}).listen(3000, () => console.log("Basic Auth demo on http://localhost:3000 (protected: /admin)"));
