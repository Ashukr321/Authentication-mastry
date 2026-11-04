const http = require("http");
const crypto = require("crypto");
const { promisify } = require("util");

const scrypt = promisify(crypto.scrypt); // async version: doesn't freeze the server while hashing
const SCRYPT_OPTIONS = { N: 2 ** 17, r: 8, p: 1, maxmem: 256 * 1024 * 1024 };

const users = new Map(); // email -> user  (stand-in for a database table with a UNIQUE email)
const COMMON_PASSWORDS = new Set(["password", "12345678", "123456789", "qwerty123", "password1", "iloveyou"]);

function validate(email, password) {
  const errors = [];
  if (typeof email !== "string" || email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim())) {
    errors.push("Email is not valid");
  }
  if (typeof password !== "string" || password.length < 8) {
    errors.push("Password must be at least 8 characters");
  } else if (password.length > 128) {
    errors.push("Password must be at most 128 characters");
  } else if (COMMON_PASSWORDS.has(password.toLowerCase())) {
    errors.push("This password is too common, please choose another");
  }
  return errors;
}

async function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const hash = await scrypt(password, salt, 64, SCRYPT_OPTIONS);
  return `${salt.toString("hex")}:${hash.toString("hex")}`;
}

function send(res, status, body) {
  res.writeHead(status, { "Content-Type": "application/json" });
  res.end(JSON.stringify(body));
}

http.createServer(async (req, res) => {
  if (req.method !== "POST" || req.url !== "/signup") return send(res, 404, { error: "Not found" });

  // 1. Read the body, with a size limit
  let raw = "";
  for await (const chunk of req) {
    raw += chunk;
    if (raw.length > 10_000) return send(res, 413, { error: "Request body too large" });
  }

  let body;
  try {
    body = JSON.parse(raw);
  } catch {
    return send(res, 400, { error: "Body must be valid JSON" });
  }

  // Pick ONLY the fields we expect (prevents mass assignment, e.g. { "role": "admin" })
  const { email, password } = body ?? {};

  // 2. Validate
  const errors = validate(email, password);
  if (errors.length) return send(res, 400, { errors });

  // 3. Normalize
  const normalizedEmail = email.trim().toLowerCase();

  // 4. Hash (never store or log the plain password)
  const passwordHash = await hashPassword(password);

  // 5. Save. Checking and saving happen together with no `await` in between,
  //    so two requests at once can't both get through (a real DB uses a UNIQUE index for this)
  if (users.has(normalizedEmail)) return send(res, 409, { error: "Email already registered" });
  const user = {
    id: crypto.randomUUID(),
    email: normalizedEmail,
    passwordHash,
    role: "user",          // set by the server, never taken from the request
    emailVerified: false,
    createdAt: new Date().toISOString(),
  };
  users.set(normalizedEmail, user);

  // 6. Respond with safe fields only, never the hash
  send(res, 201, { id: user.id, email: user.email });
}).listen(3000, () => console.log("Signup API on http://localhost:3000/signup"));
