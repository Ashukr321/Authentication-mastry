const http = require("http");
const crypto = require("crypto");
const { promisify } = require("util");

const scrypt = promisify(crypto.scrypt);
const SCRYPT_OPTIONS = { N: 2 ** 17, r: 8, p: 1, maxmem: 256 * 1024 * 1024 };

// Two timers (change them with env variables to watch expiry happen quickly)
const IDLE_MS = (Number(process.env.IDLE_TIMEOUT_SECONDS) || 30 * 60) * 1000;          // 30 min of no activity
const ABSOLUTE_MS = (Number(process.env.ABSOLUTE_TIMEOUT_SECONDS) || 8 * 60 * 60) * 1000; // 8 hours, no matter what

async function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const hash = await scrypt(password, salt, 64, SCRYPT_OPTIONS);
  return `${salt.toString("hex")}:${hash.toString("hex")}`;
}

async function verifyPassword(password, stored) {
  const [saltHex, hashHex] = stored.split(":");
  const attempt = await scrypt(password, Buffer.from(saltHex, "hex"), 64, SCRYPT_OPTIONS);
  return crypto.timingSafeEqual(attempt, Buffer.from(hashHex, "hex"));
}

// Demo user, hashed at startup. Real apps load users from a database.
const users = new Map(); // email -> { id, email, passwordHash }
const ready = (async () => {
  users.set("rahul@mail.com", { id: "u_1", email: "rahul@mail.com", passwordHash: await hashPassword("correct horse battery") });
})();
const DUMMY_HASH_PROMISE = hashPassword("dummy-password-never-used");

// ---------- The session store ----------
// shortcut: in-memory Map, lost on restart and not shared between servers. Use Redis in production.
// Key = sha256(sessionId), so a leaked store can't be used to log in.
const sessions = new Map(); // sha256(sessionId) -> { userId, createdAt, lastSeenAt, userAgent }
const keyFor = (sessionId) => crypto.createHash("sha256").update(sessionId).digest("hex");

// 1. CREATE: a new random ID on every login
function createSession(userId, req) {
  const sessionId = crypto.randomBytes(32).toString("hex"); // 256 random bits
  const now = Date.now();
  sessions.set(keyFor(sessionId), { userId, createdAt: now, lastSeenAt: now, userAgent: req.headers["user-agent"] || "unknown" });
  return sessionId;
}

const isExpired = (s, now) => now - s.lastSeenAt > IDLE_MS || now - s.createdAt > ABSOLUTE_MS;

// 2. READ + 3. REFRESH: find the session for this request
function getSession(req) {
  const sessionId = (req.headers.cookie || "").match(/(?:^|;\s*)sessionId=([a-f0-9]{64})/)?.[1];
  if (!sessionId) return { error: "Please log in" };

  const key = keyFor(sessionId);
  const session = sessions.get(key);
  if (!session) return { error: "Please log in" };

  const now = Date.now();
  if (isExpired(session, now)) {
    sessions.delete(key); // the server checks expiry itself, never trusting the cookie's Max-Age
    return { error: "Session expired, please log in again" };
  }

  session.lastSeenAt = now; // sliding idle timeout
  return { key, session };
}

// 4. DESTROY: delete expired sessions every minute so the store doesn't grow forever
setInterval(() => {
  const now = Date.now();
  for (const [key, s] of sessions) if (isExpired(s, now)) sessions.delete(key);
}, 60_000).unref();

// ---------- Helpers ----------
// Secure is left out so this works on plain http://localhost. ALWAYS add it in production (topic 05)
const sessionCookie = (id) => `sessionId=${id}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${ABSOLUTE_MS / 1000}`;
const CLEAR_COOKIE = "sessionId=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0";

function send(res, status, body, headers = {}) {
  res.writeHead(status, { "Content-Type": "application/json", ...headers });
  res.end(body === undefined ? undefined : JSON.stringify(body));
}

async function readJson(req) {
  let raw = "";
  for await (const chunk of req) {
    raw += chunk;
    if (raw.length > 10_000) return null;
  }
  try { return JSON.parse(raw); } catch { return null; }
}

const findUserById = (id) => [...users.values()].find((u) => u.id === id);

// ---------- Routes ----------
http.createServer(async (req, res) => {
  await ready;
  const route = `${req.method} ${req.url}`;

  if (route === "POST /login") {
    const { email, password } = (await readJson(req)) ?? {};
    if (typeof email !== "string" || typeof password !== "string" || !email || !password) {
      return send(res, 400, { error: "Email and password are required" });
    }
    const user = users.get(email.trim().toLowerCase());
    const ok = await verifyPassword(password, user ? user.passwordHash : await DUMMY_HASH_PROMISE);
    if (!user || !ok) return send(res, 401, { error: "Invalid email or password" });

    // Throw away any session this browser already had (prevents session fixation)
    const old = getSession(req);
    if (old.key) sessions.delete(old.key);

    const sessionId = createSession(user.id, req);
    return send(res, 200, { id: user.id, email: user.email }, { "Set-Cookie": sessionCookie(sessionId) });
  }

  // Everything below needs a valid session (this is the "requireAuth" check)
  const { key, session, error } = getSession(req);

  if (route === "POST /logout") {
    if (key) sessions.delete(key); // delete on the SERVER, so a copied cookie stops working too
    return send(res, 204, undefined, { "Set-Cookie": CLEAR_COOKIE });
  }

  if (!session && ["GET /me", "GET /sessions", "POST /logout-all"].includes(route)) {
    return send(res, 401, { error });
  }

  if (route === "GET /me") {
    const user = findUserById(session.userId); // load fresh user data, don't copy it into the session
    const now = Date.now();
    return send(res, 200, {
      user: { id: user.id, email: user.email },
      session: {
        createdAt: new Date(session.createdAt).toISOString(),
        idleExpiresInSeconds: Math.floor((session.lastSeenAt + IDLE_MS - now) / 1000),
        absoluteExpiresInSeconds: Math.floor((session.createdAt + ABSOLUTE_MS - now) / 1000),
      },
    });
  }

  if (route === "GET /sessions") {
    // A "your devices" page: every active session for this user
    const mine = [...sessions].filter(([, s]) => s.userId === session.userId);
    return send(res, 200, {
      count: mine.length,
      sessions: mine.map(([k, s]) => ({
        current: k === key,
        createdAt: new Date(s.createdAt).toISOString(),
        lastSeenAt: new Date(s.lastSeenAt).toISOString(),
        userAgent: s.userAgent,
      })),
    });
  }

  if (route === "POST /logout-all") {
    let count = 0;
    for (const [k, s] of sessions) {
      if (s.userId === session.userId) { sessions.delete(k); count++; }
    }
    return send(res, 200, { loggedOutSessions: count }, { "Set-Cookie": CLEAR_COOKIE });
  }

  send(res, 404, { error: "Not found" });
}).listen(3000, () => {
  console.log("Session auth demo on http://localhost:3000");
  console.log(`Idle timeout: ${IDLE_MS / 1000}s, absolute timeout: ${ABSOLUTE_MS / 1000}s`);
});
