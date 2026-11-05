# 41. Auth Libraries: Passport.js / Auth.js / Spring Security

## Notes

### What is an auth library?

In topics 33–40 we wrote the whole login by hand: `state`, `nonce`, PKCE, the code exchange, ID token checks, sessions, account linking. That's the best way to **learn** it, but in a real project you usually let a well-tested **library** do the protocol part. **Passport.js** is middleware for Express with hundreds of "strategies" (one per login method). **openid-client** is a certified OpenID Connect client for Node (with its own Passport strategy). **Auth.js** (formerly NextAuth.js) is a complete auth layer with routes, pages, CSRF protection and sessions. **Spring Security** does the same job in Java.

> **One-line answer:** use a library for the **protocol** (redirects, `state` / `nonce` / PKCE, the token exchange, ID token checks, CSRF on its own routes, session cookies), and keep writing **your own** code for the **account model** (which user an identity belongs to, topic 40), **authorization**, and the **settings** the library can't choose for you (secrets, cookie flags, session store, trusted hostname, which providers' emails you trust).

---

### Why does it matter?

| Hand-written mistake | What the library does instead |
|---|---|
| Forgetting to check `nonce`, `aud` or `iss` on the ID token | Checks them on every login |
| Accepting `alg: none` or the wrong key | Fetches the JWKS and only allows the expected algorithms |
| No PKCE, or `state` not tied to the session | Generates and checks them for you |
| Login button is a plain GET that anyone can trigger | Auth.js: sign-in and sign-out are POSTs with a CSRF token |
| `?callbackUrl=https://evil.example` after login (open redirect) | Auth.js only allows same-site redirects by default |
| Keeping the same session id after login (session fixation) | Passport 0.6+ regenerates the session on login and logout |
| Every new provider means new code | Add a strategy / provider entry |

But a library **can't** decide:

| Still your job | Why |
|---|---|
| Which **account** an identity belongs to (topic 40) | The library knows "KaroID user `kr_7Hq2LmV9`", not "PrintKaro customer `acct_5gLc7A`" |
| Secrets (`AUTH_SECRET`, session secret, client secrets) | Set them in env / a secret store (topic 54) |
| Cookie `secure`, session store, session lifetime | Depend on your deployment |
| Which hostname is yours | A library that trusts the `Host` header builds URLs from it |
| Which providers' emails you trust | Auth.js `allowDangerousEmailAccountLinking` is off by default for a reason |
| Keeping the library **updated** | Security fixes only help if you install them |

---

### Real-life example: buying a lock from a lock company 🔐

Rahul is opening a shop in Pune.

- He **could** make his own lock from scratch (topics 33–40). He'd learn a lot, but one weak spring and the shop is open to everyone.
- So he buys a **tested lock** from a well-known lock company (the library). Thousands of shops use it, and locksmiths have already found and fixed its weak points.
- The lock company **doesn't** decide **who gets a key**: that's Rahul's list of staff (your account model). It doesn't put the lock on the right **door** for him (your config: hostname, cookies, secrets). And when the company announces "please replace the spring", Rahul has to **actually do it** (updates).
- Different lock types for different doors: a simple latch kit he assembles himself (**Passport**: you wire up the parts), a complete door-and-lock set (**Auth.js**: routes, pages and sessions included), or the standard lock for a whole building in another country (**Spring Security** in Java).

---

### The libraries at a glance

| | Passport.js | openid-client | Auth.js (`@auth/express`) | Spring Security |
|---|---|---|---|---|
| Language | Node (Express/Connect) | Node (any) | Node (Next.js, SvelteKit, Express…) | Java (Spring Boot) |
| What it is | Middleware + "strategies" | OIDC / OAuth client, OpenID-certified | Full auth layer: routes, pages, sessions | Full security framework: filters, login, authorization |
| Providers | 500+ community strategies (quality varies) | Any standards-compliant OIDC/OAuth server | Many built-in providers + custom OIDC | `oauth2Login()` + any OIDC provider |
| Sessions | Yours (`express-session` + a store) | Yours | Built-in: encrypted **JWT cookie** (default) or **database** sessions via an adapter | Servlet session (or your choice) |
| Routes and CSRF | You write the routes | You write the routes | Built in (`/auth/signin`, `/auth/callback/…`, `/auth/signout`…) with CSRF tokens | Built-in endpoints and CSRF protection |
| Your hook | the `verify` callback | after `authorizationCodeGrant()` | `callbacks.signIn / jwt / session / redirect` | `OAuth2UserService`, success handler |

Others you'll hear about: **Better Auth** (a newer TypeScript auth framework), **Lucia** (its author deprecated the library in 2025 and turned it into a learning resource), and hosted services like Auth0, Clerk, Cognito, Keycloak (Level 8). Libraries change quickly: check the current docs and the last release date before you choose.

---

### The flow, step by step

#### 📊 Diagrams

Open **[diagrams.html](diagrams.html)** in your browser (just double-click the file) to see:

- **Flow diagram**: what the library does for you, and where your code plugs in
- **Data flow**: an Auth.js sign-in with its CSRF token, cookies and callbacks
- **Passport's moving parts**: strategy, verify, serialize/deserialize, session

In short: `your route → library builds the login URL (PKCE / state / nonce) → provider → library's callback: exchange the code, verify the ID token → YOUR callback: find or create the account → library: session cookie → your routes read req.user / getSession()`.

---

### Step 1: Passport.js: strategies, verify, serialize

Passport has four pieces:

```js
// 1. A strategy: how to log in (here: openid-client's OIDC strategy)
passport.use("karoid", new Strategy({ config, scope: "openid profile email", callbackURL }, (tokens, verified) => {
  // 2. YOUR verify function: the login worked, now which user is it?
  const claims = tokens.claims();             // already verified by the library
  verified(null, findOrCreateUser({ provider: "karoid", sub: claims.sub, ... }));
}));
// 3. What to store in the session (just the id), and how to load the user on each request
passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser((id, done) => done(null, users.get(id) ?? false));
// 4. Routes: one starts the login, one is the callback
app.get("/passport/login", passport.authenticate("karoid"));
app.get("/passport/callback", passport.authenticate("karoid", { successRedirect: "/passport/me", failureRedirect: "/passport/failed" }));
```

Then `req.user`, `req.isAuthenticated()` and `req.logout(cb)` work in every route.

| ✅ Do | ❌ Don't |
|---|---|
| Use Passport **0.6 or newer** (it regenerates the session on login: session fixation, topic 50) | Stay on 0.5 or older |
| Call `req.logout((err) => …)` with a callback (it's async now) | `req.logout(); res.redirect("/")` |
| Store only the **user id** in the session | Store the whole user, tokens or a password hash |
| Use a real session store (Redis, Postgres) | Ship the default `MemoryStore` (it leaks memory and doesn't work with 2+ servers) |
| Prefer `openid-client`'s strategy for any OIDC provider | Pick a random strategy that hasn't been updated in years |

---

### Step 2: openid-client: discovery and safe defaults

```js
const config = await client.discovery(new URL(ISSUER), CLIENT_ID, CLIENT_SECRET);
```

- **Discovery** reads `/.well-known/openid-configuration`: endpoints, JWKS, supported features (topic 36).
- The demo adds `{ execute: [client.allowInsecureRequests] }` only because the mock runs on plain `http://localhost`. **Never** in production.
- When the provider says it supports PKCE (`code_challenge_methods_supported: ["S256"]`), openid-client's Passport strategy uses **PKCE only, without `state` or `nonce`**. That's deliberate and safe: the code is bound to a verifier stored in **this** session, so a stolen or injected code fails (topics 34, 35). The demo's terminal shows it: `state ✗, nonce ✗, PKCE ✓ S256`.

---

### Step 3: Auth.js: config, callbacks, built-in routes

```js
const authConfig = {
  secret: process.env.AUTH_SECRET,
  trustHost: true,              // see "Tricky parts" 3
  providers: [{ id: "karoid", name: "KaroID", type: "oidc", issuer, clientId, clientSecret, checks: ["pkce", "state", "nonce"] }],
  callbacks: {
    async jwt({ token, account, profile }) {    // right after sign-in, account + profile are set
      if (account) token.appUserId = findOrCreateUser({ provider: account.provider, sub: profile.sub, ... }).id;
      return token;
    },
    async session({ session, token }) {          // what /auth/session returns
      session.user.id = token.appUserId;
      return session;
    },
  },
};
app.use("/auth", ExpressAuth(authConfig));
const s = await getSession(req, authConfig);     // in your own routes
```

Auth.js gives you these routes under `/auth`:

| Route | What it does |
|---|---|
| `GET /auth/signin` | A ready-made sign-in page |
| `GET /auth/csrf` | A CSRF token (also set in a cookie: the **double-submit** pattern) |
| `POST /auth/signin/:provider` | Starts the login. **Needs the CSRF token**, so another site can't log you in |
| `GET /auth/callback/:provider` | Exchanges the code, verifies the ID token, runs your callbacks, sets the session cookie |
| `GET /auth/session` | The session as JSON (what your `session` callback returns) |
| `POST /auth/signout` | Logs out. Needs the CSRF token too |

**Sessions:** by default Auth.js stores the session in an **encrypted JWT cookie** (`authjs.session-token`, a JWE made with `AUTH_SECRET`, 30 days by default). With a **database adapter** it stores a session id in the cookie and the session in your database. The difference matters for logout-everywhere (Tricky parts 4).

---

### Step 4: Your account model stays yours

Both libraries tell you **"this is KaroID user `kr_7Hq2LmV9`"**. Turning that into **"PrintKaro customer `acct_5gLc7A`"** is the same `findOrCreateUser` from topic 40, called from Passport's `verify` and from Auth.js's `jwt` callback. In the demo, Rahul logs in once through each library and gets the **same** account both times.

If you use an Auth.js database adapter, it creates `User` and `Account` tables (an account = an identity) and links them for you. The same rules from topic 40 still apply: automatic linking by email stays off unless you trust the provider for that email.

---

### Step 5: The settings only you can get right

| Setting | Passport + express-session | Auth.js |
|---|---|---|
| Secret | `secret: process.env.SESSION_SECRET` | `AUTH_SECRET` (also `AUTH_SECRET_1..3` for rotation) |
| HTTPS-only cookie | `cookie: { secure: true }` + `app.set("trust proxy", 1)` behind a proxy | automatic on `https://` (cookies get the `__Secure-` prefix) |
| Session store | Redis / Postgres store | JWT (default) or database adapter |
| Your hostname | build `callbackURL` from config | `trustHost` + a fixed `AUTH_URL` / pinned `Host` |
| Where users go after login | your own redirect | `callbacks.redirect` (same-origin only by default) |
| Debugging | your own logs | `debug: true` in development only |

---

### Step 6: Spring Security (Java), for comparison

The same idea in Spring Boot: configure the provider, turn on `oauth2Login()`, and Spring Security does the redirects, `state`, `nonce`, code exchange and ID token checks.

```yaml
# application.yml
spring.security.oauth2.client:
  registration.karoid: { client-id: printkaro, client-secret: ${KAROID_SECRET}, scope: openid,profile,email }
  provider.karoid: { issuer-uri: https://id.karoid.example }
```

```java
@Bean
SecurityFilterChain security(HttpSecurity http) throws Exception {
  return http
    .authorizeHttpRequests(a -> a.requestMatchers("/").permitAll().anyRequest().authenticated())
    .oauth2Login(Customizer.withDefaults())   // the whole login flow
    .build();
}
```

Your account-model code goes into a custom `OidcUserService` or a success handler. PKCE is used for public clients; for confidential clients you can add it with `OAuth2AuthorizationRequestCustomizers.withPkce()` (check the defaults of your Spring Security version).

---

### Which one should I pick?

| Situation | Good choice |
|---|---|
| Express API, you want full control, one or two OIDC providers | **Passport + openid-client** (or openid-client alone) |
| Next.js / SvelteKit app, many social logins, want pages + sessions done | **Auth.js** |
| Spring Boot backend | **Spring Security** |
| Many apps, enterprise SSO, MFA, user admin screens | A hosted or self-hosted identity provider (Keycloak, Auth0, Cognito…), Level 8 |
| Learning how it works | Write it by hand once (topics 33–40), then switch to a library |

---

### 🤔 Tricky parts

**1. Libraries have different defaults.**
The demo's mock logs what each library sent: openid-client used **PKCE only**, Auth.js used **PKCE + state + nonce** (because we set `checks`). Both are safe. Read the defaults instead of assuming.

**2. A library only protects the routes it owns.**
Auth.js puts CSRF tokens on **its** POST routes. Your own `POST /orders` still needs CSRF protection (topic 47). Passport protects nothing by itself: it's up to you to use POST for logout and set cookie flags.

**3. The `Host` header.**
Auth.js builds URLs (the `redirect_uri`, error pages) from the request's host when `trustHost` is on. Behind a well-configured proxy that's fine; on a server that accepts any `Host`, an attacker can put `evil.example` into those URLs. The demo **pins** the host before Auth.js sees the request (a forged `Host` still redirects to `localhost`).

**4. JWT sessions can't be revoked one by one.**
Auth.js's default JWT session lives in the cookie: the server can't end it early (until it expires) unless you add a check. If you need "log out of all devices" or instant blocking, use **database sessions** (Level 3 covered this trade-off).

**5. Library errors are vague on purpose.**
A forged callback ends at `/auth/error?error=Configuration` (Auth.js) or your `failureRedirect` (Passport): no details for the attacker. Use `debug: true` / server logs in development to see why.

**6. ESM and CommonJS.**
`@auth/express` is an ES module. Node 22+ can `require()` it (the demo does); on older Node use `import`.

**7. Unmaintained strategies.**
Some popular Passport strategies haven't been updated in years. For any provider that speaks OIDC, prefer a maintained general client (openid-client) over a provider-specific strategy.

---

### Common beginner mistakes

1. **Thinking the library handles "who is this customer".**
   It verifies the provider's identity; mapping it to your account (topic 40) is your code.

2. **Keeping the default secrets / generating them at startup.**
   Everyone gets logged out on restart, and different servers can't read each other's cookies. Set `AUTH_SECRET` / `SESSION_SECRET` from a secret store.

3. **`MemoryStore` in production.**
   Use Redis or a database session store.

4. **`secure: false` cookies in production.**
   HTTPS + `secure: true` (and `trust proxy` behind a load balancer).

5. **`allowInsecureRequests` or `debug: true` in production.**
   Development only.

6. **Turning on `allowDangerousEmailAccountLinking` for every provider.**
   Only for providers you trust to verify that email (topic 40).

7. **Trusting the `Host` header** (`trustHost: true` on a server that accepts any host).
   Pin the host or set a fixed URL.

8. **Never updating.**
   Watch security advisories (`npm audit`, Dependabot) for auth libraries first.

9. **Using a library without understanding the flow.**
   When it fails, you need topics 33–40 to read the error.

---

### Interview questions

1. **Why use an auth library instead of writing OAuth yourself?**
   The protocol has many easy-to-miss checks (`state`, `nonce`, PKCE, `iss`, `aud`, `alg`, key rotation, CSRF, open redirects, session fixation). A widely used, tested library gets them right and gets security fixes. You still own account mapping, authorization and configuration.

2. **What are Passport's `serializeUser` and `deserializeUser`?**
   `serializeUser` decides what goes into the session (usually the user id); `deserializeUser` turns that id back into `req.user` on each request.

3. **What changed in Passport 0.6?**
   `req.login()` and `req.logout()` regenerate the session (session fixation fix), and `logout` became async with a callback.

4. **How does Auth.js protect sign-in from CSRF?**
   Sign-in and sign-out are POSTs that need a CSRF token from `/auth/csrf`, checked against a signed cookie (double-submit). Another site can't start a login for you.

5. **JWT sessions vs database sessions in Auth.js?**
   JWT: an encrypted cookie, no database, can't be revoked before expiry. Database: a session id in the cookie and the session in a table, so it can be revoked, at the cost of a lookup per request.

6. **Is it OK that openid-client doesn't send `state` when PKCE is used?**
   Yes. PKCE binds the authorization code to a verifier in the user's session, which already stops code injection and login CSRF; `state` is required only when PKCE isn't available.

7. **How do you add your own user table to Auth.js?**
   Use the `signIn` / `jwt` callbacks to find or create your user (as in the demo), or a database adapter that manages `User` and `Account` tables.

8. **What does `oauth2Login()` do in Spring Security?**
   It adds the filters for the authorization code flow: redirect to the provider, handle the callback, exchange the code, validate the ID token, and create the authenticated principal.

---

### Quick recap

- Library = the **protocol** (PKCE / state / nonce, code exchange, ID token checks, its own CSRF, session cookies)
- You = **account model** (topic 40), **authorization**, **secrets**, **cookie flags**, **session store**, **hostname**, **updates**
- **Passport**: strategy + `verify` + `serializeUser` / `deserializeUser`; use 0.6+, a real store, `openid-client`'s strategy for OIDC
- **openid-client**: discovery, PKCE-only when supported; `allowInsecureRequests` only on localhost
- **Auth.js**: `/auth/*` routes, CSRF on POSTs, JWT (default) or database sessions, `callbacks.jwt/session/redirect`; pin the host
- **Spring Security**: `oauth2Login()` + `application.yml`
- Next: Level 6, passwordless and MFA (magic links, topic 42)

## Code

One **Express** file, two apps:

| Port | App |
|---|---|
| `3000` | 🖨️ **PrintKaro**: the same login done twice, with **Passport + openid-client** at `/passport/*` and **Auth.js** at `/auth/*`, both using one account store |
| `3001` | 🔑 **KaroID**: a small mock OpenID Connect provider (discovery, JWKS, PKCE required, RS256 ID tokens). It **logs what each library sends** |

Test users on KaroID: `rahul` and `priya`.

📄 **Full code: [server.js](server.js)**. Part 1 is KaroID, Part 2 is your account model, Part 3 is Passport, Part 4 is Auth.js. Read the comments, which follow the same steps as the notes above.

Install the dependencies once (from this folder), then start the server:

```bash
npm install
```

```bash
node server.js
```

This topic's dependencies are the libraries themselves: `passport`, `express-session`, `openid-client`, `@auth/express`. `@auth/express` is an ES module, so use **Node 22 or newer**.

> Port 3000 busy? Run it on other ports: `PORT=3041 node server.js` (Git Bash) uses **3041** and **3042**. The outputs below were recorded that way, so they show those ports.

### Try it in the browser

Open **http://localhost:3000**:

- **Log in with KaroID via Passport** → **Continue as rahul** → `/passport/me`
- **Log in with KaroID via Auth.js** → Auth.js's own sign-in page → **Sign in with KaroID** → **Continue as rahul** → you're back on the home page → open `/authjs/me`: it shows the **same** `acct_…`

### Try it with curl (Git Bash)

```bash
APP=http://localhost:3000
red() { curl -s -o /dev/null -w "%{redirect_url}" "$@"; }
passport_login() {  # passport_login <cookie-jar> <mock user>
  L=$(red -c $1.jar -b $1.jar $APP/passport/login); CB=$(red "$L&mock_user=$2")
  curl -s -c $1.jar -b $1.jar -o /dev/null "$CB"; curl -s -b $1.jar $APP/passport/me; echo
}
authjs_login() {    # authjs_login <cookie-jar> <mock user>: get a CSRF token, POST sign-in, follow the provider
  T=$(curl -s -c $1.jar -b $1.jar $APP/auth/csrf | sed -E 's/.*"csrfToken":"([^"]*)".*/\1/')
  L=$(red -c $1.jar -b $1.jar -X POST "$APP/auth/signin/karoid?callbackUrl=/authjs/me" -d csrfToken=$T); CB=$(red "$L&mock_user=$2")
  curl -s -c $1.jar -b $1.jar -o /dev/null -w "-> %{redirect_url}\n" "$CB"; curl -s -b $1.jar $APP/authjs/me; echo
}
```

**① Rahul via Passport, Rahul via Auth.js, Priya via Auth.js:**

```bash
passport_login p rahul
authjs_login a rahul
authjs_login b priya
```
→
```
{"via":"Passport","user":{"id":"acct_5gLc7A","name":"Rahul Sharma","email":"rahul@example.com","createdAt":"2026-11-05T06:21:35.784Z"}}
-> http://localhost:3041/authjs/me
{"via":"Auth.js","user":{"id":"acct_5gLc7A","name":"Rahul Sharma","email":"rahul@example.com","createdAt":"2026-11-05T06:21:35.784Z"},"expires":"2026-12-05T06:21:36.337Z"}
-> http://localhost:3041/authjs/me
{"via":"Auth.js","user":{"id":"acct_XMqQoQ","name":"Priya Nair","email":"priya@example.com","createdAt":"2026-11-05T06:21:36.683Z"},"expires":"2026-12-05T06:21:36.770Z"}
```

Same `acct_5gLc7A` through both libraries: the account model is yours, not the library's. Auth.js's session lasts **30 days** by default (`expires`).

The terminal shows **what each library did**:

```
🔎 Passport + openid-client sent: scope="openid profile email", state ✗, nonce ✗, PKCE ✓ S256
🔎 token request: client auth client_secret_post, code_verifier ✓
🆕 [Passport] karoid kr_7Hq2LmV9 → acct_5gLc7A (Rahul Sharma)
🔎 Auth.js sent: scope="openid profile email", state ✓, nonce ✓, PKCE ✓ S256
🔎 token request: client auth client_secret_basic, code_verifier ✓
👋 [Auth.js] karoid kr_7Hq2LmV9 → acct_5gLc7A (Rahul Sharma)
🔎 Auth.js sent: scope="openid profile email", state ✓, nonce ✓, PKCE ✓ S256
🔎 token request: client auth client_secret_basic, code_verifier ✓
🆕 [Auth.js] karoid kr_P4n8XcQ1 → acct_XMqQoQ (Priya Nair)
```

**② The session and the cookies:**

```bash
curl -s -b a.jar $APP/auth/session; echo
grep -h "pk.sid\|authjs" p.jar a.jar
```
→
```
{"user":{"name":"Rahul Sharma","email":"rahul@example.com","id":"acct_5gLc7A"},"expires":"2026-12-05T06:21:36.837Z"}

#HttpOnly_localhost  /passport  pk.sid                s%3A_FnZ5RWR6orLFMKGgc94CCy3B6Pd9m7A.Pph...     ← Passport: a session id, data on the server
#HttpOnly_localhost  /          authjs.session-token  eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2Q0JDLUhT...     ← Auth.js: the session itself, encrypted (JWE "dir" + A256CBC-HS512)
#HttpOnly_localhost  /          authjs.callback-url   http%3A%2F%2Flocalhost%3A3041%2Fauthjs%2...
#HttpOnly_localhost  /          authjs.csrf-token     afb9895b47d4328381f92f9eae3ab9dab1e1591c...     ← token|hash, for the double-submit check
```

**③ What the libraries refuse:**

```bash
# sign-in POST without a CSRF token (what a malicious site would send)
curl -s -o /dev/null -w "%{http_code} %{redirect_url}\n" -X POST $APP/auth/signin/karoid
# open redirect: callbackUrl to another site
T=$(curl -s -c o.jar -b o.jar $APP/auth/csrf | sed -E 's/.*"csrfToken":"([^"]*)".*/\1/')
red -c o.jar -b o.jar -X POST "$APP/auth/signin/karoid?callbackUrl=https://evil.example/steal" -d csrfToken=$T >/dev/null; grep callback-url o.jar | cut -f7
# a forged Host header
curl -s -o /dev/null -w "%{http_code} %{redirect_url}\n" -H "Host: evil.example" -X POST $APP/auth/signin/karoid
# stolen / injected codes on both callbacks
curl -s -b p.jar -o /dev/null -w "%{http_code} %{redirect_url}\n" "$APP/passport/callback?code=stolen&iss=http://localhost:3001"
curl -s -b a.jar -o /dev/null -w "%{http_code} %{redirect_url}\n" "$APP/auth/callback/karoid?code=stolen&state=forged"
```
→
```
302 http://localhost:3041/auth/signin?error=MissingCSRF
http%3A%2F%2Flocalhost%3A3041                                ← evil.example was replaced with our own origin
302 http://localhost:3041/auth/signin?error=MissingCSRF      ← still OUR host: pinned before Auth.js sees it
302 http://localhost:3041/passport/failed                    ← no pending login with a matching PKCE verifier
302 http://localhost:3041/auth/error?error=Configuration     ← terminal: InvalidCheck: state value could not be parsed
```

**④ Log out of both:**

```bash
curl -s -b p.jar -c p.jar -X POST $APP/passport/logout; echo
curl -s -b p.jar $APP/passport/me; echo
T=$(curl -s -c a.jar -b a.jar $APP/auth/csrf | sed -E 's/.*"csrfToken":"([^"]*)".*/\1/')
curl -s -o /dev/null -w "%{http_code}\n" -c a.jar -b a.jar -X POST $APP/auth/signout -d csrfToken=$T
curl -s -b a.jar $APP/authjs/me; echo
```
→
```
{"loggedOut":true}
{"error":"Not logged in (Passport)"}
302
{"error":"Not logged in (Auth.js)"}
```

> **Note:** pass `callbackUrl` as a **query parameter** on `POST /auth/signin/karoid` as above. In this setup Auth.js ignored it as a form field.

### Going live

Point `issuer` / `discovery()` at your real provider's HTTPS URL and **remove** `allowInsecureRequests`. Set `AUTH_SECRET`, `SESSION_SECRET` and the client secret from a secret store, use `secure: true` cookies with a real session store (Redis / Postgres), and keep the hostname fixed. This demo only uses the mock, so check each library's current docs for version-specific defaults.

> **Windows PowerShell users:** the variables, `red()` / `passport_login()` / `authjs_login()` functions, cookie jars and `PORT=... node ...` work in Git Bash. In PowerShell, use the browser, Git Bash, or `$env:PORT=3041; node server.js`.
