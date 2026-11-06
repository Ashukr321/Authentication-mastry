# 69. Zero Trust & API Gateway Auth

## Notes

### What is Zero Trust, and what does an API gateway have to do with it?

The old way of securing a company was a **castle and moat**: a strong firewall (or VPN) around the network, and anything **inside** was trusted. A request from `10.0.x.x` or a header like `X-User: priya` was simply believed.

**Zero Trust** throws that idea away: **being inside the network proves nothing**. Every request, from outside or inside, has to prove **who** is calling, **from what device**, and **whether this exact action is allowed right now**.

An **API gateway** is the front door that every outside request goes through (Kong, AWS API Gateway, Apigee, Envoy, NGINX, Azure APIM). It is the natural place to **enforce** those checks once, centrally. In zero trust the services behind it **check again** anyway.

> **One-line answer:** Zero trust = "never trust, always verify": authenticate and authorize **every** request using identity **plus** device health and context, give **least privilege**, and **assume the network is already breached**. An API gateway is the Policy Enforcement Point at the edge: it validates the caller's token, strips any identity headers the client sent, checks the policy, and forwards a **short-lived, signed, audience-bound** token that each service **verifies itself**.

---

### Why it matters

| Problem (perimeter thinking) | What goes wrong |
|---|---|
| "Inside the VPN = trusted" | One phished VPN password or one hacked server, and the attacker can call everything |
| Backend trusts `X-User` / `X-Roles` headers | Anyone who can send a header (through a gateway bug, or from inside) becomes anyone |
| Gateway only checks "logged in", backend does the rest | Authorization is split and each side assumes the other did it |
| One token works for every service | A token stolen from the least important service opens the most important one |
| Device health checked once at login (or never) | A laptop with disk encryption turned off, or full of malware, keeps full access |
| No per-request logs | After a breach, nobody can say who called what |

Big real breaches (Target 2013 through an HVAC vendor's access, many ransomware cases through VPN accounts) were "get inside once, then move sideways". Google built **BeyondCorp** after the 2009 "Operation Aurora" attack so that employees work without a VPN, and every app checks user + device on every request. NIST wrote it down as **SP 800-207, Zero Trust Architecture**.

---

### Real-life example: the office in Bengaluru 🏢

**Old way (castle and moat):** Rahul shows his ID card at the **main gate** once in the morning. After that, every floor, the server room and the HR file room are open to anyone already inside. A delivery person who slipped in behind someone can walk into the HR room and say "I'm Priya from HR", and the clerk believes him.

**Zero trust way:**

1. The **main gate** (API gateway) checks Rahul's card **and** looks at what he's carrying: is it the company laptop, and is it healthy (device posture)?
2. The gate doesn't let Rahul write his own visitor slip. **The guard** writes it: "Rahul, employee, for the **canteen**, valid **1 minute**", and signs it (internal token with `aud`, `exp`).
3. **Every door** (service) checks the slip **itself**: real signature? Made for **this door**? Not expired? The HR room also checks "is this person HR?" again.
4. If IT reports that Priya's laptop has turned off disk encryption, the guard stops her at the HR room **from the next visit**, even though her ID card is still valid.
5. When Rahul hands in his card (logout), the gate refuses it **immediately**.

The delivery person inside the building? He has no signed slip, so no door opens.

---

### The big picture

#### 📊 Diagrams

Open **[diagrams.html](diagrams.html)** in your browser (just double-click the file) to see:

- **Flow diagram**: every check a request passes at the gateway and then at the service, with where each attack is stopped
- **Data flow (perimeter vs zero trust)**: the `X-User` spoof and the gateway bypass, vulnerable vs safe
- **Data flow (assume breach)**: a stolen internal token, a forged one, a non-compliant laptop, and logout

In short: `client → gateway (strip identity headers → authenticate → check role + device → mint internal JWT for ONE service, 60 s) → service (verify signature, iss, aud, exp → check role again) → data`.

| | Perimeter model ❌ | Zero trust ✅ |
|---|---|---|
| Who is trusted? | Anything inside the network | Nobody by default |
| Identity between services | `X-User` header, IP allow-list | Signed token (JWT) or mTLS, verified by each service |
| Where are checks? | At the edge (firewall/VPN) only | At the edge **and** at every service |
| Device | Ignored, or checked at VPN login | Checked on every request, can change any minute |
| Access | Broad ("employees can reach the network") | Least privilege, per app, per route |
| Mindset | "Keep them out" | "Assume they're already in" |

**Policy Enforcement Point (PEP)** = the thing that blocks or allows (the gateway, a sidecar proxy, the service's middleware). **Policy Decision Point (PDP)** = the thing that decides (in our demo the `ROUTES` table + device lookup; in big companies OPA or a Zanzibar-style service, topic 71).

---

### Step 1: Never trust identity headers from the client

Headers like `X-User`, `X-User-Id`, `X-Roles`, `X-Email`, `X-Forwarded-User` are how many gateways tell backends who the user is. That's fine **only if the client can never set them**.

```js
// ❌ BUG: the client's headers are spread AFTER ours, so a client-sent X-User wins
headers: { "x-user": who.email, ...clientXHeaders }

// ✅ Build the upstream headers from scratch. Nothing the client sent about identity goes through.
headers: { authorization: `Bearer ${internalToken}`, "x-request-id": rid }
```

| ✅ Do | ❌ Don't |
|---|---|
| Drop (or overwrite) every identity header at the edge | Forward "all headers" or all `x-*` headers |
| Log it when a client sends one: someone is probing | Let a backend read `X-User` without a signature |
| Prefer a **signed** token over a plain header | Trust `X-Forwarded-For` blindly for IP-based rules (only the last proxy you run is real) |

---

### Step 2: Authenticate at the gateway (opaque outside, JWT inside)

Our client gets an **opaque** access token: 32 random bytes that mean nothing on their own. The gateway looks it up on every request. This is the **phantom token** pattern:

- **Outside** (browser, mobile app): an opaque token. Nothing to decode, nothing to leak, and **revoking it works instantly** (topic 70).
- **Inside**: the gateway swaps it for a short-lived **JWT** the services can verify without calling anyone.

```js
const who = authenticate(req); // sha256(token) → { email, deviceId, expiresAt }
if (!who) return res.status(401).json({ error: "Missing, expired or revoked access token" });
```

Many gateways instead validate a JWT the IdP issued (signature from the IdP's JWKS, `iss`, `aud`, `exp`, topic 22) and forward it. Both are fine. The point is that the **gateway** authenticates, not each client-facing route on its own.

---

### Step 3: Authorize with identity **and** context, on every request

```js
const ROUTES = new Map([
  ["orders",  { path: "/orders",  aud: "orders-service",  role: "employee", managedDevice: false }],
  ["payroll", { path: "/payroll", aud: "payroll-service", role: "hr",       managedDevice: true  }],
]);
```

- **Least privilege:** Rahul (employee) can read his own orders, not payroll.
- **Device posture:** payroll also needs a **healthy, company-managed** device. The gateway asks the device inventory (fed by the MDM: Intune, Jamf, Kandji) **on every request**, not only at login.
- **Risk-based:** low-risk routes can allow more (a personal phone can see your own orders), sensitive ones need more (managed device, recent MFA, topic 45 step-up).

Other context signals real systems use: location / impossible travel, time of day, IP reputation, recent MFA (`amr`, `auth_time`), risk scores from the IdP (Okta, Entra ID Conditional Access).

| ✅ Do | ❌ Don't |
|---|---|
| Re-evaluate on every request (continuous verification) | Decide everything once at login |
| Different rules for different routes | One rule: "logged in = allowed everywhere" |
| Look up device health live | Copy "compliant: true" into a 30-day token |

---

### Step 4: Give each service its own short-lived, signed token

```js
mintInternalToken({
  iss: "https://gateway.corp.example", sub: who.email, aud: "payroll-service",
  roles: who.user.roles, device: who.deviceId, iat: now, exp: now + 60, jti: crypto.randomUUID(),
});
```

| Claim | Why |
|---|---|
| `aud` | A token made for `orders-service` is **useless** at `payroll-service`. A hacked orders service can't pivot |
| `exp` = 60 s | A stolen copy dies quickly |
| `iss` | Only tokens from **our** gateway count |
| Signed with **Ed25519** (asymmetric) | Services get only the **public** key: they can verify, never mint. With a shared HMAC secret, every service could forge tokens for every other |

---

### Step 5: Every service verifies again (assume breach)

```js
if (header.alg !== "EdDSA") return { error: "unexpected alg" };        // pin the algorithm (topic 53)
if (!crypto.verify(null, data, gatewayPublicKey, sig)) return { error: "bad signature" };
if (claims.iss !== GATEWAY_ISS) return { error: "wrong issuer" };
if (claims.aud !== expectedAud) return { error: "wrong audience" };
if (claims.exp < now) return { error: "expired" };
```

Then the service checks its own rules **again** (payroll: `roles` must include `hr`) and uses `sub` from the token, never from a header or the body. That's **defense in depth**: if someone misconfigures the gateway route table, payroll still says no.

How do services prove **themselves** to each other (so a random process can't pretend to be the gateway)? **mTLS** with workload identities like SPIFFE, usually done by a service mesh (Istio, Linkerd). That's topic 68. In real zero trust you use **both**: mTLS for "which workload is calling" and a signed token for "on behalf of which user".

---

### Step 6: Revoke fast and log everything

- **Logout / disable user** → the opaque token is deleted at the gateway → the **next** request fails. No waiting for a JWT to expire.
- Internal tokens that are already issued still live up to 60 s. That's the price of not calling the gateway from every service. Keep it short.
- **One audit line per decision** with a request id that every service logs too (topic 55):

```
🛡️  ALLOW GET /api/orders user=rahul@corp.com device=rahul-laptop rid=801fe28b
⛔ DENY  GET /api/payroll user=priya@corp.com device=priya-mbp rid=6bf36f6c reason="device not compliant: disk encryption turned off"
```

Gateways also do things outside this topic that still protect auth: **rate limiting** per user/IP (topic 52), request size limits, TLS termination, WAF rules, CORS (topic 49).

---

### 🤔 Tricky parts

**1. "We have a gateway, so the backends don't need auth."** That's the perimeter model with a new name. Our demo's step ④ calls the legacy payroll service **directly** with `X-User: priya@corp.com` and gets every salary. Any pod in the cluster, any SSRF bug (a server fetching a URL the attacker chose), any stolen VPN account can do the same.

**2. Header spoofing through the gateway is a real, common bug.** It shows up as "pass all headers through", a spread in the wrong order, a route that skips auth but still forwards headers, or a second load balancer path that skips the gateway entirely.

**3. Shared HMAC secret vs asymmetric keys.** If every service has the same `HS256` secret, a hacked service can mint tokens for any other. Use asymmetric keys (EdDSA, ES256, RS256) and publish a JWKS.

**4. Revocation vs performance.** Opaque tokens = instant revocation but a lookup per request (cache it for a few seconds). JWTs = no lookup but they live until `exp`. The phantom token pattern takes the best of both: instant at the edge, 60 s inside.

**5. Device identity must be proven.** Our demo reads `deviceId` from the login body (a shortcut). Real zero trust ties it to a key the device can't give away: a certificate in the TPM / Secure Enclave used for mTLS, or a signed attestation from the MDM. Otherwise a thief just claims "priya-mbp".

**6. Zero trust is not a product.** Vendors sell "zero trust" boxes, but it's a set of rules: verify explicitly, least privilege, assume breach. A gateway is one piece. Identity provider, device management, mTLS between services, fine-grained authorization (topic 71) and logs are the other pieces.

**7. Don't leak why to outsiders.** Our 403 says "device not compliant" because employees need to fix it. For public APIs, keep error details short and put the detail in your logs (with the `requestId` the user can quote to support).

---

### Common beginner mistakes

1. **Trusting the network.** "It's internal" or "it's on the VPN" is not authentication.
2. **Backends that read `X-User` / `X-Roles` without a signature.**
3. **Forwarding client headers as-is** (or spreading them after your own).
4. **Only authenticating at the gateway**, and assuming everything behind it is safe.
5. **One token with no `aud`** that works on every service.
6. **Long-lived internal tokens** (hours or days) between services.
7. **Shared HMAC secrets** across services, so any one of them can forge tokens.
8. **Letting the token choose `alg`** (`none`, or `HS256` signed with your public key, topic 53).
9. **Checking device health only at login.** It can change in five minutes.
10. **No request id and no audit log**, so you can't trace a call through services after an incident.
11. **Leaving a second way in** (a direct load balancer, a debug port, an old `/v1` route) that skips the gateway.

---

### Interview questions

1. **What is zero trust?**
   A security model that trusts no request because of where it comes from. Every request is authenticated and authorized using identity, device and context, with least privilege, and the design assumes attackers are already inside. NIST SP 800-207 describes it; Google's BeyondCorp is the famous example.

2. **What are the core principles?**
   Verify explicitly (every request, every time), use least-privilege access, and assume breach (segment, encrypt, verify inside too, log everything).

3. **What does an API gateway do for authentication?**
   It's the single entry point: terminates TLS, validates tokens (signature, `iss`, `aud`, `exp`, or introspection for opaque tokens), strips spoofable identity headers, applies coarse policy (scopes, roles, rate limits), and forwards a trusted identity (a signed token) to upstream services.

4. **Is gateway authentication enough?**
   No. If services trust the gateway blindly, anything that reaches them directly (a compromised pod, SSRF, a misrouted load balancer) bypasses all checks. Services must verify a signed, audience-bound token themselves and do their own fine-grained authorization.

5. **What is the phantom token pattern?**
   Clients get an opaque token. The gateway introspects it and forwards a short-lived JWT to services. Outside you get instant revocation and nothing readable to leak; inside services verify locally without calling the auth server.

6. **Why put `aud` in internal tokens?**
   So a token issued for one service can't be replayed at another. If orders-service is hacked, its tokens don't open payroll-service.

7. **Header-based identity (`X-User-Id`) vs signed tokens between gateway and services?**
   Headers are fine only if nothing but the gateway can reach the service **and** the gateway always overwrites them. That's perimeter trust. A signed token (or mTLS + signed token) holds even if the network is compromised.

8. **What is device posture and how is it checked?**
   The health of the device: managed by the company, disk encrypted, OS patched, not jailbroken, EDR running. An MDM reports it; the device proves its identity with a certificate. The policy engine checks it on each request (Entra Conditional Access, Okta Device Trust, Google BeyondCorp).

9. **PEP vs PDP?**
   The Policy Enforcement Point blocks or allows (gateway, sidecar, middleware). The Policy Decision Point evaluates the rules and returns allow/deny (OPA, a policy service, topic 71).

10. **How do you revoke access quickly in a gateway setup?**
    Use opaque tokens or introspection at the gateway (topic 70), keep internal JWTs short-lived (seconds to a few minutes), and cache introspection results only briefly.

---

### Quick recap

- **Zero trust** = never trust the network; verify identity + device + context on **every** request; least privilege; assume breach
- **Gateway** (PEP at the edge): strip client identity headers → authenticate → authorize (role + device posture) → mint a **60-second, per-service** signed token → forward → log with a request id
- **Services**: verify signature (pinned alg), `iss`, `aud` = me, `exp`; check roles **again**; take the user from the token only
- **Asymmetric** signing so services can verify but not mint
- **Phantom token**: opaque outside (instant revocation), JWT inside
- Device health is checked **live**; a laptop that goes non-compliant loses sensitive access on the next request
- Next: service-to-service mTLS (topic 68) for workload identity, token introspection and revocation (topic 70), fine-grained authorization (topic 71)

## Code

One file runs **two servers**:

| Server | Port | Plays |
|---|---|---|
| 🚪 **API gateway** | `PORT` (3069 below) | The only door from the internet |
| 🏢 **Internal services** (`orders-service`, `payroll-service`) | `PORT + 1` (3070 below), on `127.0.0.1` | The "private network" behind it |

Calling the internal port directly with curl plays an attacker who is **already inside** (a hacked pod, a stolen VPN account).

| | ❌ Perimeter (vulnerable) | ✅ Zero trust |
|---|---|---|
| Gateway route | `GET /vulnerable/api/:service`: checks "logged in" only, forwards the client's `x-*` headers after its own `X-User` | `GET /api/:service`: drops client identity headers, checks role + device posture, mints a signed 60 s token for that service only |
| Service | `GET /legacy/payroll`, `/legacy/orders`: believes `X-User` | `GET /payroll`, `/orders`: verify the gateway's Ed25519 token (alg, signature, `iss`, `aud`, `exp`); payroll checks the `hr` role again |

Plus `POST /login` (gives an **opaque** token bound to a device), `POST /logout` (revokes it), and `POST /mdm/devices/:id` (the device management system reporting a laptop's health, needs `X-MDM-Key`).

Test users: **Rahul** `rahul@corp.com` / `chai-and-code-42` (employee, device `rahul-laptop`), **Priya** `priya@corp.com` / `filter-coffee-77` (employee + HR, device `priya-mbp`). Everything is in memory, so a restart resets it and creates new signing keys.

📄 **Full code: [server.js](server.js)**. Open it and read the comments, which follow the same steps as the notes above.

Install Express once (from this folder), then start the server:

```bash
npm install
```

```bash
node server.js
```

> Port 3000 busy? Run it on another port: `PORT=3069 node server.js` (Git Bash). The internal services then use port 3070. The outputs below were recorded this way. Needs Node 18+ (for the built-in `fetch`).

### Try it (Git Bash)

```bash
GW=http://localhost:3069
INT=http://127.0.0.1:3070
J="Content-Type: application/json"
```

Use `127.0.0.1` (not `localhost`) for the internal port: the internal services only listen on IPv4 loopback, and `localhost` may resolve to IPv6 `::1` on Windows.

🔑 **① Rahul logs in from his laptop** and gets an opaque token:

```bash
RAHUL=$(curl -s $GW/login -H "$J" -d '{"email":"rahul@corp.com","password":"chai-and-code-42","deviceId":"rahul-laptop"}' | sed 's/.*"access_token":"\([^"]*\)".*/\1/')
echo $RAHUL
```
→ `dhLuUDgLRi8citIaPdTI3sjYrzp1qB2YFuznwDIn480` (the JSON was `{"access_token":"…","token_type":"Bearer","expires_in":900}`)

#### Part A: the perimeter model ❌

🚫 **② Rahul asks the vulnerable gateway for payroll.** The legacy service checks `X-User` and says no:

```bash
curl -s $GW/vulnerable/api/payroll -H "Authorization: Bearer $RAHUL"
```
→ `{"error":"payroll (legacy): HR only"}`

😈 **③ He adds one header.** The gateway's spread puts his `X-User` after the real one, and the backend believes it:

```bash
curl -s $GW/vulnerable/api/payroll -H "Authorization: Bearer $RAHUL" -H "X-User: priya@corp.com"
```
→ `{"service":"payroll-service (legacy)","viewer":"priya@corp.com","payroll":[{"name":"Rahul","salary":"₹18,00,000"},{"name":"Priya","salary":"₹24,00,000"}]}`

😱 **④ From inside the network, no token is needed at all.** Skip the gateway and call the service directly:

```bash
curl -s $INT/legacy/payroll -H "X-User: priya@corp.com"
```
→ `{"service":"payroll-service (legacy)","viewer":"priya@corp.com","payroll":[{"name":"Rahul","salary":"₹18,00,000"},{"name":"Priya","salary":"₹24,00,000"}]}`

#### Part B: zero trust ✅

📦 **⑤ Rahul reads his orders through the safe gateway.** The service shows the token it got from the gateway: only for `orders-service`, valid 60 s. (`demoStolenToken` is there **only** so the next steps can play an attacker who hacked orders-service.)

```bash
curl -s -i $GW/api/orders -H "Authorization: Bearer $RAHUL" | tee orders.txt
STOLEN=$(sed -n 's/.*"demoStolenToken":"\([^"]*\)".*/\1/p' orders.txt)
```
→
```
HTTP/1.1 200 OK
Cache-Control: no-store
X-Request-Id: 801fe28b-2b4e-4bd5-9650-f7ad8c516301
...
{"service":"orders-service","orders":[{"id":"ORD-101","item":"Laptop stand","amount":"₹1,499"}],"tokenSeen":{"sub":"rahul@corp.com","aud":"orders-service","roles":["employee"],"device":"rahul-laptop","expiresIn":"60s"},"requestId":"801fe28b-2b4e-4bd5-9650-f7ad8c516301","demoStolenToken":"eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJpc3Mi…"}
```

🧹 **⑥ The same `X-User` trick on the safe gateway.** The header is dropped and Rahul is judged by his own token:

```bash
curl -s $GW/api/payroll -H "Authorization: Bearer $RAHUL" -H "X-User: priya@corp.com"
```
→ `{"error":"This API needs the \"hr\" role","requestId":"e48141d6-f2a5-4a2f-bd85-8a4558b2cc74"}`

🏢 **⑦ Skipping the gateway doesn't help any more.** The real payroll service wants a signed token, not a header:

```bash
curl -s $INT/payroll -H "X-User: priya@corp.com"
```
→ `{"error":"payroll-service: no token"}`

🎟️ **⑧ The token stolen from orders-service, replayed at payroll.** Real signature, wrong audience (run this within 60 s of step ⑤):

```bash
curl -s $INT/payroll -H "Authorization: Bearer $STOLEN"
```
→ `{"error":"payroll-service: wrong audience (made for orders-service, this is payroll-service)"}`

✏️ **⑨ So he edits the token**: `aud` → `payroll-service`, `roles` → add `hr`. Without the gateway's private key he can't re-sign it:

```bash
P=$(echo "$STOLEN" | cut -d. -f2); P=$P$(printf '%*s' $(( (4 - ${#P} % 4) % 4 )) '' | tr ' ' '=')
echo "$P" | tr '_-' '/+' | base64 -d; echo
FAKE=$(echo "$P" | tr '_-' '/+' | base64 -d | sed 's/orders-service/payroll-service/; s/\["employee"\]/["employee","hr"]/' | base64 -w0 | tr '+/' '-_' | tr -d '=')
FORGED=$(echo "$STOLEN" | cut -d. -f1).$FAKE.$(echo "$STOLEN" | cut -d. -f3)
curl -s $INT/payroll -H "Authorization: Bearer $FORGED"
```
→
```
{"iss":"https://gateway.corp.example","sub":"rahul@corp.com","aud":"orders-service","roles":["employee"],"device":"rahul-laptop","iat":1793946795,"exp":1793946855,"jti":"35361f63-d7ad-4aa8-9b1b-ef04238cb40d"}
{"error":"payroll-service: bad signature"}
```

👩‍💼 **⑩ Priya (HR) logs in from her company laptop** and can see payroll:

```bash
PRIYA=$(curl -s $GW/login -H "$J" -d '{"email":"priya@corp.com","password":"filter-coffee-77","deviceId":"priya-mbp"}' | sed 's/.*"access_token":"\([^"]*\)".*/\1/')
curl -s $GW/api/payroll -H "Authorization: Bearer $PRIYA"
```
→ `{"service":"payroll-service","viewer":"priya@corp.com","payroll":[{"name":"Rahul","salary":"₹18,00,000"},{"name":"Priya","salary":"₹24,00,000"}]}`

💻 **⑪ The MDM reports her laptop's disk encryption is off.** Same valid token, but payroll is blocked on the **next** request. Her own orders (low risk) still work:

```bash
curl -s $GW/mdm/devices/priya-mbp -H "$J" -H "X-MDM-Key: mdm-demo-key-2026" -d '{"compliant":false,"reason":"disk encryption turned off"}'
curl -s $GW/api/payroll -H "Authorization: Bearer $PRIYA"
curl -s $GW/api/orders -H "Authorization: Bearer $PRIYA"
```
→
```
{"device":"priya-mbp","compliant":false,"reason":"disk encryption turned off"}
{"error":"This API needs a healthy company device (device not compliant: disk encryption turned off)","requestId":"6bf36f6c-11f8-47ed-83a2-14b14910b53b"}
{"service":"orders-service","orders":[{"id":"ORD-102","item":"Noise-cancelling headphones","amount":"₹8,990"}],"tokenSeen":{…}, …}
```

✅ **⑫ She turns encryption back on**, and access comes back without logging in again:

```bash
curl -s $GW/mdm/devices/priya-mbp -H "$J" -H "X-MDM-Key: mdm-demo-key-2026" -d '{"compliant":true}'
curl -s $GW/api/payroll -H "Authorization: Bearer $PRIYA"
```
→
```
{"device":"priya-mbp","compliant":true,"reason":null}
{"service":"payroll-service","viewer":"priya@corp.com","payroll":[{"name":"Rahul","salary":"₹18,00,000"},{"name":"Priya","salary":"₹24,00,000"}]}
```

👋 **⑬ Rahul logs out.** His opaque token dies at the gateway at once. The internal token already handed to orders-service still works until its 60 s run out, then it's dead too:

```bash
curl -s -X POST $GW/logout -H "Authorization: Bearer $RAHUL"
curl -s $GW/api/orders -H "Authorization: Bearer $RAHUL"
curl -s $INT/orders -H "Authorization: Bearer $STOLEN"
```
→
```
{"message":"Logged out: this token is dead at the gateway right now"}
{"error":"Missing, expired or revoked access token","requestId":"781986d4-efd7-4a93-a98e-4e192423085a"}
{"service":"orders-service","orders":[{"id":"ORD-101","item":"Laptop stand","amount":"₹1,499"}],"tokenSeen":{…,"expiresIn":"37s"}, …}
```
A minute later, the same command:
```bash
curl -s $INT/orders -H "Authorization: Bearer $STOLEN"
```
→ `{"error":"orders-service: expired"}` and in the server terminal `🔒 orders-service rejected a request: expired`

**Server terminal** for the whole run (the gateway's audit log and the services' rejections):

```
🚪 API gateway on http://localhost:3069
🏢 Internal services (orders, payroll) on http://127.0.0.1:3070
🛡️  ALLOW GET /api/orders user=rahul@corp.com device=rahul-laptop rid=801fe28b
🧹 Ignored client-supplied identity header(s): x-user (rid=e48141d6)
⛔ DENY  GET /api/payroll user=rahul@corp.com device=rahul-laptop rid=e48141d6 reason="needs role hr"
🔒 payroll-service rejected a request: no token
🔒 payroll-service rejected a request: wrong audience (made for orders-service, this is payroll-service)
🔒 payroll-service rejected a request: bad signature
🛡️  ALLOW GET /api/payroll user=priya@corp.com device=priya-mbp rid=457a9a1b
📱 MDM: priya-mbp is now NOT compliant ❌ (disk encryption turned off)
⛔ DENY  GET /api/payroll user=priya@corp.com device=priya-mbp rid=6bf36f6c reason="device not compliant: disk encryption turned off"
🛡️  ALLOW GET /api/orders user=priya@corp.com device=priya-mbp rid=df2d6410
📱 MDM: priya-mbp is now compliant ✅
🛡️  ALLOW GET /api/payroll user=priya@corp.com device=priya-mbp rid=cacd4aa1
⛔ DENY  GET /api/orders user=- device=- rid=781986d4 reason="no valid access token"
```

Note how the vulnerable routes in Part A left **no** audit lines at all: nobody would ever know payroll was read.

> **Windows PowerShell users:** the single quotes in `-d '...'`, `$(…)`, `sed`, `base64` and `VAR=value node ...` work in Git Bash. In PowerShell, use Git Bash or Postman, or set the port with `$env:PORT=3069; node server.js`. Restart the server to reset everything (new signing keys too, so old internal tokens stop working).
