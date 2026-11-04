# 05. HTTPS / TLS

## Notes

### Why this topic matters

Everything you'll build in auth (passwords, cookies, session IDs, JWTs) gets sent **over the network**.

With plain **HTTP**, all of it travels as **plain text**. Anyone on the same Wi-Fi, your internet provider, or a hacked router can **read it and steal it**.

**HTTPS** fixes this. Without HTTPS, **no auth system is secure**, no matter how good your password hashing is.

---

### The one-line answer

- **HTTP** = sending a **postcard**. Anyone who handles it can read it. 📬
- **HTTPS** = sending a **sealed, tamper-proof envelope** to a **verified address**. 🔒

**HTTPS = HTTP + TLS.** TLS (Transport Layer Security) is the layer that does the encryption. HTTP itself doesn't change. It just travels inside a secure tunnel.

> You may also hear **SSL**. SSL is the **old, broken** version of TLS. People still say "SSL certificate" out of habit, but today it's always **TLS** (versions 1.2 and 1.3).

---

### The problem: what HTTP looks like to an attacker

Imagine you log in on **free café Wi-Fi** over plain HTTP. An attacker on the same network sees this, **exactly as typed**:

```
POST /login HTTP/1.1
Host: shop.example.com
Content-Type: application/json

{ "email": "rahul@mail.com", "password": "secret123" }
```

And on every request after that:

```
GET /orders HTTP/1.1
Cookie: sessionId=abc123      ← attacker copies this and is now logged in as you
```

This is called a **Man-in-the-Middle (MITM) attack**: someone sits between you and the server, reading or even **changing** the traffic.

With HTTPS, the same attacker only sees random-looking bytes:

```
17 03 03 00 4a 8f 2c e1 9b 77 d4 0a ...   ← useless garbage without the key
```

---

### The 3 things HTTPS guarantees

| Guarantee | Question it answers | Without it... |
|---|---|---|
| 🔒 **Encryption** (privacy) | "Can anyone **read** my data?" | Passwords and cookies can be stolen |
| ✅ **Integrity** | "Did anyone **change** my data on the way?" | An attacker could inject malware into the page or change "send ₹100" into "send ₹10,000" |
| 🪪 **Authentication** (identity) | "Am I really talking to **bank.com**?" | A fake server could pretend to be your bank |

Remember topic 03? HTTPS uses **all of it**:
- **Asymmetric** encryption and signatures → to prove the server's identity and agree on a key
- **Symmetric** encryption (AES) → to encrypt the actual data quickly
- **Hashing / HMAC** → to detect changes

---

### Certificates: the server's passport 🛂

How does your browser know it's talking to the **real** `bank.com` and not an attacker?

The server shows a **TLS certificate**, like a **passport**.

#### Real-life example: checking a passport

At the airport, the officer doesn't just trust you when you say "I'm Rahul." They check:
1. Is the **name** on the passport yours? → Does the certificate's domain match `bank.com`?
2. Was it issued by a **trusted government**? → Was it signed by a trusted **Certificate Authority (CA)**?
3. Is it **expired**? → Is the certificate still valid?

#### What's inside a certificate

| Field | Example |
|---|---|
| Domain name | `bank.com`, `*.bank.com` |
| Public key | The server's public key (from a key pair) |
| Issuer (CA) | Let's Encrypt, DigiCert, Google Trust Services |
| Valid from / to | 2026-01-01 → 2026-04-01 |
| CA's signature | Proves the CA really issued it |

#### Certificate Authorities (CAs) and the chain of trust

Your operating system and browser come with a built-in list of **trusted root CAs**. A certificate is trusted because it's **signed by someone your browser already trusts**:

```
Root CA (pre-installed in your browser/OS) ✅
   └── signs → Intermediate CA
                 └── signs → bank.com's certificate
```

If anything in this chain is wrong (bad signature, wrong domain, expired), the browser shows a big warning: **"Your connection is not private."**

#### The private key is the real secret

- The **certificate** (with the public key) is **public**. Every visitor gets a copy.
- The **private key** stays **only on the server**. It proves that the server really owns the certificate.

If the private key leaks, an attacker can impersonate your site. Guard it like a password.

#### Getting a certificate

- **Let's Encrypt**: free, automated, and used by most of the web
- **Cloud providers**: AWS, Cloudflare, Vercel, etc. often handle it for you automatically
- **Self-signed**: you create it yourself. Fine for **local development**, but browsers **won't trust it** in production.

---

### The TLS handshake (simplified)

Before any HTTP data is sent, the browser and server do a quick **handshake** to agree on how to talk securely. In TLS 1.3 this takes just **one round trip**.

```
Browser                                              Server
   │                                                    │
   │ ── 1. "Hello! I support these ciphers,  ────────►  │
   │       here's my half of the key exchange"          │
   │                                                    │
   │ ◄── 2. "Hello! Let's use this cipher.  ─────────── │
   │        Here's my CERTIFICATE + my half             │
   │        of the key exchange + proof I own           │
   │        the private key"                            │
   │                                                    │
   │  3. Browser checks the certificate:                │
   │     ✅ signed by a trusted CA?                     │
   │     ✅ domain matches?                             │
   │     ✅ not expired?                                │
   │                                                    │
   │  4. Both sides now compute the SAME secret key     │
   │     (without ever sending it over the network!)    │
   │                                                    │
   │ ══════ 5. Encrypted HTTP traffic (AES) ══════════  │
   │       POST /login { password... } 🔒               │
```

#### Real-life example: mixing paint 🎨

How can two people agree on a secret over a public channel? A classic way to picture it:
1. Both start with the same public color (yellow).
2. Each secretly adds their **own private color** and sends the mix to the other.
3. Each adds their **private color again** to what they received.
4. Both end up with the **same final color**, but someone watching only saw the mixes and **can't un-mix them**.

This is the idea behind **Diffie-Hellman key exchange**, which TLS uses.

#### Why use both asymmetric and symmetric?

| | Used for | Why |
|---|---|---|
| **Asymmetric** (certificate, key exchange) | Handshake only | Proves identity + safely creates a shared key, but it's **slow** |
| **Symmetric** (AES) | All the actual data | **Fast**, but both sides need the same key, which the handshake just gave them |

---

### What HTTPS hides, and what it doesn't

| Hidden (encrypted) 🔒 | Still visible to the network 👀 |
|---|---|
| Full URL path and query: `/orders?id=42` | The **domain name**: `bank.com` |
| Headers: `Cookie`, `Authorization` | The server's **IP address** |
| Request and response **body** | **When** you connected and **how much** data moved |
| Passwords, tokens, form data | |

⚠️ HTTPS protects data **in transit** only. Once it reaches the server, it's decrypted. So:
- URLs (including query strings) often end up in **server logs**, browser history, and analytics. **Never put tokens or passwords in the URL.**
- HTTPS doesn't protect a hacked server or a stolen database. That's why we still hash passwords.

---

### HTTPS and auth: what you must do as a backend developer

#### 1. Use HTTPS everywhere, for every page and every API

Not just the login page. If **any** request carries a cookie or token over plain HTTP, it can be stolen.

#### 2. Mark auth cookies `Secure`

```
Set-Cookie: sessionId=abc123; Secure; HttpOnly; SameSite=Lax
```

`Secure` means: **the browser will never send this cookie over plain HTTP.** (Topic 10 covers cookie flags in detail.)

#### 3. Redirect HTTP → HTTPS

If someone types `http://shop.com`, send a `301` redirect to `https://shop.com`.

#### 4. Turn on HSTS

There's a gap: the **very first** `http://` request (before the redirect) is still unprotected. **HSTS** (HTTP Strict Transport Security) tells the browser:

> "For the next year, **only ever** talk to me over HTTPS. Don't even try HTTP."

```
Strict-Transport-Security: max-age=31536000; includeSubDomains
```

After the browser sees this header once (over HTTPS), it automatically upgrades every future `http://` link to `https://`.

#### 5. Avoid mixed content

An HTTPS page that loads a script over `http://` is **mixed content**. The attacker can change that script and take over the page. Browsers block most of it, but load **everything** over HTTPS.

#### 6. Know about TLS termination

In real deployments, your Node.js app often **doesn't** handle TLS itself:

```
Browser ══HTTPS══► Load balancer / Nginx / Cloudflare ──HTTP──► Your Node.js app
                   (TLS ends here: "TLS termination")       (inside a private network)
```

This means:
- Your app sees requests as plain HTTP. The proxy tells you the original protocol with the `X-Forwarded-Proto: https` header.
- In Express, set `app.set("trust proxy", 1)`, or features like `Secure` cookies and `req.secure` won't work correctly.
- The network between the proxy and your app must be private and trusted.

#### 7. Never turn off certificate checks

When calling other APIs from your backend, you may hit certificate errors. **Don't** "fix" them by disabling verification:

```js
// ❌ NEVER do this in real code. It turns off the "identity" check, so MITM becomes possible.
process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
https.request({ ..., rejectUnauthorized: false });
```

Fix the real problem instead (expired cert, wrong hostname, missing CA).

---

### Common beginner mistakes

1. **Thinking the 🔒 padlock means a site is safe or honest.**
   It only means the connection is encrypted and the domain matches. A phishing site like `paypa1-login.com` can have a valid certificate too.

2. **Using HTTPS only on the login page.**
   The session cookie sent on every other page can still be stolen. Use HTTPS everywhere.

3. **Putting tokens or passwords in the URL.**
   `?token=abc123` ends up in logs and browser history, even with HTTPS.

4. **Disabling certificate verification** (`rejectUnauthorized: false`).
   This removes protection against MITM attacks completely.

5. **Forgetting the `Secure` flag on cookies.**
   The browser may then send the cookie over plain HTTP.

6. **No HSTS.**
   The first HTTP request can be hijacked before the redirect happens (an "SSL stripping" attack).

7. **Committing the private key (`key.pem`) to Git.**
   Anyone with the key can impersonate your server. Add `*.pem` and `*.key` to `.gitignore`.

8. **Letting certificates expire.**
   Your site suddenly shows scary warnings to every user. Use automatic renewal (Let's Encrypt / certbot / your cloud provider).

9. **Thinking HTTPS replaces password hashing.**
   HTTPS protects data on the network. Hashing protects data in your database. You need both.

---

### Interview questions

1. **What's the difference between HTTP and HTTPS?**
   HTTPS is HTTP running inside a TLS connection. TLS adds encryption, integrity, and server authentication. HTTP sends everything as plain text.

2. **What are the three guarantees TLS gives?**
   Confidentiality (nobody can read the data), integrity (nobody can change it unnoticed), and authentication (you're talking to the real server, proven by its certificate).

3. **What is a TLS certificate, and who issues it?**
   A file that binds a domain name to a public key, signed by a trusted Certificate Authority (like Let's Encrypt). Browsers trust it because they trust the CA.

4. **Explain the TLS handshake briefly.**
   The client and server say hello and agree on a cipher. The server sends its certificate, and the client verifies it. Both use a key exchange (Diffie-Hellman) to compute the same session key, and then all data is encrypted with fast symmetric encryption.

5. **Why does TLS use both asymmetric and symmetric encryption?**
   Asymmetric crypto is slow but solves identity and key sharing. Symmetric crypto is fast, so it's used for the actual data once the handshake has created a shared key.

6. **What is HSTS and why is it needed?**
   A response header that tells browsers to use only HTTPS for a domain for a set time. It prevents SSL-stripping attacks on the first HTTP request.

7. **Does HTTPS hide which website I'm visiting?**
   No. The domain name (through SNI and DNS) and the IP address are still visible. The path, headers, and body are hidden.

8. **What is TLS termination?**
   When a proxy or load balancer handles TLS and forwards plain HTTP to the app servers. The app must trust the proxy's `X-Forwarded-Proto` header to know the original request was HTTPS.

9. **What is a man-in-the-middle attack, and how does HTTPS prevent it?**
   An attacker intercepts traffic between client and server. HTTPS prevents it because the attacker can't decrypt the data, and can't impersonate the server without a valid certificate for that domain.

---

### Quick recap

- **HTTPS = HTTP + TLS.** SSL is the old name.
- TLS gives **encryption + integrity + server identity**
- The **certificate** is the server's passport, signed by a trusted **CA**
- The **handshake** uses asymmetric crypto to agree on a key, then **AES** encrypts the data
- The domain and IP are still visible. The path, headers, cookies, and body are hidden.
- For auth: **HTTPS everywhere**, `Secure` cookies, **HSTS**, HTTP → HTTPS redirect, and **never** disable certificate checks
- HTTPS protects data **in transit**. You still need **hashing** for data **at rest**.

## Code

A local HTTPS server using only Node.js's built-in `https` module, with an HTTP → HTTPS redirect and HSTS.

### Step 1: create a self-signed certificate (for local development only)

```bash
openssl req -x509 -newkey rsa:2048 -nodes -keyout key.pem -out cert.pem -days 365 -subj "/CN=localhost"
```

This creates two files:
- `key.pem` → the **private key** (secret! never commit it)
- `cert.pem` → the **certificate** (public)

> Windows: `openssl` comes with Git Bash. Run the command there.

### Step 2: the server

```js
// server.js
const fs = require("fs");
const http = require("http");
const https = require("https");

const options = {
  key: fs.readFileSync("key.pem"),   // private key: proves we own the certificate
  cert: fs.readFileSync("cert.pem"), // certificate: sent to every visitor
};

// HTTPS server: everything here travels encrypted
https.createServer(options, (req, res) => {
  res.writeHead(200, {
    // HSTS: "browser, only use HTTPS for this site for the next year"
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    // Secure: this cookie will never be sent over plain HTTP
    "Set-Cookie": "sessionId=abc123; Secure; HttpOnly; SameSite=Lax",
  });
  res.end("🔒 Hello over HTTPS!\n");
}).listen(8443, () => console.log("HTTPS on https://localhost:8443"));

// HTTP server: does nothing except redirect to HTTPS
http.createServer((req, res) => {
  const host = (req.headers.host || "localhost").split(":")[0];
  res.writeHead(301, { Location: `https://${host}:8443${req.url}` });
  res.end();
}).listen(8080, () => console.log("HTTP  on http://localhost:8080 (redirects to HTTPS)"));
```

```bash
node server.js
```

### Step 3: try it

```bash
curl -i http://localhost:8080/profile
```
→ `301 Moved Permanently` with `Location: https://localhost:8443/profile`

```bash
curl https://localhost:8443
```
→ **fails** with a certificate error. This is TLS doing its job! curl doesn't trust a self-signed certificate.

```bash
curl --cacert cert.pem -i https://localhost:8443
```
→ `200` with the `Strict-Transport-Security` and `Set-Cookie` headers. Here we told curl to trust **our** certificate explicitly. This is the right way, and it's different from turning verification off.

```bash
openssl s_client -connect localhost:8443 -CAfile cert.pem < /dev/null 2>/dev/null | grep -E "^subject|^issuer|Cipher is|Verify return code" | sed "s/^ *//" | sort -u
```
→ shows what happened in the handshake:

```
New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384    ← TLS 1.3 + AES (symmetric) for the data
Verify return code: 0 (ok)                        ← certificate checked and trusted
issuer=CN=localhost                               ← who signed it (ourselves = self-signed)
subject=CN=localhost                              ← which domain the certificate is for
```

You can also open `https://localhost:8443` in a browser. You'll see a "Not secure / Your connection is not private" warning because the certificate is self-signed. That's expected in local development.

> Add `*.pem` to `.gitignore` so you never commit the private key.
