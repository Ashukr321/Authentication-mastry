# 40. Account Linking

## Notes

### What is account linking?

Rahul signed up at PrintKaro with email + password. Later he clicks "Log in with Google", and next month "Log in with GitHub". **Account linking** decides whether those are **one account with three ways in**, or three separate accounts. Get it wrong one way and Rahul ends up with three half-empty accounts. Get it wrong the other way and **Vikram** gets into Rahul's account just by showing an email address.

> **One-line answer:** store each login method as an **identity** (`provider + provider_user_id`) that points to **one user**. Link a new identity to an existing user only when the person has **proved they own that user**: they're **logged in (recently)** and ask for it, **or** they log in to the existing account with its password to confirm, **or** (automatic) **both sides verified the same email** with a provider you trust. Never link on an unverified email, never move an identity between users, and always email the owner when something is linked.

---

### Why does it matter?

| Problem | What goes wrong |
|---|---|
| No linking at all | Rahul has 3 accounts: his orders are in one, his saved address in another |
| Linking by **any** email a provider sends | Vikram sets his Microsoft email to Rahul's (nOAuth, topic 38) and logs in **as Rahul** |
| Linking to an account whose email was **never verified** | **Pre-account hijacking:** Vikram signs up with Priya's email first; when Priya uses Google, she lands in Vikram's account, and Vikram's password still works |
| Linking without a **recent login** | Someone at Rahul's unlocked laptop connects **their** GitHub to Rahul's account: a permanent back door |
| Link flow without `state` bound to the session (topic 35) | Vikram tricks Rahul's browser into finishing **Vikram's** link: Vikram's Google now logs into Rahul's account |
| Unlinking the **last** login method | Rahul locks himself out forever |
| **Moving** an identity from one account to another | One click hands someone else's login to the wrong account |

---

### Real-life example: a bank locker with several keys 🔑

Rahul has a locker at his bank in Pune.

- The **locker** is his PrintKaro account. Each **key** is a way in: his password, his Google login, his GitHub login.
- Getting a **new key cut** (linking) needs **Rahul in person, with his existing key, today**. A stranger saying "my name is also Rahul Sharma" doesn't get a key: same name ≠ same person (same email claim ≠ same owner).
- If a stranger shows a **government ID** (a trusted provider's verified email) **and** the bank had verified Rahul's ID too, the bank can match them. A **visiting card** with Rahul's name (an unverified email) proves nothing.
- If someone opened a locker in Priya's name **without any ID check** (an unverified signup), and the real Priya arrives with her passport, the bank doesn't give her that locker (the stranger has its key). It gives Priya her **own** locker and takes the name off the fake one.
- Every new key, the bank **SMSes** the locker owner: "A new key was made. Not you? Call us."
- You can hand back a key, but **not the last one**.

---

### The data model

```
users                                user_identities
┌──────────────┐                    ┌────────────────────────────────────────┐
│ id           │◄───────────────────│ user_id                                │
│ email UNIQUE │                    │ provider        ┐ UNIQUE together      │
│ email_verified                    │ provider_user_id┘                      │
│ password_hash (NULL = none)       │ email (snapshot), linked_at            │
│ name         │                    └────────────────────────────────────────┘
└──────────────┘
```

- **One user, many identities.** Login with a provider = find the identity by `(provider, provider_user_id)` → its `user_id`. Email plays **no part** once an identity is linked.
- `(provider, provider_user_id)` is **unique**: one Google account can belong to only **one** PrintKaro user.
- The identity's email is a **snapshot** for display; the user's own `email` is what you send mail to.

---

### The flow, step by step

#### 📊 Diagrams

Open **[diagrams.html](diagrams.html)** in your browser (just double-click the file) to see:

- **Flow diagram**: the decision tree for "a new identity just logged in"
- **Data flow**: explicit linking from Settings, and confirming a link with the password
- **Pre-account hijacking**: what the attack is, and how the demo stops it

In short: `known identity → its user` · `new identity + verified account with that email + trusted verified provider → auto-link` · `new identity + verified account, untrusted claim → "log in with your password to connect"` · `unverified account with that email + trusted provider → that account loses the email` · `otherwise → new user`.

---

### Step 1: Start every provider flow with an intent

```js
s.pending.set(state, { provider, intent: "login" | "link", userId: s.userId, expiresAt });
```

- **`login`**: logged out, "Log in with Google".
- **`link`**: logged in, Settings → "Connect GitHub". Requires a **recent** login (for example the last 5 minutes), like changing a password (topic 14).
- `state` is bound to **this session** and remembers the provider, the intent and the **user** who started a link (topic 35). A callback can't be replayed into another session or account.

---

### Step 2: A known identity logs straight in

```js
const existing = identities.get(`${provider}|${providerUserId}`);
if (existing) return logIn(existing.userId);
```

No email lookup at all. If Rahul changes his Google email tomorrow, he still lands in the same account.

---

### Step 3: Explicit linking (the safest way)

The user is logged in, recently, and clicked "Connect GitHub". At the callback:

| Case | What to do |
|---|---|
| Session's user ≠ the user who started the link | ❌ Refuse ("session changed, start again") |
| Identity already belongs to **another** user | ❌ **409**, never move it |
| Identity already belongs to **this** user | ✅ Nothing to do |
| Identity is new | ✅ Link it, **email the owner** |

Here the email of the GitHub account **doesn't matter**: Rahul can connect a GitHub account that uses a completely different email. He proved who he is by being logged in.

---

### Step 4: A new identity at login: the decision

```js
const owner = userByEmail(identity.email);
const trusted = PROVIDERS[provider].trustEmail && identity.emailVerified;

if (owner?.emailVerified && trusted)  → link automatically, log in, email the owner   // 4a
else if (owner?.emailVerified)        → "account exists: log in with your password to connect" // 4b
else if (owner && trusted)            → owner (unverified) loses the email               // 4c
→ create a new user for this identity                                                    // 4d
```

| ✅ Auto-link only when | ❌ Never auto-link when |
|---|---|
| The provider says `email_verified` **and** you trust it for that address (Google for `@gmail.com`, a Workspace domain with `hd`) | The provider gives no "verified" flag (Facebook), or its email is admin-controlled (Microsoft `email`, nOAuth) |
| **Your** account's email is verified too | Your account's email was never verified |
| You **email the owner** afterwards | The match is by name, username or phone number |

Which providers count as "trusted" is **your decision**, per provider. The demo trusts Google only; GitHub and Microsoft go through 4b.

---

### Step 5: "Account exists: prove it's you" (4b)

The safe answer to "this provider says it's rahul@gmail.com, but I can't trust that":

1. Keep the new identity as a **pending link** in this session (short expiry), and tell the user to log in.
2. The user logs in with the **existing** account's method (password, or an already-linked provider).
3. Show "Connect Microsoft (rahul@gmail.com) to this account?" and link only after they **confirm** (`POST /link/confirm`).

Vikram can't do step 2, so his Microsoft account never gets near Rahul's.

**Tradeoff:** the "account exists" message tells the caller that an account uses this email (account enumeration, topic 51). It's usually accepted here, because the caller already presented that email through a provider. If it isn't acceptable for your app, create a separate account instead and let the user link later from Settings.

---

### Step 6: Pre-account hijacking (4c)

The attack (from the 2022 research paper *"Pre-hijacked accounts"*):

1. **Vikram** signs up at PrintKaro with **priya@gmail.com** and **his** password. He can't verify it (it's Priya's inbox), so it stays **unverified**.
2. **Priya** later clicks "Log in with Google". Google says `priya@gmail.com`, verified.
3. A naive app links Google to the existing account. Priya uses PrintKaro happily, saving addresses and cards… and **Vikram logs in with his password** and sees everything.

The fix:

- **Never link to an account whose email is unverified.**
- When a **trusted, verified** provider proves the email, the unverified account **loses its claim** to the address (and its old verification links stop working). Priya gets a **new, clean** account.
- Also: don't let unverified accounts do much (topic 12), and expire them.

---

### Step 7: Unlinking

- Needs a **recent login** too.
- **Never remove the last way in**: if the user has no password and this is their only identity, refuse ("set a password or connect another account first").
- Email the owner: "GitHub was disconnected."

---

### 🤔 Tricky parts

**1. "Same email" is not "same person".**
An email from a provider is a **claim**. It becomes proof only when a provider you trust verified it **and** your own record of that email was verified. Everything else needs the user to prove ownership of the account.

**2. Merging two existing accounts is a different, harder thing.**
If Rahul already has two full accounts (orders in both), linking an identity isn't enough: you need a **merge** that moves orders, settles conflicts (two addresses, two plans) and deletes one account. Require the user to log in to **both** in one session, show what will happen, and keep an audit log. Many apps just don't support it.

**3. Emails change.**
Rahul changes his Google email. Nothing breaks, because his identity is keyed by `sub`. Update the identity's email snapshot on login; change the **user's** email only through your own verified change-email flow.

**4. Re-authentication.**
"Logged in 30 days ago" is not enough to add a new way in. Ask for the password again (or a fresh provider login) within the last few minutes.

**5. Always notify.**
Every link and unlink sends an email to the account's verified address. It's the only way a victim learns about a back door.

**6. Libraries.**
Auth.js has an `allowDangerousEmailAccountLinking` option: the name says it all. It's off by default; turn it on only for providers you trust for email (Step 4).

---

### Common beginner mistakes

1. **Linking by email alone.**
   nOAuth, unverified GitHub emails, Facebook emails without a "verified" flag: all become account takeover.

2. **Linking to an unverified account.**
   Pre-account hijacking. Only verified-to-verified, with a trusted provider.

3. **Keying users by email instead of having an identities table.**
   One user can have many identities; one identity belongs to one user.

4. **No re-authentication before linking or unlinking.**
   A borrowed laptop becomes a permanent back door.

5. **Link flow without `state` bound to the session and the user.**
   Link CSRF: the victim's account gets the attacker's identity (topic 35).

6. **"Moving" an identity that already belongs to someone else.**
   Answer 409; the other user must unlink it themselves.

7. **Letting users remove their last login method.**
   Lockout and a support ticket.

8. **Not telling the user.**
   Send "X was connected / disconnected" emails.

9. **Auto-merging two full accounts silently.**
   Merges need both logins, a preview and an audit log.

---

### Interview questions

1. **How do you model users who can log in with password, Google and GitHub?**
   A `users` table and a `user_identities(provider, provider_user_id, user_id)` table with a unique index on `(provider, provider_user_id)`. Login looks up the identity, not the email.

2. **When is it safe to link a social login to an existing account automatically?**
   Only when the provider says the email is verified, you trust that provider to verify that address, and your account's email is verified too. Notify the owner afterwards. Otherwise ask the user to log in to the existing account and confirm.

3. **What is pre-account hijacking?**
   The attacker creates an account with the victim's email before the victim does (unverified, with the attacker's password). When the victim later signs in with a social provider and the app links them, the attacker keeps access. Prevent it by never linking to unverified accounts and dropping unverified claims when the real owner proves the email.

4. **Why require re-authentication before linking?**
   Linking adds a permanent way into the account. A stale or stolen session shouldn't be enough to add one.

5. **How does `state` protect an account-linking flow?**
   It ties the callback to the session (and user) that started the link, so an attacker can't make the victim's browser finish the attacker's link (attaching the attacker's identity to the victim's account).

6. **A user tries to connect a Google account that's already connected to another user. What do you do?**
   Refuse with a clear error. Never move it automatically; the other account must unlink it first.

7. **Can a user unlink every login method?**
   No. Keep at least one: a password or one identity.

8. **What's the difference between linking and merging?**
   Linking adds an identity to one user. Merging combines two existing users' data, which needs both logins, conflict handling and an audit trail.

---

### Quick recap

- **users** + **user_identities(provider, provider_user_id UNIQUE)**: one user, many ways in
- Known identity → its user. **Email is not involved**
- **Explicit link** from Settings: logged in + **recent auth** + `state` bound to session and user
- **Auto-link** only: trusted provider + `email_verified` **and** your account's email verified; then **notify**
- Otherwise: **"log in with your password to connect"**, then confirm
- Unverified account with that email + trusted provider → it **loses the email** (pre-hijacking)
- Never **move** an identity (409); never unlink the **last** way in
- Next: auth libraries that do this for you (topic 41)

## Code

One **Express** file, two apps:

| Port | App |
|---|---|
| `3000` | 🖨️ **PrintKaro**: password signup/login, "Log in with …", "Connect …" in Settings, confirm and unlink |
| `3001` | 🧪 **Mock Google, GitHub and Microsoft**: tiny fakes that return an already-normalized identity |

Topics 37–39 showed how to verify each provider's real answer. Here every mock already returns the **normalized identity** from topic 38's adapters, so the code can focus on **linking**. The test users:

| Provider | User | Email | Verified? | PrintKaro trusts this provider's email? |
|---|---|---|---|---|
| Google | `rahul` | rahul@gmail.com | ✅ | ✅ |
| Google | `priya` | priya@gmail.com | ✅ | ✅ |
| GitHub | `rahul` | rahul@gmail.com | ✅ | ❌ (our choice: proof by password) |
| Microsoft | `rahul` | rahul@gmail.com | ❌ | ❌ |
| Microsoft | `vikram` | rahul@gmail.com (**fake**, his own tenant) | ❌ | ❌ |

📄 **Full code: [server.js](server.js)**. Part 1 is the mocks, Part 2 is PrintKaro. Read the comments, which follow the same steps as the notes above.

Install the dependencies once (from this folder), then start the server:

```bash
npm install
```

```bash
node server.js
```

> Port 3000 busy? Run it on other ports: `PORT=3040 node server.js` (Git Bash) uses **3040** and **3041**. The outputs below were recorded that way, so they show those ports.

### Try it in the browser

Open **http://localhost:3000** → **Log in with: Google** → **Continue as priya** → `/me` shows a new account with one identity. The "Connect" buttons do the same for a logged-in user.

### Try it with curl (Git Bash)

```bash
APP=http://localhost:3000
red() { curl -s -o /dev/null -w "%{redirect_url}" "$@"; }
flow() {   # flow <cookie-jar> <login|link> <provider> <mock user>
  L=$(red -X POST -c $1.jar -b $1.jar "$APP/$2/$3")
  [ -z "$L" ] && { curl -s -X POST -b $1.jar "$APP/$2/$3" -w " %{http_code}\n"; return; }
  CB=$(red "$L&mock_user=$4")
  curl -s -c $1.jar -b $1.jar -L "$CB" -w " %{http_code}\n"
}
pw() {     # pw <cookie-jar> <email> <password>
  curl -s -c $1.jar -b $1.jar $APP/login -H "Content-Type: application/json" -d "{\"email\":\"$2\",\"password\":\"$3\"}" -w " %{http_code}\n"
}
```

**① Rahul signs up with a password and verifies his email:**

```bash
curl -s $APP/signup -H "Content-Type: application/json" -d '{"email":"rahul@gmail.com","password":"rahul-pass-123","name":"Rahul Sharma"}'; echo
curl -s "$APP/verify-email?token=<token from the terminal>"; echo
```
→ `{"message":"Check your inbox to verify your email"}` and `{"verified":"rahul@gmail.com"}`

**② Automatic link:** "Log in with Google" as Rahul. Google is trusted and verified, his account is verified: same account.

```bash
flow g login google rahul
```
→
```
{"id":"acct_4SS_jw","name":"Rahul Sharma","email":"rahul@gmail.com","emailVerified":true,"hasPassword":true,"identities":[{"provider":"google","providerUserId":"107691503500061507151","email":"rahul@gmail.com","linkedAt":"2026-11-05T06:12:03.591Z"}]} 200
```
Terminal:
```
🔗 Google (107691503500061507151) linked to acct_4SS_jw [automatic: both sides verified the same email]
📧 To: rahul@gmail.com: "Google was connected to your PrintKaro account. Not you? Secure your account."
```

**③ Explicit link** from Settings: log in with the password, then "Connect GitHub". From now on, GitHub logs into the same account:

```bash
pw r rahul@gmail.com rahul-pass-123
flow r link github rahul
flow gh login github rahul
```
→
```
{"loggedIn":"acct_4SS_jw"} 200
{"id":"acct_4SS_jw",...,"identities":[{"provider":"google",...},{"provider":"github","providerUserId":"583231","email":"rahul@gmail.com","linkedAt":"2026-11-05T06:12:03.875Z"}]} 200
{"id":"acct_4SS_jw",...}  200          ← GitHub login, same account. Terminal: 👋 GitHub → acct_4SS_jw
```

**④ Vikram's Microsoft account claims Rahul's email** (nOAuth). Microsoft's email isn't trusted, so PrintKaro asks for proof, which Vikram can't give:

```bash
flow v login microsoft vikram
curl -s -b v.jar -X POST $APP/link/confirm -w " %{http_code}\n"
```
→
```
{"error":"account_exists","message":"An account with rahul@gmail.com already exists. Log in with your password (POST /login), then POST /link/confirm to connect Microsoft."} 409
{"error":"Log in first"} 401
```

**⑤ The real Rahul does the same with his Microsoft account**, and proves it's him with his password:

```bash
flow m login microsoft rahul
pw m rahul@gmail.com rahul-pass-123
curl -s -c m.jar -b m.jar -X POST $APP/link/confirm -w " %{http_code}\n"
flow mm login microsoft rahul
```
→
```
{"error":"account_exists",...} 409
{"loggedIn":"acct_4SS_jw","pendingLink":"Microsoft (rahul@gmail.com) wants to connect to this account. POST /link/confirm to connect it."} 200
{"id":"acct_4SS_jw",...,"identities":[{"provider":"google",...},{"provider":"github",...},{"provider":"microsoft","providerUserId":"9188040d-6c67-4c5b-b112-36a304b66dad:00000000-0000-0000-66f3-3332eca7ea81",...}]} 200
{"id":"acct_4SS_jw",...} 200           ← Microsoft now logs straight in. Terminal: 👋 Microsoft → acct_4SS_jw
```

**⑥ Pre-account hijacking:** Vikram signs up with **Priya's** email first. Then Priya uses Google:

```bash
curl -s $APP/signup -H "Content-Type: application/json" -d '{"email":"priya@gmail.com","password":"vikram-pass-999"}'; echo
flow p login google priya
pw x priya@gmail.com vikram-pass-999
```
→
```
{"message":"Check your inbox to verify your email"}
{"id":"acct_IjYxtg","name":"Priya Nair","email":"priya@gmail.com","emailVerified":true,"hasPassword":false,"identities":[{"provider":"google",...}]} 200   ← her OWN new account
{"error":"Wrong email or password"} 401        ← Vikram's password no longer gets him anywhere near priya@gmail.com
```
Terminal: `🛡️  Pre-hijack blocked: unverified acct__J5NNQ loses its claim on priya@gmail.com`

**⑦ The guard rails:**

```bash
flow p link google rahul                                                  # Priya tries to connect RAHUL's Google
curl -s -b r.jar "$APP/callback/github?code=x&state=forged" -w " %{http_code}\n"   # a callback this session didn't start
curl -s -b p.jar -X DELETE $APP/me/identities/google -w " %{http_code}\n"         # Priya removes her only way in
curl -s -b r.jar -X DELETE $APP/me/identities/microsoft -w " %{http_code}\n"      # Rahul removes Microsoft: fine
flow z link github rahul                                                  # "Connect" while logged out
```
→
```
{"error":"This Google account is already connected to a different PrintKaro account"} 409
{"error":"This login didn't start here (state mismatch)"} 400
{"error":"This is your only way to log in. Set a password or connect another account first."} 400
{"id":"acct_4SS_jw",...,"identities":[{"provider":"google",...},{"provider":"github",...}]} 200
{"error":"Log in first, then connect accounts"} 401
```
Terminal: `✂️  Microsoft unlinked from acct_4SS_jw` and `📧 To: rahul@gmail.com: "Microsoft was disconnected from your PrintKaro account."`

**⑧ Re-authentication:** the "recent login" window is 5 minutes. To see it expire quickly, start with `REAUTH_SECONDS=3 node server.js`, sign up and log in, wait 4 seconds, then:

```bash
curl -s -X POST -b r.jar $APP/link/github -w " %{http_code}\n"
curl -s -b r.jar -X DELETE $APP/me/identities/google -w " %{http_code}\n"
```
→
```
{"error":"Please log in again to connect an account (re-authentication required)"} 401
{"error":"Please log in again to disconnect an account (re-authentication required)"} 401
```

> **Windows PowerShell users:** the variables, `red()` / `flow()` / `pw()` functions, cookie jars and `PORT=... node ...` work in Git Bash. In PowerShell, use the browser, Git Bash, or `$env:PORT=3040; node server.js`.
