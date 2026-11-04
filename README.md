# Authentication Mastery

A level-by-level path through backend authentication and authorization, from the basics to enterprise SSO.
Each topic folder has a `README.md` with notes (concepts, common mistakes, interview questions) and, where useful, a small runnable Node.js example with tests.

## How to use
1. Go through the levels in order. Each one builds on the previous.
2. Open a topic folder, read its `README.md`, then run its code:
   ```bash
   node server.js
   ```
   ```bash
   node --test
   ```

## Progress
✅ done · ⬜ not started

### [Level 0: Fundamentals](level-0-fundamentals)

| # | Topic | Status |
|---|---|---|
| 01 | [Authentication vs Authorization](level-0-fundamentals/01-authentication-vs-authorization) | ⬜ |
| 02 | [HTTP Basics: Stateless, Headers, Cookies, 401 vs 403](level-0-fundamentals/02-http-stateless-headers-cookies-status-codes) | ⬜ |
| 03 | [Hashing vs Encryption vs Encoding](level-0-fundamentals/03-hashing-vs-encryption-vs-encoding) | ⬜ |
| 04 | [Password Hashing: bcrypt, argon2, scrypt, Salt, Pepper](level-0-fundamentals/04-password-hashing-bcrypt-argon2-salt-pepper) | ⬜ |
| 05 | [HTTPS / TLS](level-0-fundamentals/05-https-tls) | ⬜ |

### [Level 1: Basic Email + Password](level-1-basic-email-password)

| # | Topic | Status |
|---|---|---|
| 06 | [Signup](level-1-basic-email-password/06-signup) | ⬜ |
| 07 | [Login](level-1-basic-email-password/07-login) | ⬜ |
| 08 | [HTTP Basic Auth](level-1-basic-email-password/08-http-basic-auth) | ⬜ |
| 09 | [Session-Based Auth](level-1-basic-email-password/09-session-based-auth) | ⬜ |
| 10 | [Cookie Flags: HttpOnly, Secure, SameSite, Domain, Path, Max-Age](level-1-basic-email-password/10-cookie-flags) | ⬜ |
| 11 | [Logout](level-1-basic-email-password/11-logout) | ⬜ |

### [Level 2: Account Lifecycle](level-2-account-lifecycle)

| # | Topic | Status |
|---|---|---|
| 12 | [Email Verification](level-2-account-lifecycle/12-email-verification) | ⬜ |
| 13 | [Forgot / Reset Password](level-2-account-lifecycle/13-forgot-reset-password) | ⬜ |
| 14 | [Change Password](level-2-account-lifecycle/14-change-password) | ⬜ |
| 15 | [Remember Me](level-2-account-lifecycle/15-remember-me) | ⬜ |
| 16 | [Account Lockout & Rate Limiting](level-2-account-lifecycle/16-account-lockout-rate-limiting) | ⬜ |
| 17 | [Account Deletion / Deactivation](level-2-account-lifecycle/17-account-deletion-deactivation) | ⬜ |

### [Level 3: Token-Based Auth (JWT)](level-3-token-based-auth-jwt)

| # | Topic | Status |
|---|---|---|
| 18 | [JWT Structure, HS256 vs RS256/ES256](level-3-token-based-auth-jwt/18-jwt-structure-hs256-rs256) | ⬜ |
| 19 | [Stateless Auth with Bearer Token](level-3-token-based-auth-jwt/19-bearer-token-stateless-auth) | ⬜ |
| 20 | [Access Token](level-3-token-based-auth-jwt/20-access-token) | ⬜ |
| 21 | [Refresh Token](level-3-token-based-auth-jwt/21-refresh-token) | ⬜ |
| 22 | [Access Token Expiry & Silent Refresh](level-3-token-based-auth-jwt/22-access-token-expiry-silent-refresh) | ⬜ |
| 23 | [Refresh Token Rotation & Reuse Detection](level-3-token-based-auth-jwt/23-refresh-token-rotation-reuse-detection) | ⬜ |
| 24 | [Token Revocation & Logout with JWT](level-3-token-based-auth-jwt/24-token-revocation-logout) | ⬜ |
| 25 | [Token Storage: localStorage vs Cookie vs Memory](level-3-token-based-auth-jwt/25-token-storage-localstorage-vs-cookie) | ⬜ |
| 26 | [Multi-Device Sessions](level-3-token-based-auth-jwt/26-multi-device-sessions) | ⬜ |
| 27 | [JWT Claims Validation](level-3-token-based-auth-jwt/27-jwt-claims-validation) | ⬜ |

### [Level 4: Authorization](level-4-authorization)

| # | Topic | Status |
|---|---|---|
| 28 | [Role-Based Access Control (RBAC)](level-4-authorization/28-rbac) | ⬜ |
| 29 | [ABAC / Policy-Based Authorization](level-4-authorization/29-abac-policy-based) | ⬜ |
| 30 | [Route Guards & Middleware](level-4-authorization/30-route-guards-middleware) | ⬜ |
| 31 | [Resource Ownership Checks (IDOR)](level-4-authorization/31-resource-ownership-idor) | ⬜ |
| 32 | [API Keys](level-4-authorization/32-api-keys) | ⬜ |

### [Level 5: OAuth 2.0 & Social Login](level-5-oauth2-social-login)

| # | Topic | Status |
|---|---|---|
| 33 | [OAuth 2.0 Concepts](level-5-oauth2-social-login/33-oauth2-concepts) | ⬜ |
| 34 | [OAuth 2.0 Grant Types & PKCE](level-5-oauth2-social-login/34-oauth2-grant-types-pkce) | ⬜ |
| 35 | [state & nonce](level-5-oauth2-social-login/35-state-and-nonce) | ⬜ |
| 36 | [OpenID Connect (OIDC)](level-5-oauth2-social-login/36-openid-connect) | ⬜ |
| 37 | [Google Login](level-5-oauth2-social-login/37-google-login) | ⬜ |
| 38 | [GitHub / Facebook / Microsoft / LinkedIn Login](level-5-oauth2-social-login/38-github-facebook-microsoft-linkedin-login) | ⬜ |
| 39 | [Apple Sign-In](level-5-oauth2-social-login/39-apple-sign-in) | ⬜ |
| 40 | [Account Linking](level-5-oauth2-social-login/40-account-linking) | ⬜ |
| 41 | [Auth Libraries: Passport.js / Auth.js / Spring Security](level-5-oauth2-social-login/41-auth-libraries-passport-authjs) | ⬜ |

### [Level 6: Passwordless & MFA](level-6-passwordless-mfa)

| # | Topic | Status |
|---|---|---|
| 42 | [Magic Link Login](level-6-passwordless-mfa/42-magic-link) | ⬜ |
| 43 | [Email / SMS OTP](level-6-passwordless-mfa/43-email-sms-otp) | ⬜ |
| 44 | [TOTP (Authenticator App)](level-6-passwordless-mfa/44-totp-authenticator-app) | ⬜ |
| 45 | [MFA Flow](level-6-passwordless-mfa/45-mfa-flow) | ⬜ |
| 46 | [WebAuthn / Passkeys / FIDO2](level-6-passwordless-mfa/46-webauthn-passkeys) | ⬜ |

### [Level 7: Security Hardening](level-7-security-hardening)

| # | Topic | Status |
|---|---|---|
| 47 | [CSRF](level-7-security-hardening/47-csrf) | ⬜ |
| 48 | [XSS & Token Theft](level-7-security-hardening/48-xss-token-theft) | ⬜ |
| 49 | [CORS with Credentials](level-7-security-hardening/49-cors-with-credentials) | ⬜ |
| 50 | [Session Fixation & Hijacking](level-7-security-hardening/50-session-fixation-hijacking) | ⬜ |
| 51 | [Timing Attacks & User Enumeration](level-7-security-hardening/51-timing-attacks-user-enumeration) | ⬜ |
| 52 | [Credential Stuffing Defense](level-7-security-hardening/52-credential-stuffing-defense) | ⬜ |
| 53 | [JWT Attacks](level-7-security-hardening/53-jwt-attacks) | ⬜ |
| 54 | [Secrets Management & Key Rotation](level-7-security-hardening/54-secrets-management-key-rotation) | ⬜ |
| 55 | [Audit Logs & Login Alerts](level-7-security-hardening/55-audit-logs-login-alerts) | ⬜ |
| 56 | [OWASP Auth Cheat Sheets](level-7-security-hardening/56-owasp-cheat-sheets) | ⬜ |

### [Level 8: Enterprise & Advanced](level-8-enterprise-advanced)

| # | Topic | Status |
|---|---|---|
| 57 | [SSO Concepts: IdP vs SP](level-8-enterprise-advanced/57-sso-concepts-idp-sp) | ⬜ |
| 58 | [SAML 2.0](level-8-enterprise-advanced/58-saml-2) | ⬜ |
| 59 | [SAML Attacks](level-8-enterprise-advanced/59-saml-attacks) | ⬜ |
| 60 | [OIDC SSO: Okta / Entra ID / Auth0 / Keycloak](level-8-enterprise-advanced/60-oidc-sso-okta-azure-auth0-keycloak) | ⬜ |
| 61 | [Single Logout (SLO)](level-8-enterprise-advanced/61-single-logout) | ⬜ |
| 62 | [SCIM Provisioning](level-8-enterprise-advanced/62-scim-provisioning) | ⬜ |
| 63 | [LDAP / Active Directory](level-8-enterprise-advanced/63-ldap-active-directory) | ⬜ |
| 64 | [Kerberos](level-8-enterprise-advanced/64-kerberos) | ⬜ |
| 65 | [Multi-Tenant Auth](level-8-enterprise-advanced/65-multi-tenant-auth) | ⬜ |
| 66 | [Own Authorization Server](level-8-enterprise-advanced/66-own-authorization-server) | ⬜ |
| 67 | [Token Exchange & Impersonation](level-8-enterprise-advanced/67-token-exchange-impersonation) | ⬜ |
| 68 | [Service-to-Service Auth / mTLS](level-8-enterprise-advanced/68-service-to-service-mtls) | ⬜ |
| 69 | [Zero Trust & API Gateway Auth](level-8-enterprise-advanced/69-zero-trust-api-gateway) | ⬜ |
| 70 | [Token Introspection & Revocation](level-8-enterprise-advanced/70-token-introspection-revocation) | ⬜ |
| 71 | [Fine-Grained Authorization: Zanzibar / OpenFGA / OPA](level-8-enterprise-advanced/71-fine-grained-authz-zanzibar-opa) | ⬜ |

## License
See [LICENSE](LICENSE).
