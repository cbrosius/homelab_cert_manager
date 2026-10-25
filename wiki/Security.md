# Security & Architecture Guide

HomeLab Cert Manager is designed with a defense-in-depth approach to secure your internal Public Key Infrastructure (PKI).

---

## 1. Cryptographic Standards

- **RSA Key Size:** All certificates (Root CA, Leaf certificates, and the manager's service certificate) use **4096-bit RSA keys** generated using Go's cryptographically secure pseudo-random number generator (`crypto/rand`).
- **Signature Algorithm:** SHA-256 with RSA (`SHA256WithRSA`).
- **Certificate Serials:** Unique 128-bit cryptographically random integers for every certificate to prevent serial collision attacks.
- **TLS Version:** Enforces TLS 1.2 and TLS 1.3 on port 8443.

---

## 2. Authentication & Session Protections

### Brute-Force Rate Limiting
- Monitors failed authentication attempts by client IP address.
- Locks out an IP address for **5 minutes** after **5 consecutive failed attempts**.
- Successful logins reset the failure counter.

### Session Inactivity Timeout
- Sessions expire automatically after inactivity (configurable between **1 and 30 minutes**, default 2 minutes).
- User activity (mouse movement, clicks, keystrokes, scrolling) refreshes the session lease.
- Server restarts immediately invalidate active session tokens stored in memory.

### Password Policy
- Enforces minimum 8 characters and maximum 72 characters (bounded by bcrypt).
- Hashed using **bcrypt** with a secure cost factor.
- Enforces an immediate mandatory password change when logging in with initial credentials.

### OpenID Connect (OIDC) & PKCE Protections
- **PKCE (Proof Key for Code Exchange, RFC 7636):** Enforced with the `S256` (SHA-256) challenge method across all OIDC authorization code flows. Eliminates code interception and injection vulnerabilities.
- **Ephemeral Verifier Cookies:** The PKCE code verifier is kept in a temporary (10-minute) `HttpOnly`, `SameSite=Lax` cookie and is immediately deleted upon token exchange completion.
- **Client Secret Encryption at Rest:** For confidential clients, OIDC client secrets are encrypted using AES-256-GCM before being stored in `data/settings.json`.
- **Client Secret Masking:** In the web UI, client secrets are masked (displaying only the first 4 characters followed by bullets, e.g. `LRnX••••••••`) to prevent shoulder surfing.
- **Public Client Compatibility:** Full support for Pocket ID public clients, allowing deployments to operate without client secrets entirely.

---

## 3. Web Application Protections

- **CSRF Defense:** Cryptographic Cross-Site Request Forgery (CSRF) tokens are validated on all state-changing endpoints (forms, uploads, deletes, certificate creation).
- **Path Traversal Protection:** All file operations sanitize certificate names, preventing directory traversal (`../`) and unauthorized filesystem access.
- **Root CA Private Key Protection:** The Root CA private key (`data/root-cert/HomeLab_Root_CA.key`) is stored in an isolated directory and cannot be downloaded or exposed via the web UI or API.
- **Protected Key Handling for CSRs:** For external CSRs, no private keys are ever collected or stored.
- **Request Size Limits:** Maximum request body is capped at 5 MB to prevent memory exhaustion DoS attacks.
- **Slowloris Mitigation:** Read, write, and idle timeouts are configured on the HTTP server to prevent resource exhaustion from slow clients.

---

## 4. HTTP Security Headers

Every response includes modern security headers:

| Header | Value | Purpose |
| :--- | :--- | :--- |
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` | Enforces HTTPS for 1 year |
| `Content-Security-Policy` | Standard restrictive CSP | Restricts script sources & injection |
| `X-Frame-Options` | `DENY` | Prevents clickjacking attacks |
| `X-Content-Type-Options` | `nosniff` | Blocks MIME-type sniffing |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | Limits referrer leakage |

---

## 5. File System Permissions

HomeLab Cert Manager sets restrictive file system permissions on startup and write operations:

| Resource Path | Permission Mask | Description |
| :--- | :--- | :--- |
| `data/root-cert/` | `0700` | Root CA directory (owner access only) |
| `data/root-cert/*.key` | `0600` | Root CA private key (owner read/write only) |
| `data/certs/*.key` | `0600` | Leaf private keys (owner read/write only) |
| `data/settings.json` | `0600` | Configuration & credentials (owner read/write only) |
| `data/certs/` | `0750` | Generated certificates directory |
| `data/certmanager-cert/` | `0750` | Manager service certificate directory |
| `*.pem` / `*.crt` | `0644` | Public certificates (readable) |

---

## 6. Container Hardening

- Runs under a dedicated, unprivileged user (`appuser`, UID `10001`) and group (`appgroup`, GID `10001`).
- The entrypoint script verifies data volume permissions and drops root privileges using `su-exec` before launching the application.