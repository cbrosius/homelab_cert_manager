# Homelab Cert Manager

## Overview

Homelab Cert Manager is a Go project designed to manage SSL/TLS certificates for your homelab environment.
This tool can generate a Homelab Root-Certificate and additional certificates for your homelab-services like docker-containers or devices.

All you need to do is import and trust the generated Root-Certificate once to your PC and generate a new certificate for each of your services.

These certificates can then be used to configure SSL for or replace the self-signed cert of your HomeLAB services.

Then your internal sites show secure connections (without warnings) in all modern browsers.

> [!TIP]
> For in-depth documentation, OS-specific Root CA installation guides (Windows, macOS, Linux, iOS, Android), appliance CSR workflows, and OIDC/Pocket ID setup, visit the official **[Project Wiki](https://github.com/cbrosius/homelab_cert_manager/wiki)**.

## Features

- **Internal Certificate Management:** Generate and manage internal SSL/TLS certificates.
- **CSR Signing (Certificate Signing Requests):** Upload or paste external CSRs from third-party appliances, switches, and servers (Proxmox, TrueNAS, etc.) to sign them with your Root CA without handling private keys.
- **Pocket ID / OIDC SSO Authentication:** Optional Passkey and Single Sign-On support via Pocket ID or any OpenID Connect provider with built-in Root CA trust and emergency local fallback.
- **PKCE & Secret Encryption:** RFC 7636 (S256) PKCE enforcement for OIDC authorization flows, support for public clients with optional client secret, AES-256-GCM encryption at rest for stored secrets, and UI secret masking.
- **Configurable Session Timeout:** Inactivity timeout (1–30 minutes, default 2 minutes) with live top-bar countdown badge that automatically resets upon user activity.
- **Robust Security:** CSRF protection, brute-force login rate limiter, strong password policies, and path traversal prevention.
- **Hardened HTTP & TLS:** Modern security headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options), Slowloris protection, request body size limits, and TLS 1.2+ encryption.
- **4096-bit RSA Keys:** Strong encryption with 128-bit random serial numbers for all certificates.
- **Ease of Use:** Simple web interface for generating, viewing, and exporting certificates.
- **Dark/Light Mode:** Toggle between dark and light themes with preference persistence.
- **Search/Filter:** Easily search and filter certificates in the table.
- **Tabbed Settings Page:** Configure certificate defaults, server certificates, OIDC SSO, and session timeouts with interactive slider controls.
- **Integrated Offline Help & Docs:** Built-in Markdown help viewer (`/help`) rendered locally without CDN dependencies, featuring same-window navigation, real-time topic filtering, and contextual `?` help icons linking directly to exact setting explanations.
- **PKCS#12 Export:** Export certificates in `.pfx` format for Windows and IIS services.
- **Unprivileged Container:** Runs securely in Docker under an unprivileged user (`appuser`, UID 10001).

## Screenshots

### Certificates Dashboard
*Overview of Root CA, application server certificate, issued certificates, and CSR badges.*

| Dark Mode | Light Mode |
|:---:|:---:|
| ![Dashboard Dark](static/screenshots/10_dashboard_with_certificates_dark.png) | ![Dashboard Light](static/screenshots/10_dashboard_with_certificates_light.png) |

### Interactive Certificate Creator
*Create certificates with live domain validation, SAN auto-population, and custom validity periods.*

| Dark Mode | Light Mode |
|:---:|:---:|
| ![Create Certificate Dark](static/screenshots/08_create_certificate_dark.png) | ![Create Certificate Light](static/screenshots/08_create_certificate_light.png) |

### External CSR Signing
*Sign certificate signing requests from Proxmox, TrueNAS, switches, and other homelab appliances.*

| Dark Mode | Light Mode |
|:---:|:---:|
| ![Sign CSR Modal Dark](static/screenshots/09_sign_csr_modal_dark.png) | ![Sign CSR Modal Light](static/screenshots/09_sign_csr_modal_light.png) |

### Pocket ID / OIDC Single Sign-On
*Configure OpenID Connect authentication with automatic internal Root CA trust and local admin fallback.*

| Dark Mode | Light Mode |
|:---:|:---:|
| ![OIDC Settings Dark](static/screenshots/12_settings_oidc_auth_dark.png) | ![OIDC Settings Light](static/screenshots/12_settings_oidc_auth_light.png) |

### Session Inactivity Timeout
*Interactive slider setting timeout between 1 and 30 minutes with live countdown badge.*

| Dark Mode | Light Mode |
|:---:|:---:|
| ![Session Timeout Dark](static/screenshots/13_settings_session_timeout_dark.png) | ![Session Timeout Light](static/screenshots/13_settings_session_timeout_light.png) |

<details>
<summary><strong>View Additional Setup & Configuration Screenshots</strong></summary>

#### Initial Login & Mandatory Password Setup
| Dark Mode | Light Mode |
|:---:|:---:|
| ![Login Dark](static/screenshots/01_initial_login_dark.png) | ![Login Light](static/screenshots/01_initial_login_light.png) |
| ![Password Change Dark](static/screenshots/02_mandatory_password_change_dark.png) | ![Password Change Light](static/screenshots/02_mandatory_password_change_light.png) |

#### Root CA Creation
| Dark Mode | Light Mode |
|:---:|:---:|
| ![Generate Root CA Dark](static/screenshots/04_generate_root_ca_dark.png) | ![Generate Root CA Light](static/screenshots/04_generate_root_ca_light.png) |

#### Server Certificate Configuration
| Dark Mode | Light Mode |
|:---:|:---:|
| ![Server Cert Dark](static/screenshots/06_settings_server_cert_dark.png) | ![Server Cert Light](static/screenshots/06_settings_server_cert_light.png) |

#### Certificate Defaults Configuration
| Dark Mode | Light Mode |
|:---:|:---:|
| ![Cert Defaults Dark](static/screenshots/11_settings_cert_defaults_dark.png) | ![Cert Defaults Light](static/screenshots/11_settings_cert_defaults_light.png) |

#### Dedicated Password Change
| Dark Mode | Light Mode |
|:---:|:---:|
| ![Change Password Dark](static/screenshots/14_change_password_dark.png) | ![Change Password Light](static/screenshots/14_change_password_light.png) |

</details>

## Security Features

Homelab Cert Manager includes comprehensive security measures:

- **Session Inactivity Timeout:** Configurable between 1 and 30 minutes (default 2 minutes). A real-time countdown badge in the top navigation displays remaining time, seamlessly resets on user interaction, and invalidates session keys on server reboot.
- **Login Rate Limiter:** Protects against brute-force attacks by locking out an IP address for 5 minutes after 5 consecutive failed login attempts.
- **Password Security Policy:** Enforces strong passwords (8–72 characters, bcrypt hashed), forbids default credentials, and enforces a mandatory password change on first login.
- **CSRF Protection:** All forms and state-changing API endpoints require persistent, cryptographically secure CSRF tokens.
- **Path Traversal Prevention:** Sanitizes all user inputs and certificate filenames to prevent directory traversal attacks.
- **Root CA Protection:** Prevents unauthorized download or disclosure of Root CA private key files.
- **OIDC Secret Encryption at Rest:** Client secrets stored in `data/settings.json` are encrypted using authenticated AES-256-GCM with automatic transparent migration of plaintext secrets.
- **PKCE (RFC 7636):** Enforces SHA-256 code challenges (`S256`) for OpenID Connect authorization flows, preventing authorization code interception attacks and enabling secure integration with Public Clients.
- **HTTP Security Headers:**
  - `Strict-Transport-Security` (HSTS) with 1-year max-age and subdomains
  - `Content-Security-Policy` (CSP)
  - `X-Frame-Options: DENY` (clickjacking protection)
  - `X-Content-Type-Options: nosniff` (MIME sniffing prevention)
  - `Referrer-Policy: strict-origin-when-cross-origin`
- **Cookie Security:** Cookies are configured with `HttpOnly`, `SameSite=Lax`, and `Secure` attributes.
- **Server & DoS Hardening:** HTTP server read, write, and idle timeouts mitigate Slowloris attacks, and request bodies are capped at 5 MB.
- **Secure File Permissions:**
  - Private keys: `0600` (owner read/write only)
  - Settings file (`data/settings.json`): `0600` (owner read/write only)
  - Certificates: `0644` (world-readable)
  - CA directory (`data/root-cert`): `0700` (owner only)
  - Data directories: `0750` (group readable)
- **Strong Cryptography:** 4096-bit RSA keys, 128-bit random certificate serial numbers, and TLS 1.2 minimum version.

## Getting Started

### Using Docker

To use Homelab Cert Manager, download and run the Docker image:

```bash
docker pull ghcr.io/cbrosius/homelab_cert_manager/homelab_cert_manager:latest
docker run -p 8443:8443 -v $(pwd)/data:/app/data ghcr.io/cbrosius/homelab_cert_manager/homelab_cert_manager:latest
```

The container runs securely as an unprivileged user (`appuser`, UID 10001) with the persistent `/app/data` volume.

> [!NOTE]
> **Migrating from Legacy Versions (v1.x / root-based container):**
> Older versions of this container ran as `root` (UID 0), creating files owned by `root:root` with restricted permissions. 
> The container entrypoint automatically detects legacy root-owned files in `/app/data` (and `/app/app.log`) and updates ownership to `appuser:appgroup` before dropping root privileges.
> If you prefer to update file ownership manually on the host before starting, you can run:
> ```bash
> sudo chown -R 10001:10001 ./data
> ```

### Building from Source

Alternatively, you can clone the repository and compile the project locally:

```bash
git clone https://github.com/cbrosius/homelab_cert_manager.git
cd homelab_cert_manager
go build -o homelab_cert_manager ./cmd/cert_manager
./homelab_cert_manager
```

### Initial Setup

When Homelab Cert Manager has started, navigate to `https://<IP-Of-HomeLAB-Cert-Manager>:8443`

1. Log in using **admin/admin** as initial Username/Password. You will be prompted immediately to set a secure password (minimum 8 characters).
2. Click **Create Root Certificate** to generate your HomeLAB Root CA.
3. Download the Root CA `.pem` file and import it into the Trusted Root Certification Authorities store on your devices.
4. (Optional) Replace the self-signed HomeLAB Cert Manager Certificate with a CA-signed one.
5. Create certificates for your internal servers, containers, or NAS devices.
6. Deploy the certificates (`.pem` / `.key` or `.pfx`) to your services.

## Configuration

### Session Inactivity Timeout

The session inactivity timeout can be customized via the **Settings** page under **Session Inactivity Timeout**:
- Valid range: **1 to 30 minutes** (default: **2 minutes**).
- A real-time countdown badge is displayed in the navigation header.
- Interacting with the application (mouse movement, clicks, keypresses, scrolls) resets the timer.
- Changes survive service restarts and are persisted in `data/settings.json`.

### Certificate Defaults

Default certificate attributes can be configured through the **Settings** page:

- Validity period (years)
- Organization & Organizational Unit
- Country (2-letter ISO), State, Location
- Email Address

### External CSR Signing (Certificate Signing Requests)

For hardware appliances, managed switches, hypervisors, and storage systems (e.g. Proxmox, TrueNAS, pfSense, Ubiquiti) where the private key is generated directly on the device and must not leave it:

1. Generate a standard Certificate Signing Request (CSR) on your appliance.
2. In Homelab Cert Manager, click **Sign CSR** on the dashboard.
3. Either upload the `.csr` file or paste the raw `-----BEGIN CERTIFICATE REQUEST-----` PEM block.
4. Specify the desired validity period (in days) and submit.
5. The application validates the cryptographic signature, extracts all Subject attributes and Subject Alternative Names (SANs - DNS, IP, URI, Email), and signs the certificate using your HomeLab Root CA.
6. The signed certificate is saved in your certificate dashboard with a distinct **CSR** badge. Since the private key remains on the target device, the "Download Key" option is cleanly disabled.

### Pocket ID / OIDC Single Sign-On (SSO)

Homelab Cert Manager supports optional Passkey and Single Sign-On (SSO) via [Pocket ID](https://pocket-id.org/) or any standard OpenID Connect (OIDC) identity provider.

#### 1. Setup in Pocket ID / Identity Provider
- **Client Type:** Public (PKCE) or Confidential
- **PKCE Support:** PKCE with `S256` code challenge is enforced for all OIDC login flows. The Client Secret is completely optional when configured as a Public Client in Pocket ID.
- **Redirect / Callback URI:** `https://<cert-manager-host>:8443/auth/oidc/callback`
- **Scopes:** `openid`, `profile`, `email`

#### 2. Configuration Options
You can configure OIDC either in the web interface under **Settings -> Pocket ID / OIDC Authentication** or via Docker environment variables:

| Environment Variable | Description | Example |
| --- | --- | --- |
| `OIDC_ENABLED` | Enable or disable OIDC SSO (`true`/`false`) | `true` |
| `OIDC_ISSUER_URL` | Base URL of your OIDC provider | `https://pocket-id.homelab.local` |
| `OIDC_CLIENT_ID` | Client ID registered in your provider | `homelab-cert-manager` |
| `OIDC_CLIENT_SECRET` | Client Secret (optional for Pocket ID Public Clients / PKCE) | `your-secret-here` |
| `OIDC_REDIRECT_URL` | Explicit callback URL override (optional) | `https://certs.homelab.local:8443/auth/oidc/callback` |

#### 3. Automatic Internal Root CA Trust
A common issue in self-hosted homelabs is a "chicken-and-egg" certificate error when your OIDC provider itself uses a certificate issued by your internal Root CA. 

Homelab Cert Manager solves this automatically:
- Its internal OIDC HTTP client automatically loads and trusts your local Homelab Root CA (`data/root-cert/HomeLab_Root_CA.pem` / `data/rootCA.crt`).
- No need to inject extra certificates into container trust stores.

#### 4. Emergency Local Admin Fallback
To prevent lockouts if your OIDC provider is offline or its own certificate has expired:
- The standard local username and password login remains available on the login page via a discreet **Local admin fallback** link.
- You can always sign in locally with your administrator password to renew certificates or troubleshoot services.

### Debug Logging

To enable debug logging, add the following to `data/settings.json`:

```json
{
  "debug": true
}
```

Debug logging is disabled by default for security.

## File Permissions

The application ensures proper permission masks for all data:

| Path | Permission | Description |
| --- | --- | --- |
| `data/root-cert` | 0700 | CA private key storage (owner only) |
| `data/certs` | 0750 | Issued certificates |
| `data/certmanager-cert` | 0750 | Application's own certificate |
| `data/settings.json` | 0600 | Configuration file (owner read/write only) |
| Private Key files (`*.key`) | 0600 | Private keys (owner read/write only) |
| Certificate files (`*.pem`) | 0644 | Public certificates |

## Security Considerations

- Always access the application via HTTPS (TLS is enforced on port 8443).
- Change the default admin password immediately on first login.
- Keep the `data/root-cert` directory secure, as it contains your Root CA private key.
- Regularly back up the `data` directory — losing the Root CA private key will invalidate your PKI chain.
- The `data/settings.json` file contains password hashes and session configuration; never commit it to public version control repositories.

## License

See [LICENSE](LICENSE) file for details.
