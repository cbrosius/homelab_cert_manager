# Configuration Guide

HomeLab Cert Manager features a streamlined, tabbed settings interface with deep-linking support (`#server-cert`, `#cert-defaults`, `#oidc-auth`, `#session-timeout`) and full keyboard accessibility.

---

## 1. Tabbed Settings Overview

Access settings by clicking **Settings** in the top navigation bar.

### Tab 1: Server Certificate
Manage the SSL certificate used by HomeLab Cert Manager itself:
- **DNS Names:** Enter hostnames and FQDNs for the manager (e.g. `localhost`, `certs.homelab.local`). Click **Add** to add more entries.
- **IP Addresses:** Enter internal IP addresses where the manager is reachable (e.g. `127.0.0.1`, `192.168.1.50`).
- **Recreate Certificate:** Click **Recreate HomeLab Certificate Manager Certificate** to regenerate the service certificate signed by your Root CA with all configured SANs.

![Server Certificate Settings](https://raw.githubusercontent.com/cbrosius/homelab_cert_manager/main/static/screenshots/06_settings_server_cert_dark.png)

---

### Tab 2: Certificate Defaults
Set default attributes automatically populated whenever you create a new leaf certificate:
- **Default Validity:** Certificate lifetime in years (e.g., 1, 2, or 5 years).
- **Organization (O) & Organizational Unit (OU):** Company, lab, or family name (e.g., `HomeLab`, `DevOps`).
- **Country (C):** 2-letter ISO Country code (e.g., `DE`, `US`, `AT`, `CH`).
- **State / Province (ST) & Locality / City (L):** Regional details.
- **Email Address:** Administrative contact email for the certificates.

![Certificate Defaults Settings](https://raw.githubusercontent.com/cbrosius/homelab_cert_manager/main/static/screenshots/11_settings_cert_defaults_dark.png)

---

### Tab 3: Pocket ID / OIDC Authentication
Configure Single Sign-On and Passkey authentication:
- **OIDC Toggle:** Turn OIDC authentication on or off in real-time.
- **OIDC Issuer URL:** Your provider's base endpoint (e.g. `https://pocket-id.homelab.local`).
- **Client ID:** Registered OIDC client ID (e.g. `homelab-cert-manager`).
- **Client Secret (Optional for Public Clients / PKCE):** OIDC client secret.
  - **Optional for Public Clients:** Can be left empty when using Pocket ID configured as a Public Client with PKCE (`S256`).
  - **Encrypted & Masked:** If entered for confidential clients, secrets are encrypted at rest using AES-256-GCM and masked (e.g. `LRnX••••••••`) in the UI. Click the eye icon to unmask and verify.
- **Redirect URL (Optional):** Explicit callback URL override if running behind a complex reverse proxy.

![OIDC Authentication Settings](https://raw.githubusercontent.com/cbrosius/homelab_cert_manager/main/static/screenshots/12_settings_oidc_auth_dark.png)

---

### Tab 4: Session Inactivity Timeout
To protect administrative access if a workstation is left unattended, HomeLab Cert Manager includes a configurable session inactivity timer:
- **Interactive Slider:** Adjust timeout between **1 and 30 minutes** (default: **2 minutes**).
- **Preset Buttons:** Quick-select common durations (**5m**, **10m**, **15m**, **20m**, **30m**).
- **Live Countdown Badge:** Displays remaining session time directly in the navigation bar.
- **Automatic Reset:** Any user interaction (mouse movement, keystroke, touch, or scroll) immediately resets the session timer.

![Session Inactivity Timeout Settings](https://raw.githubusercontent.com/cbrosius/homelab_cert_manager/main/static/screenshots/13_settings_session_timeout_dark.png)

---

## 2. Password Management (`/change-password`)

For improved security and streamlined navigation, password changes are handled via a dedicated page accessible from the top-right Admin dropdown menu (**Change Password**):

1. Click your username in the navigation bar and select **Change Password**.
2. Enter your current password.
3. Enter your new password and confirmation.
4. Requirements:
   - Minimum length: **8 characters**
   - Maximum length: **72 characters** (bcrypt limit)
   - Cannot match default credentials
5. Click **Change Password**.

![Change Password Screen](https://raw.githubusercontent.com/cbrosius/homelab_cert_manager/main/static/screenshots/14_change_password_dark.png)

> [!NOTE]
> On a fresh installation, the application requires an immediate password change upon your first login with `admin` / `admin`.

---

## 3. Debug Logging

By default, verbose debug logging is disabled to ensure performance and prevent log clutter.

To enable debug logging, edit `data/settings.json` on the host:

```json
{
  "debug": true
}
```

Restart the container or service. Diagnostic logs will appear in standard output and `/app/app.log`.