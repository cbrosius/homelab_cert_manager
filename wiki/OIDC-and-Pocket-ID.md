# Pocket ID & OpenID Connect (OIDC) Single Sign-On Guide

HomeLab Cert Manager supports **OpenID Connect (OIDC)** and is tested with modern identity providers such as **[Pocket ID](https://pocket-id.org/)**, **Authentik**, **Keycloak**, and **Authelia**.

This allows you to sign in with **Passkeys (FIDO2 / WebAuthn, Touch ID, Face ID, YubiKey)** or central directory credentials.

---

## 1. Identity Provider Setup

Register HomeLab Cert Manager as an OpenID Connect client in your identity provider (e.g. Pocket ID):

- **Application Name:** `HomeLab Cert Manager`
- **Client Type:** `Public` (Recommended for Pocket ID with PKCE) or `Confidential`
- **PKCE Support:** Enforced with `S256` (SHA-256 challenge method)
- **Redirect / Callback URI:**
  ```text
  https://<YOUR-CERT-MANAGER-HOST>:8443/auth/oidc/callback
  ```
- **Allowed Scopes:** `openid`, `profile`, `email`
- Note down your **Issuer URL** and **Client ID** (and **Client Secret** if using a confidential client).

> [!TIP]
> **No Client Secret Needed for Pocket ID:**
> Because HomeLab Cert Manager implements PKCE (RFC 7636, S256), you can configure HomeLab Cert Manager as a **Public Client** in Pocket ID. You do **not** need to generate or enter a Client Secret!

---

## 2. Configuration Options

You can configure OIDC using either the Web UI or Docker environment variables.

### Option A: Web UI Configuration (Settings Tab)
1. Navigate to **Settings** > **Pocket ID / OIDC Authentication** tab.
2. Toggle **Enable Pocket ID / OIDC Single Sign-On** to ON.
3. Fill in:
   - **OIDC Issuer URL:** The base URL of your identity provider (e.g., `https://pocket-id.homelab.local`).
   - **Client ID:** The registered client ID (e.g., `homelab-cert-manager`).
   - **Client Secret (Optional):**
     - **Leave empty** if using Pocket ID configured as a **Public Client** with PKCE.
     - Enter your client secret if using a confidential client. Secrets are masked (e.g. `LRnX••••••••`) and encrypted at rest with AES-256-GCM. Use the eye icon to unmask and verify.
   - **Redirect URL (Optional):** Explicit callback URL override if running behind a complex reverse proxy.
4. Click **Save OIDC Settings**.

![Pocket ID and OIDC Authentication Settings](/static/screenshots/12_settings_oidc_auth_dark.png)

### Option B: Docker Environment Variables
You can also supply settings directly via your container environment (`docker-compose.yml` or CLI):

| Variable | Description | Example |
| :--- | :--- | :--- |
| `OIDC_ENABLED` | Set to `true` to activate OIDC | `true` |
| `OIDC_ISSUER_URL` | Base URL of your OIDC IdP | `https://pocket-id.homelab.local` |
| `OIDC_CLIENT_ID` | Registered Client ID | `homelab-cert-manager` |
| `OIDC_CLIENT_SECRET` | Client Secret (optional for Pocket ID Public Clients / PKCE) | `your-secret-here` |
| `OIDC_REDIRECT_URL` | Optional callback URL override | `https://certs.homelab.local:8443/auth/oidc/callback` |

---

## 3. PKCE & Security Architecture

HomeLab Cert Manager implements **Proof Key for Code Exchange (PKCE, RFC 7636)** with the **S256** challenge method for all OIDC login flows.

### How the PKCE Flow Works
1. **Login Initiation (`/auth/oidc/login`):**
   - The server generates a cryptographically secure random 32-byte CSRF state and an OAuth2 code verifier.
   - It computes the SHA-256 code challenge (`code_challenge_method=S256`).
   - The server stores the state and verifier in temporary, short-lived (10-minute) `HttpOnly`, `SameSite=Lax` cookies (`oidc_state` and `oidc_verifier`).
   - The browser is redirected to the IdP's authorization endpoint with the `code_challenge`.
2. **User Authentication:**
   - The user authenticates with their identity provider (e.g. via Passkey or WebAuthn in Pocket ID).
   - The IdP redirects the user back to `/auth/oidc/callback` with an authorization code and the state parameter.
3. **Verification & Token Exchange (`/auth/oidc/callback`):**
   - HomeLab Cert Manager verifies the `state` matches the cookie state.
   - It extracts the `oidc_verifier` cookie and immediately purges both cookies.
   - It calls the IdP token endpoint to exchange the authorization code, passing `oauth2.VerifierOption(cookieVerifier)`.
   - The IdP verifies that `SHA256(verifier) == code_challenge` before returning identity tokens. This ensures authorization codes cannot be intercepted or injected.

### Client Secret Protection at Rest & In-Transit
- **Optional for Public Clients:** When using Pocket ID or similar IdPs supporting public clients, the client secret can be omitted entirely.
- **AES-256-GCM Encryption at Rest:** If a client secret is configured, it is encrypted using AES-256-GCM with a host-derived key before being persisted in `data/settings.json`.
- **UI Masking:** In the web interface, the client secret is displayed with only the first 4 characters visible (e.g., `LRnX••••••••`), preventing shoulder-surfing and DOM snooping.

---

## 4. Automatic Internal Root CA Trust (Solving the Chicken-and-Egg Issue)

In many self-hosted homelabs, the OIDC identity provider (such as Pocket ID) is itself secured by an SSL certificate issued by HomeLab Cert Manager.

Normally, this creates a **chicken-and-egg problem**: the certificate manager's internal Go HTTP client would reject connections to `https://pocket-id.homelab.local` because the local Root CA is not part of the standard container trust store.

**HomeLab Cert Manager automatically solves this:**
- The internal OIDC authentication client automatically detects and loads your local Root CA (`data/root-cert/HomeLab_Root_CA.pem`).
- It dynamically appends your HomeLab Root CA to its runtime TLS trust pool.
- You do **not** need to manually mount custom CA files or run `update-ca-certificates` inside the container!

---

## 5. Emergency Local Admin Fallback

What happens if your OIDC provider is down, or its certificate expired and you need HomeLab Cert Manager to renew it?

HomeLab Cert Manager provides a built-in recovery mechanism:
- On the `/login` screen, a discreet link labeled **"Sign in with local admin account"** is always available.
- Clicking this reveals the standard username and password fields.
- You can always log in locally with your administrator credentials to troubleshoot, recreate certificates, or update OIDC settings.