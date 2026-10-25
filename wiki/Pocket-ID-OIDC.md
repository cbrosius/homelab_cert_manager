# Pocket ID & OpenID Connect (OIDC) Single Sign-On Guide

HomeLab Cert Manager supports **OpenID Connect (OIDC)** and is tested with modern identity providers such as **[Pocket ID](https://pocket-id.org/)**, **Authentik**, **Keycloak**, and **Authelia**.

This allows you to sign in with **Passkeys (FIDO2 / WebAuthn, Touch ID, Face ID, YubiKey)** or central directory credentials.

---

## OIDC Setup

### 1. Register Client in Your Identity Provider

Register HomeLab Cert Manager as an OpenID Connect client in your IdP (such as Pocket ID):
- **Application Name:** `HomeLab Cert Manager`
- **Client Type:** `Public` (Recommended for Pocket ID with PKCE) or `Confidential`
- **PKCE Support:** Enforced with `S256` (SHA-256 challenge method)
- **Redirect / Callback URI:**
  ```text
  https://<YOUR-CERT-MANAGER-HOST>:8443/auth/oidc/callback
  ```
- **Allowed Scopes:** `openid`, `profile`, `email`
- Note down your **Issuer URL** and **Client ID** (and **Client Secret** if using a confidential client).

### 2. Configure HomeLab Cert Manager

1. Navigate to **Settings** > **Pocket ID / OIDC Authentication** tab (`/settings#oidc-auth`).
2. Toggle **Enable Pocket ID / OIDC Single Sign-On** to ON.
3. Fill in:
   - **OIDC Issuer URL:** The base URL of your IdP (e.g., `https://pocket-id.homelab.local`).
   - **Client ID:** The registered client ID (e.g., `homelab-cert-manager`).
   - **Client Secret (Optional):** Leave empty if using Pocket ID configured as a Public Client with PKCE.
   - **Redirect URL (Optional):** Explicit callback URL override if running behind a complex reverse proxy.
4. Click **Save OIDC Settings**.

---

## PKCE Public Client

Proof Key for Code Exchange (PKCE, RFC 7636) with SHA-256 (`S256`) is enforced by HomeLab Cert Manager for all OIDC authorization code flows.

### Advantages of PKCE Public Clients
- **No Client Secret Required:** Pocket ID supports public clients. Because the exchange is protected by dynamic cryptographic challenges generated per-request, storing and rotating static client secrets is unnecessary.
- **Interception Prevention:** Even if an authorization code is intercepted in transit, it cannot be exchanged for tokens without the one-time `code_verifier` kept securely in a short-lived `HttpOnly` cookie.
- **Confidential Client Protection:** If you do configure a client secret (e.g., for providers requiring one), it is encrypted at rest with AES-256-GCM and masked in the UI.

---

## Internal CA Trust

In many homelabs, the identity provider (such as Pocket ID) is itself secured by a certificate issued by HomeLab Cert Manager. This commonly causes a "chicken-and-egg" TLS trust issue.

HomeLab Cert Manager solves this automatically:
- During startup and runtime, outbound HTTPS connections to the OIDC Issuer URL dynamically load and trust `data/root-cert/HomeLab_Root_CA.pem`.
- Outbound token verification requests will automatically trust certificates signed by your own Root CA without needing manual container trust modification.

---

## Emergency Fallback

To prevent accidental lockouts if your OIDC provider becomes unreachable or its TLS certificate expires:

1. Navigate to the login screen (`/login`).
2. Click the link **"Sign in with local admin account"**.
3. Enter your local administrator username and password.
4. You can immediately access the dashboard and settings to renew certificates or reconfigure OIDC settings.
