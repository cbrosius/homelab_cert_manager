# Settings Reference

The **Settings** page (`/settings`) allows you to configure server certificates for the web interface, certificate default attributes, Single Sign-On (SSO) via OpenID Connect (OIDC) / Pocket ID, and session security timeouts.

> [!NOTE]
> Changing default certificate values only affects **newly created** certificates. Existing certificates in your list remain unchanged until you renew or recreate them.

---

## Server Certificate
<a id="server-cert"></a>

Manage the TLS/HTTPS certificate used by HomeLab Cert Manager itself.

### Server Certificate DNS Hostnames
* **Anchor:** `#server-cert-dns`
* **Aliases:** `#dns-hostnames`, `#server-certificate-dns-hostnames`
* **Format:** Comma or Enter-separated list of hostnames/FQDNs (e.g. `localhost`, `certs.homelab.local`, `certmanager.lan`).
* **Description:** Defines the domain names and hostnames embedded into the Certificate Manager's own certificate as DNS Subject Alternative Names (SANs). Whenever you access the web interface via a domain or hostname, that name must be listed here to prevent browser certificate mismatch errors.

### Server Certificate IP Addresses
* **Anchor:** `#server-cert-ips`
* **Aliases:** `#ip-addresses`, `#server-certificate-ip-addresses`
* **Format:** Enter-separated list of IPv4 or IPv6 addresses (e.g. `127.0.0.1`, `192.168.1.50`, `10.0.0.5`).
* **Description:** Specifies the IP addresses embedded into the certificate as IP SANs. If you access the application directly via an IP address (e.g. `https://192.168.1.50:8443`), this IP must be configured here so modern browsers validate the certificate successfully.

### Recreate Server Certificate
* **Anchor:** `#recreate-server-cert`
* **Aliases:** `#recreate-server-certificate`
* **Description:** Generates a new 4096-bit RSA TLS certificate for the web interface signed by your local HomeLab Root CA, incorporating all configured DNS names and IP addresses. The server seamlessly reloads the new TLS certificate without interrupting existing connections.

---

## Certificate Defaults
<a id="cert-defaults"></a>

These values pre-fill the creation forms when issuing new leaf service certificates or signing external CSRs.

### Default Validity Period
* **Anchor:** `#validity-period`
* **Aliases:** `#cert-validity-days`, `#default-validity-period`
* **Default:** `1` Year (365 days)
* **Range:** 1 to 100 years (Recommended: 1 year).
* **Important Browser Limit (398 Days):** Modern browsers (Chrome, Edge, Safari, Firefox) and mobile operating systems (iOS, Android) enforce a strict maximum validity limit of **398 days** for leaf server certificates. Setting service certificate validity beyond 398 days will cause modern browsers to reject the certificate with `ERR_CERT_VALIDITY_TOO_LONG`.

### Organization
* **Anchor:** `#organization`
* **X.509 Field:** `O` (Organization Name)
* **Examples:** `HomeLab`, `MyNetwork`, `Internal Services`
* **Description:** Identifies your homelab or organization. This name is displayed in browser certificate viewer windows and OS trust stores.

### Organizational Unit
* **Anchor:** `#organizational-unit`
* **X.509 Field:** `OU` (Organizational Unit Name)
* **Examples:** `Infrastructure`, `Docker Services`, `Security`
* **Description:** An optional subdivision within your organization used to categorize certificates.

### Country
* **Anchor:** `#country`
* **X.509 Field:** `C` (Country Name)
* **Format:** Exactly 2 uppercase letters following ISO 3166-1 alpha-2 (e.g. `DE`, `US`, `AT`, `CH`, `FR`, `GB`).
* **Description:** Two-letter country code embedded in the certificate subject.

### State or Province
* **Anchor:** `#state-or-province`
* **Aliases:** `#province`, `#state`
* **X.509 Field:** `ST` (State or Province Name)
* **Examples:** `Rhineland-Palatinate`, `Bavaria`, `California`
* **Description:** The regional state or province where your homelab is located.

### Locality
* **Anchor:** `#locality`
* **X.509 Field:** `L` (Locality / City Name)
* **Examples:** `Landau`, `Berlin`, `Home`
* **Description:** The municipality, city, or locality name for the certificate subject.

### Admin Email
* **Anchor:** `#admin-email`
* **Aliases:** `#email`
* **Examples:** `admin@homelab.local`, `sysadmin@home.arpa`
* **Description:** Optional administrative contact email address associated with the certificate.

### Root Validity Days
* **Anchor:** `#root-validity-days`
* **Default:** `3650` (approx. 10 years)
* **Description:** Defines the lifetime of the Root CA certificate itself. Because the Root CA certificate must be manually installed and trusted across your client devices, a long validity period (10–30 years) is recommended to prevent needing to re-distribute the Root CA frequently.

### Key Size
* **Anchor:** `#key-size`
* **Default:** `4096` bits (RSA)
* **Description:** Cryptographic key size used for generating RSA private keys. 4096 bits provides an optimal balance of robust long-term security and modern cryptographic standards.

---

## Single Sign-On (OIDC) / Pocket ID
<a id="oidc-auth"></a>

HomeLab Cert Manager supports optional Single Sign-On (SSO) and Passkey authentication via **Pocket ID** or any OpenID Connect (OIDC) compliant identity provider.

### OIDC Enabled
* **Anchor:** `#oidc-enabled`
* **Environment Override:** `OIDC_ENABLED=true|false`
* **Description:** Toggles OIDC authentication. When enabled, a "Sign in with Pocket ID / OIDC" button appears on the sign-in page.
* **Emergency Local Fallback:** Enabling OIDC **never disables** the local administrator password login. The local login form remains accessible as an emergency fallback on the login screen, preventing chicken-and-egg lockouts if your OIDC provider or its network becomes unavailable.

### OIDC Issuer URL
* **Anchor:** `#oidc-issuer-url`
* **Environment Override:** `OIDC_ISSUER_URL`
* **Examples:** `https://pocket-id.homelab.local`
* **Description:** The base endpoint URL of your OIDC provider. Homelab Cert Manager queries `/.well-known/openid-configuration` to discover endpoints automatically.
* **Automatic Root CA Trust:** If your Pocket ID server is secured by an SSL certificate issued by HomeLab Cert Manager, the backend automatically trusts your local `data/root-cert/` Root CA, preventing TLS handshake errors.

### OIDC Client ID
* **Anchor:** `#oidc-client-id`
* **Environment Override:** `OIDC_CLIENT_ID`
* **Examples:** `homelab-cert-manager`
* **Description:** The unique client identifier configured in your identity provider.

### OIDC Client Secret
* **Anchor:** `#oidc-client-secret`
* **Environment Override:** `OIDC_CLIENT_SECRET`
* **Required:** Optional when using PKCE (RFC 7636).
* **Using Pocket ID Public Clients (PKCE):** Homelab Cert Manager implements PKCE (`S256`) on all OIDC authentication flows. You can configure your client in Pocket ID as a **Public Client** and leave this field completely empty. For confidential clients requiring a secret, enter it here. Values are encrypted at rest using AES-256-GCM and masked in the UI.

### OIDC Redirect URL
* **Anchor:** `#oidc-redirect-url`
* **Environment Override:** `OIDC_REDIRECT_URL`
* **Format:** `https://<cert-manager-host>:8443/auth/oidc/callback`
* **Description:** The callback URL where your identity provider returns the user after authentication. If left blank, the application automatically constructs this from the incoming request host.

---

## Session Timeout

### Session Inactivity Timeout
* **Anchor:** `#session-timeout`
* **Aliases:** `#timeout-minutes`, `#session-inactivity-timeout`
* **Default:** `2` Minutes
* **Range:** `1` to `30` Minutes
* **Description:** Controls the inactivity duration before an idle administrator session is automatically terminated. Any user interaction (mouse move, keyboard click, scroll, touch) resets the timer. The remaining time is visible in the top navigation bar's live countdown pill badge.

---

## Administrator Security

### Change Password
* **Anchor:** `#change-password`
* **Location:** Accessible via `/change-password` or the top-right profile dropdown.
* **Requirements:** Minimum 8 characters, maximum 72 characters (bcrypt limit).
* **Description:** Changes the local `admin` account password. On fresh installations, changing the default password (`admin`) is mandatory before issuing certificates.