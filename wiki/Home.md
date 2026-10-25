# HomeLab Cert Manager

Welcome to the **HomeLab Cert Manager** documentation wiki!

HomeLab Cert Manager is a secure, lightweight, and modern certificate authority and SSL/TLS management application written in Go. It is tailored specifically for homelabbers, self-hosters, and home network enthusiasts who want trusted HTTPS connections across all their internal devices and services without dealing with complex OpenSSL CLI commands.

![HomeLab Certificate Manager Dashboard](/static/screenshots/10_dashboard_with_certificates_dark.png)

---

## 🚀 Key Highlights & Features

- **Internal Root Certificate Authority (CA):** Generate a dedicated 4096-bit RSA HomeLab Root CA with a single click.
- **Service Certificate Generation:** Issue custom SSL/TLS certificates for Docker containers, NAS devices, hypervisors, and local web applications.
- **External CSR Signing:** Sign Certificate Signing Requests (CSRs) for hardware appliances (Proxmox VE, TrueNAS, UniFi, pfSense, IPMI) where private keys never leave the source device.
- **Pocket ID & OIDC Single Sign-On:** Modern authentication featuring Passkey and SSO support, **PKCE (RFC 7636, S256)** support for Pocket ID public clients (making client secrets optional), AES-256-GCM secret encryption at rest, automatic Root CA trust for internal identity providers, and an emergency local admin fallback.
- **PKCS#12 (.pfx) & PEM Exports:** Export full certificate bundles, individual certificates, private keys, or Windows-compatible `.pfx` containers.
- **Security Hardened by Default:**
  - 4096-bit RSA keys and 128-bit random serial numbers
  - Strict file permissions (`0600` for keys/settings, `0700` for CA)
  - Configurable session inactivity timeout (1-30 min) with live countdown badge
  - Brute-force rate limiting (5 attempts → 5 min lockout)
  - CSRF protection and modern security headers (HSTS, CSP, X-Frame-Options)
  - Unprivileged container execution (`appuser`, UID 10001) with automatic permission migration
- **Cyber-Glass UI:** Modern, responsive interface with Dark and Light mode support, search/filtering, and tabbed configuration with keyboard navigation.

---

## ⚡ Quick Start

### Running with Docker

Run the official container from GitHub Container Registry:

```bash
docker run -d \
  --name homelab_cert_manager \
  -p 8443:8443 \
  -v $(pwd)/data:/app/data \
  ghcr.io/cbrosius/homelab_cert_manager/homelab_cert_manager:latest
```

The service is available at `https://<YOUR-SERVER-IP>:8443`.

> [!NOTE]
> On first access, log in using default-password `admin`. You will immediately be prompted to configure a strong personal administrator password.

---

## 📚 Wiki Documentation Navigation

Browse the dedicated wiki guides for detailed instructions and configurations:

| Section | Description |
| :--- | :--- |
| **[Installation & Deployment](Installation-and-Deployment)** | Docker, Docker Compose, Portainer, unprivileged UID 10001, legacy file migration, and building from source. |
| **[Root CA & Client Trust](Root-CA-and-Client-Trust)** | Generating your Root CA and importing it into Windows, Linux, macOS, iOS, Android, and browsers. |
| **[Configuration Guide](Configuration)** | Tabbed settings, server certificates, session timeout slider, certificate defaults, and password management. |
| **[External CSR Signing](CSR-Signing)** | Sign external CSRs from Proxmox, TrueNAS, pfSense, switches, and hardware appliances while keeping private keys safe. |
| **[OIDC & Pocket ID SSO](OIDC-and-Pocket-ID)** | Configure Single Sign-On and Passkeys via Pocket ID or any OIDC provider, with PKCE (S256), auto-trust, and emergency recovery. |
| **[Security & Architecture](Security)** | Details on 4096-bit RSA cryptography, rate limiting, file permissions, HTTP security headers, and CSRF protection. |
| **[Frequently Asked Questions (FAQ)](FAQ)** | Common questions, troubleshooting tips, and best practices. |

---

## 🔗 Project Links

- **Main GitHub Repository:** [cbrosius/homelab_cert_manager](https://github.com/cbrosius/homelab_cert_manager)
- **Issue Tracker & Feature Requests:** [GitHub Issues](https://github.com/cbrosius/homelab_cert_manager/issues)
- **Docker Container Images:** [GitHub Container Packages](https://github.com/cbrosius/homelab_cert_manager/pkgs/container/homelab_cert_manager%2Fhomelab_cert_manager)