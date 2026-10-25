# Service Certificates Guide

HomeLab Cert Manager allows you to issue, manage, and download SSL/TLS certificates for all your self-hosted homelab applications, Docker containers, hypervisors, and local network devices.

---

## Create Certificate
<a id="create-certificate"></a>

### Creating a New Service Certificate

1. On the main certificate list (`/certificates`), click the **Create Certificate** button in the top action bar.
2. Fill in the certificate properties:
   - **Common Name (CN):** The primary domain or host identifier (e.g. `vaultwarden.homelab.local`, `portainer.lan`, `192.168.1.100`).
   - **Validity Period (Years):** Choose the desired validity (default: 1 year).
   - **Subject Attributes:** Organization, Unit, Country, State, and Locality (pre-filled from [Settings](Settings#cert-defaults)).
3. Configure your Subject Alternative Names (see below).
4. Click **Create Certificate**.

![Create Certificate Screen](/static/screenshots/08_create_certificate_dark.png)

The manager creates a dedicated 4096-bit RSA key pair, embeds all requested SANs, signs the certificate with your internal Root CA, and securely stores the files in `data/certs/`.

---

## SAN Configuration
<a id="san-configuration"></a>

### Configuring Subject Alternative Names (SANs)

Modern web browsers (including Chrome, Firefox, Edge, Safari, and curl) require and strictly validate **Subject Alternative Names (SANs)**. The legacy `Common Name` (CN) field alone is no longer considered sufficient for hostname verification.

When creating a certificate, specify all ways clients may reach your service:

- **DNS Names:** Hostnames, local domains, and FQDNs.
  - Examples: `pihole.local`, `pihole.homelab.lan`, `homeassistant.internal`
  - *Wildcards:* Wildcard certificates (e.g. `*.homelab.local`) are supported and cover any single-level subdomain.
- **IP Addresses:** Direct IPv4 or IPv6 addresses.
  - Examples: `192.168.1.50`, `10.0.0.100`, `127.0.0.1`
  - Necessary if you access web interfaces directly via IP (e.g. `https://192.168.1.50:9443`).

In the creation dialog, enter each DNS name or IP address into the tag box and press **Enter** (or comma) to add multiple entries.

---

## Downloading Certificates and Keys

Once issued, your certificate appears in the main dashboard table with its Common Name, SAN list, validity status, and expiration date.

![Dashboard with Issued Certificates and Download Options](/static/screenshots/10_dashboard_with_certificates_dark.png)

You can download your credentials in multiple formats:
- **Certificate (.pem / .crt):** The signed public certificate for your service.
- **Certificate Bundle (.pem):** Full certificate chain (Service Certificate + Root CA certificate) required by reverse proxies such as Nginx, Traefik, Caddy, and Apache.
- **Private Key (.key):** The 4096-bit RSA private key (`0600` permissions).
- **PKCS#12 Container (.pfx):** Password-protected binary bundle combining the certificate, private key, and CA chain, ideal for Windows Server, IIS, and Java Keystores.

---

## Self Certificate
<a id="self-certificate"></a>

### Recreating the Certificate Manager's Own HTTPS Certificate

HomeLab Cert Manager secures its own web interface using an internal HTTPS server. Upon first boot without a Root CA, it starts with a temporary self-signed certificate.

Once your Root CA is generated, you should recreate the Certificate Manager's own certificate so that accessing this web UI displays a trusted green lock icon:

1. Navigate to **Settings** (`/settings#server-cert`).
2. Under the **Server Certificate** tab:
   - Add all DNS hostnames used to reach this machine (e.g. `certs.homelab.local`, `localhost`).
   - Add all IP addresses where the web UI is accessed (e.g. `192.168.1.10`, `127.0.0.1`).
3. Click **Recreate Server Certificate**.

![Server Certificate Settings](/static/screenshots/06_settings_server_cert_dark.png)

The application immediately generates a new certificate signed by your Root CA and live-reloads the TLS listener without dropping current user sessions.

![Dashboard with Recreated Server Certificate](/static/screenshots/07_dashboard_server_cert_recreated_dark.png)

