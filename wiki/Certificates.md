# Service Certificates & SAN Configuration Guide

HomeLab Cert Manager enables the quick issuance and lifecycle management of SSL/TLS leaf certificates for all internal applications, web servers, reverse proxies, and containers.

---

## Create Certificate

To create a new service certificate for a server or container:

1. Click the **Create Certificate** button in the dashboard top action bar.
2. Enter the **Common Name (CN)**, such as `plex.homelab.local` or `vault.lan`.
3. Provide Subject Alternative Names (SANs) – both DNS hostnames and IP addresses (see below).
4. Specify validity duration in years (default configured in Settings).
5. Click **Create Certificate**.

HomeLab Cert Manager generates a 4096-bit RSA key pair, issues an X.509 certificate signed by your Root CA, and securely saves the files in `./data/`.

---

## SAN Configuration

Subject Alternative Names (SANs) are **mandatory** in modern TLS (RFC 2818). Web browsers like Google Chrome, Apple Safari, and Mozilla Firefox will reject certificates that only specify a Common Name without SANs.

### DNS Names
- Add all fully qualified domain names (FQDNs), local hostnames, and wildcards.
- Examples:
  - `myserver.homelab.local`
  - `vault.internal`
  - `*.apps.homelab.local`

### IP Addresses
- Add all IPv4 and IPv6 addresses through which clients or API consumers reach the service.
- Examples:
  - `192.168.1.100`
  - `10.0.0.50`
  - `127.0.0.1`

### Best Practices for SANs
1. Always include the primary hostname as the first SAN DNS entry.
2. If accessing services by direct IP in addition to DNS, list both in the certificate creation dialog.
3. For multi-service nodes (e.g. Docker swarm, Kubernetes node, reverse proxy), list all virtual host domains.

---

## Self Certificate

By default, HomeLab Cert Manager initializes on first launch with a temporary self-signed certificate. Once your Root CA is created, you should replace the Cert Manager's own certificate with one signed by your Root CA so the web interface itself is fully trusted.

### Recreating the Server Certificate

1. Go to **Settings** (`/settings#server-cert`).
2. Under **Server Certificate**, add the hostnames and IP addresses used to reach HomeLab Cert Manager.
3. Click **Save & Recreate Certificate**.

The application automatically creates a fresh 4096-bit leaf certificate signed by your Root CA and reloads the HTTPS listener seamlessly without requiring a service restart.
