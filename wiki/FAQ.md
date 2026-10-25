# Frequently Asked Questions (FAQ)

### General & Authentication

#### How do I change the administrator password?
Click your username in the top-right corner of the navigation bar and select **Change Password** (or navigate to `/change-password`). Enter your current password, your new password (minimum 8 characters), and confirm. Click **Change Password** to save.

#### How do I switch between Dark and Light themes?
Click the moon/sun icon in the top navigation bar. Your theme preference is automatically remembered across sessions in your browser.

#### How does the Session Inactivity Timeout work?
HomeLab Cert Manager monitors user interaction (mouse movement, clicks, keystrokes, scrolling). If no activity occurs within the configured timeout period (default: 2 minutes), your session is automatically terminated to protect administrative access. You can customize the timeout duration (1-30 minutes) under **Settings** > **Session Inactivity Timeout**.

#### What happens if my OIDC provider is offline or inaccessible?
You are never locked out. On the login screen (`/login`), click the discreet link labeled **"Sign in with local admin account"** to reveal the standard username/password login form. You can log in locally to troubleshoot, reconfigure OIDC, or renew certificates.

#### Do I need an OIDC Client Secret for Pocket ID?
**No.** HomeLab Cert Manager implements PKCE (RFC 7636) with SHA-256 (`S256`) code challenges. You can register HomeLab Cert Manager as a **Public Client** in Pocket ID, which requires no client secret at all. If you are using a provider that requires confidential clients (e.g. Keycloak or Authentik), you can still enter a client secret; it will be encrypted at rest using AES-256-GCM and masked in the web interface.

#### What is PKCE and why does HomeLab Cert Manager use it?
Proof Key for Code Exchange (PKCE, RFC 7636) is a security extension to the OAuth 2.0 authorization code flow. It dynamically creates a cryptographically random code verifier and computes its SHA-256 challenge (`S256`) for every login session. This prevents authorization code injection and interception attacks, and allows secure authentication with public clients like Pocket ID without needing static client secrets.

---

### Certificates & PKI

#### Where are certificates and keys stored?
All data is stored inside the `data/` directory relative to the application:
- `data/root-cert/`: Contains the Root CA private key and certificate.
- `data/certs/`: Contains generated server certificates and private keys.
- `data/certmanager-cert/`: Contains the certificate used by the manager itself.
- `data/settings.json`: Configuration, credentials hash, and defaults.

#### Can I download the Root CA private key from the web interface?
**No.** For security, the Root CA private key (`data/root-cert/HomeLab_Root_CA.key`) is never exposed or downloadable via the UI or API. It remains protected with `0600` / `0700` filesystem permissions on the host.

#### What is the difference between "Create Certificate" and "Sign CSR"?
- **Create Certificate:** HomeLab Cert Manager generates both the 4096-bit RSA private key and the signed certificate. Both the certificate and private key can be downloaded (or exported as a `.pfx` bundle).
- **Sign CSR:** Used for devices (e.g. Proxmox VE, TrueNAS, switches) where the private key was generated on the hardware and must not leave it. You provide only the Certificate Signing Request (`.csr`), and the manager signs it. The private key remains exclusively on your hardware appliance.

#### Why is the "Download Key" button disabled for some certificates?
Certificates marked with a **CSR** badge were issued from external Certificate Signing Requests. Because the private key was generated on the target device and never transmitted to HomeLab Cert Manager, there is no private key to download.

#### How do I recreate the HomeLab Certificate Manager Certificate?
1. Go to **Settings** > **Server Certificate** tab.
2. Ensure all relevant DNS names and IP addresses for the manager are entered.
3. Click **Recreate HomeLab Certificate Manager Certificate**.
4. The application generates a fresh certificate signed by your Root CA.

---

### Docker & Deployment

#### How do I pull and run the Docker image?
Pull the latest image from GitHub Container Registry:
```bash
docker pull ghcr.io/cbrosius/homelab_cert_manager/homelab_cert_manager:latest
docker run -d -p 8443:8443 -v $(pwd)/data:/app/data ghcr.io/cbrosius/homelab_cert_manager/homelab_cert_manager:latest
```

#### Why does the container run as UID 10001?
For security hardening, the container runs under an unprivileged user (`appuser`, UID `10001`). If you are migrating from older root-based versions, the container entrypoint automatically adjusts permissions on `./data` to UID `10001` on startup. If you experience file permission issues on restrictive NFS/CIFS mounts, run `sudo chown -R 10001:10001 ./data` on the host.

#### How do I build and run the project locally from source?
Clone the repository and build the binary from the `./cmd/cert_manager` directory:
```bash
git clone https://github.com/cbrosius/homelab_cert_manager.git
cd homelab_cert_manager
go build -o homelab_cert_manager ./cmd/cert_manager
./homelab_cert_manager
```

#### How do I enable debug logging?
Add `"debug": true` to your `data/settings.json` file:
```json
{
  "debug": true
}
```
Restart the application or container to start seeing verbose logs.