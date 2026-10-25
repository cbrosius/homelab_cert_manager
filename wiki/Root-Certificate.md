# Root Certificate Guide

A **Root Certificate Authority (CA)** is the trust anchor of your homelab PKI (Public Key Infrastructure). Every leaf and service certificate issued by HomeLab Cert Manager is cryptographically signed by your Root CA. Once you trust this Root CA on your computers, laptops, and mobile devices, every homelab service displays a verified green lock icon in web browsers with zero certificate warnings.

---

## Create Root CA
<a id="create-root-ca"></a>

### Generating Your Root CA

1. On the main dashboard (`/certificates`), if no Root CA exists, click **Create Root Certificate**.
2. Complete the Root CA creation form:
   - **Common Name (CN):** Descriptive name for your CA (e.g. `HomeLab Root CA`).
   - **Organization (O):** Your homelab or family organization name.
   - **Country (C):** 2-letter uppercase ISO code (e.g. `DE`, `US`).
   - **Validity (Days):** Recommended 10 to 30 years (3650 to 10950 days). Since Root CAs must be manually distributed, a long lifetime prevents frequent re-distribution.
3. Click **Create Root Certificate**.

The application generates a **4096-bit RSA** private key (`data/root-cert/rootCA.key`) and self-signed certificate (`data/root-cert/rootCA.pem`). The private key is secured with strict file permissions (`0600`) and the root certificate directory is set to `0700`.

### Renewing or Replacing the Root CA

If you ever need to replace your Root CA (e.g. prior to key compromise or expiration):
1. In the dashboard, locate the **Root Certificate** card at the top.
2. Click **Delete Root Certificate**.
3. Confirm the deletion dialog.
4. Issue a new Root CA.

> [!WARNING]
> Replacing or deleting your Root CA will invalidate trust for all existing service certificates signed by the old CA. You must re-install the new Root CA on all client devices and reissue certificates for your homelab services.

---

## Trust Root CA
<a id="trust-root-ca"></a>

To enable seamless HTTPS trust across your network, install the Root CA on your client devices. You only need to do this **once per client device**.

Download `HomeLab_Root_CA.pem` from the top Root Certificate card on the dashboard, then follow the instructions for your operating system:

### Windows 10 & 11

1. Double-click the downloaded `HomeLab_Root_CA.pem` file (or right-click and select **Install Certificate...**).
2. Choose **Local Machine** as the Store Location and click **Next** (requires Administrator rights).
3. Select **Place all certificates in the following store**.
4. Click **Browse...** and choose **Trusted Root Certification Authorities**.
5. Click **Next**, then **Finish**.
6. Restart your web browser (Chrome, Edge, Brave, etc.).

Alternatively, via PowerShell (as Administrator):
```powershell
Import-Certificate -FilePath "C:\Path\To\HomeLab_Root_CA.pem" -CertStoreLocation Cert:\LocalMachine\Root
```

---

### macOS

1. Open **Keychain Access** (via Spotlight or Applications > Utilities).
2. In the left sidebar, select the **System** keychain.
3. Drag and drop `HomeLab_Root_CA.pem` into the certificate list.
4. Double-click the newly imported **HomeLab Root Certificate**.
5. Expand the **Trust** section.
6. Set **When using this certificate** to **Always Trust**.
7. Close the window and authenticate with your Mac user password or Touch ID.

---

### Linux (Ubuntu, Debian, Proxmox VE, Raspberry Pi OS)

1. Copy the Root CA certificate to the system trust directory:
   ```bash
   sudo cp HomeLab_Root_CA.pem /usr/local/share/ca-certificates/homelab-root-ca.crt
   ```
2. Update the system CA certificates:
   ```bash
   sudo update-ca-certificates
   ```
3. Test using `curl`:
   ```bash
   curl -I https://certs.homelab.local:8443
   ```

---

### Linux (RHEL, Fedora, Rocky, AlmaLinux, Arch)

**RHEL / Fedora / Rocky:**
```bash
sudo cp HomeLab_Root_CA.pem /etc/pki/ca-trust/source/anchors/homelab-root-ca.crt
sudo update-ca-trust extract
```

**Arch Linux:**
```bash
sudo trust anchor --store HomeLab_Root_CA.pem
```

---

### iOS & iPadOS

1. Send `HomeLab_Root_CA.pem` to your Apple device (via AirDrop, email, or download from the Cert Manager web interface).
2. Tap the file and accept **Profile Downloaded**.
3. Open **Settings** > **Profile Downloaded** (or **General** > **VPN & Device Management**).
4. Tap **Install** and enter your device passcode.
5. **Critical Step:** Go to **Settings** > **General** > **About** > **Certificate Trust Settings**.
6. Under **Enable full trust for root certificates**, toggle **HomeLab Root Certificate** to **ON**.

---

### Android

1. Transfer `HomeLab_Root_CA.pem` to your device storage.
2. Open **Settings** > **Security** (or **Security & Privacy**).
3. Tap **More security settings** > **Encryption & credentials**.
4. Tap **Install a certificate** > **CA certificate**.
5. When prompted with a security warning, select **Install anyway**.
6. Select your certificate file and confirm.

---

### Mozilla Firefox (Independent Certificate Store)

Modern versions of Firefox on Windows and macOS automatically inherit OS trust. If your Firefox uses its own standalone store:
1. Open Firefox and navigate to `about:preferences#privacy`.
2. Scroll down to **Certificates** and click **View Certificates...**.
3. Under the **Authorities** tab, click **Import...**.
4. Select `HomeLab_Root_CA.pem`.
5. Check **Trust this CA to identify websites** and click **OK**.
