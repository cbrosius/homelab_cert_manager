# Root Certificate Authority & Client Trust Guide

HomeLab Cert Manager allows you to establish your own dedicated 4096-bit RSA Root Certificate Authority (CA) to secure internal services across your entire homelab network.

---

## Create Root CA

When starting HomeLab Cert Manager for the first time, you need to create your internal Root CA before issuing service certificates or signing CSRs.

### Generating the Root CA

1. Navigate to the **Root CA** card or modal on the dashboard (`/certificates`).
2. Fill in the organizational details or click **Prefill Form**:
   - **Common Name:** e.g. `HomeLab Root CA`
   - **Organization (O) & Unit (OU):** e.g. `HomeLab`, `IT`
   - **Country (C), State (ST), Locality (L):** Regional details (e.g., `DE`, `Bavaria`, `Munich`)
   - **Validity:** Default 30 years (recommended for Root CAs to avoid frequent client re-trusting).
3. Click **Create Root Certificate**.

The cryptographic key pair (4096-bit RSA) and the self-signed X.509 certificate will be securely generated and saved in `./data/root-cert/`.

---

## Trust Root CA

To ensure web browsers and operating systems trust all SSL/TLS certificates issued by HomeLab Cert Manager without security warnings or untrusted certificate errors, you must install and trust `HomeLab_Root_CA.pem` on your client devices.

You only need to do this **once per client device**.

### Windows 10 & 11

1. Download `HomeLab_Root_CA.pem` from the dashboard.
2. Double-click the file and select **Install Certificate...**.
3. Choose **Local Machine** as Store Location and click **Next**.
4. Select **Place all certificates in the following store**.
5. Click **Browse...** and select **Trusted Root Certification Authorities**.
6. Click **Next** and **Finish**.
7. Restart your browser.

*PowerShell (Administrator alternative):*
```powershell
Import-Certificate -FilePath "HomeLab_Root_CA.pem" -CertStoreLocation Cert:\LocalMachine\Root
```

---

### Linux (Debian, Ubuntu, Proxmox VE, Raspberry Pi OS)

1. Copy the certificate to the system trust directory:
   ```bash
   sudo cp HomeLab_Root_CA.pem /usr/local/share/ca-certificates/homelab-root-ca.crt
   ```
2. Update the system trust store:
   ```bash
   sudo update-ca-certificates
   ```
3. Test using `curl`:
   ```bash
   curl -I https://certs.homelab.local:8443
   ```

---

### Linux (RHEL, Fedora, Rocky, AlmaLinux)

1. Copy the Root CA to the anchors directory:
   ```bash
   sudo cp HomeLab_Root_CA.pem /etc/pki/ca-trust/source/anchors/homelab-root-ca.crt
   ```
2. Update the trust store:
   ```bash
   sudo update-ca-trust extract
   ```

---

### macOS

1. Open **Keychain Access** (`Applications > Utilities`).
2. Select the **System** keychain in the left sidebar.
3. Drag and drop `HomeLab_Root_CA.pem` into the certificate list.
4. Double-click the newly imported Root CA.
5. Expand the **Trust** section and set **When using this certificate** to **Always Trust**.
6. Close the window and authenticate with your macOS password or Touch ID.

---

### iOS & iPadOS

1. Send `HomeLab_Root_CA.pem` to your Apple device (AirDrop, email, or local download).
2. Tap the file and approve **Profile Downloaded**.
3. Go to **Settings** > **Profile Downloaded** (or **General** > **VPN & Device Management**) and tap **Install**.
4. **Important Step:** Go to **Settings** > **General** > **About** > **Certificate Trust Settings**.
5. Under **Enable full trust for root certificates**, toggle your **HomeLab Root Certificate** to **ON**.

---

### Android

1. Transfer `HomeLab_Root_CA.pem` to your device storage.
2. Go to **Settings** > **Security & Privacy** > **More security settings** > **Encryption & credentials**.
3. Tap **Install a certificate** > **CA certificate**.
4. Confirm any warning prompts by tapping **Install anyway**.
5. Select `HomeLab_Root_CA.pem`.

---

### Mozilla Firefox

Most browsers use the system trust store, but Firefox can maintain an independent store:
1. Open Firefox **Settings** (`about:preferences`).
2. Search for **Certificates** and click **View Certificates...**.
3. Under the **Authorities** tab, click **Import...**.
4. Select `HomeLab_Root_CA.pem` and check **Trust this CA to identify websites**.
5. Click **OK**.
