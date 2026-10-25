# Root CA and Client Trust Guide

To ensure that your internal servers, containers, and appliances display trusted green lock icons in modern web browsers without certificate warning screens, you must install and trust your **HomeLab Root Certificate** on your client devices.

You only need to do this **once per client device**. After the Root CA is trusted, all current and future certificates issued by your HomeLab Cert Manager will automatically be accepted as valid.

---

## 1. Initial Setup and Onboarding Walkthrough

When starting HomeLab Cert Manager for the first time, follow this initial onboarding flow to establish your Certificate Authority.

### Step 1: Initial Login

Navigate to `https://<server-ip>:8443/login` in your web browser. Log in using the default administrator credentials:
- **Username:** `admin`
- **Password:** `admin`

![Initial Login Page](/static/screenshots/01_initial_login_dark.png)

---

### Step 2: Mandatory First Password Change

To ensure out-of-the-box security, HomeLab Cert Manager requires an immediate password change upon initial login. You cannot navigate the system or issue certificates until a strong administrator password is set:

- **Current Password:** `admin`
- **New Password:** Choose a strong password (minimum 8 characters with upper, lower, digits, and symbols recommended).

![Mandatory Initial Password Change](/static/screenshots/02_mandatory_password_change_dark.png)

---

### Step 3: Dashboard Without Root CA

After setting your password, you arrive at the main dashboard (`/certificates`). Because no Root Certificate exists yet, the system displays an alert indicating that a Root Certificate is missing, and all certificate creation or CSR signing actions are disabled until a Root CA is established.

![Dashboard Without Root CA](/static/screenshots/03_dashboard_no_root_ca_dark.png)

Click **Create Root Certificate** to launch the Root CA generation wizard.

---

### Step 4: Generating the Root CA Certificate

On the Root CA creation screen, fill in your organizational identity or click **Prefill Form** for standard homelab values:
- **Common Name:** e.g. `HomeLab Root CA`
- **Organization & Unit:** e.g. `my HomeLab`, `private`
- **Location & Country:** e.g. `HomeCity`, `HomeState`, `DE`
- **Validity:** Default 30-year validity for Root CAs to prevent frequent re-distribution.

The system generates a cryptographic **4096-bit RSA** key pair stored securely in `./data/root-cert/`.

![Generate Root Certificate Form](/static/screenshots/04_generate_root_ca_dark.png)

Click **Create Root Certificate** to generate the CA.

---

### Step 5: Dashboard with Active Root CA

Once generated, the dashboard immediately updates to display your active Root Certificate card:
- **Common Name & Issuer:** `CN=HomeLab Root CA`
- **Validity Period:** Displaying creation and expiration timestamps.
- **Download Action:** Allows downloading `HomeLab_Root_CA.pem` to distribute to client devices.

![Dashboard with Active Root CA](/static/screenshots/05_dashboard_root_ca_created_dark.png)

---

### Step 6: Generating the Certificate Manager's Service Certificate

By default, HomeLab Cert Manager boots with a temporary self-signed certificate. Now that your Root CA exists, recreate the Certificate Manager's own TLS certificate signed by your new Root CA so that accessing the web UI itself is fully trusted!

1. Go to **Settings** (`/settings#server-cert`).
2. Under **Server Certificate**, specify all hostnames and IP addresses used to reach your certificate manager (e.g. `certmanager.homelab.local`, `192.168.1.50`).
3. Click **Save & Recreate Certificate**.

![Settings - Certificate Manager HTTPS Certificate](/static/screenshots/06_settings_server_cert_dark.png)

The system automatically creates a 4096-bit leaf certificate signed by your Root CA and reloads the TLS listener seamlessly without service disruption.

---

### Step 7: Dashboard with Recreated Server Certificate

Returning to the dashboard now shows both:
1. The **Root CA Card**
2. The **Certificate Manager Service Certificate Card** (with Subject Alternative Names and status `Valid`)

![Dashboard with Root CA and Recreated Server Certificate](/static/screenshots/07_dashboard_server_cert_recreated_dark.png)

---

## 2. Installing & Trusting the Root CA on Clients


### Windows 10 & 11

1. Double-click the downloaded `HomeLab_Root_CA.pem` file (or right-click and select **Install Certificate...**).
2. Choose **Local Machine** as the Store Location and click **Next** (requires Administrator rights).
3. Select **Place all certificates in the following store**.
4. Click **Browse...** and choose **Trusted Root Certification Authorities**.
5. Click **Next**, then **Finish**.
6. Restart your web browser (Chrome, Edge, Brave, etc.).

Alternatively, via PowerShell (Administrator):
```powershell
Import-Certificate -FilePath "C:\Path\To\HomeLab_Root_CA.pem" -CertStoreLocation Cert:\LocalMachine\Root
```

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

1. Open **Keychain Access** (via Spotlight or Applications > Utilities).
2. In the left sidebar, select the **System** keychain.
3. Drag and drop `HomeLab_Root_CA.pem` into the certificate list.
4. Double-click the newly imported **HomeLab Root Certificate**.
5. Expand the **Trust** section.
6. Set **When using this certificate** to **Always Trust**.
7. Close the window and authenticate with your Mac user password or Touch ID.

---

### iOS & iPadOS

1. Send `HomeLab_Root_CA.pem` to your Apple device (via AirDrop, email, or a local web server).
2. Tap the file and accept **Profile Downloaded**.
3. Open **Settings** > **Profile Downloaded** (or **General** > **VPN & Device Management**).
4. Tap **Install** and enter your device passcode.
5. **Critical Step:** Go to **Settings** > **General** > **About** > **Certificate Trust Settings**.
6. Under **Enable full trust for root certificates**, toggle **HomeLab Root Certificate** to **ON**.

---

### Android

1. Transfer `HomeLab_Root_CA.pem` (or `.crt`) to your device storage.
2. Open **Settings** > **Security** (or **Security & Privacy**).
3. Tap **More security settings** > **Encryption & credentials**.
4. Tap **Install a certificate** > **CA certificate**.
5. If prompted with a warning, select **Install anyway**.
6. Browse and select your certificate file.

---

### Mozilla Firefox (Optional)

Most modern browsers (Chrome, Edge, Safari, Brave) use the operating system's trust store. However, Firefox can maintain an independent certificate store:

1. Open Firefox and go to **Settings** (`about:preferences`).
2. Search for **Certificates** and click **View Certificates...**.
3. Go to the **Authorities** tab and click **Import...**.
4. Select `HomeLab_Root_CA.pem`.
5. Check the box: **Trust this CA to identify websites**.
6. Click **OK**.

*(Tip: In Firefox, you can also set `security.enterprise_roots.enabled` to `true` in `about:config` so Firefox automatically trusts certificates from your OS store).*

---

## 3. Verification

Once imported, visit any service with a certificate issued by HomeLab Cert Manager. The browser address bar should now display a secure lock icon without any warnings:

![Verified Dashboard with Certificates and Root CA](/static/screenshots/10_dashboard_with_certificates_dark.png)
