# External CSR Signing Guide

One of the standout features of HomeLab Cert Manager is native support for **External Certificate Signing Requests (CSRs)**. 

---

## 1. Why Use External CSR Signing?

Many enterprise and homelab appliances, operating systems, and network devices enforce strict security models where private keys are generated directly on the device and must never leave hardware storage. Examples include:

- **Hypervisors & Storage:** Proxmox VE, TrueNAS SCALE / CORE, VMware ESXi
- **Firewalls & Routers:** pfSense, OPNsense, MikroTik RouterOS, UniFi Gateways
- **Network Hardware:** Managed switches, IPMI, Dell iDRAC, HPE iLO
- **Security-Sensitive Services:** Vault, internal databases, microservices

With CSR signing:
1. The device creates its own private key and generates a `.csr` (Certificate Signing Request).
2. The private key remains secure on the source hardware and is never transmitted over the network.
3. HomeLab Cert Manager signs the CSR using your Root CA.
4. You upload the resulting certificate back to your appliance.

---

## Sign CSR

Follow this step-by-step workflow to sign an external Certificate Signing Request (CSR):

### Step 1: Generate the CSR on Your Device
Follow your appliance's vendor guide to generate a CSR. Ensure you include all relevant **Subject Alternative Names (SANs)**, such as internal hostnames, FQDNs, and IP addresses (e.g. `proxmox.homelab.local`, `192.168.1.10`).

### Step 2: Open Sign CSR in HomeLab Cert Manager
1. Log in to HomeLab Cert Manager.
2. In the certificate dashboard, click the **Sign CSR** button (located in the top action bar next to *Create Certificate*).

### Step 3: Provide the CSR
You have two flexible options:
- **File Upload:** Click **Choose File** (or drag and drop) to select your `.csr`, `.pem`, or `.txt` file.
- **Paste Raw PEM:** Paste the full PEM block into the text area:
  ```text
  -----BEGIN CERTIFICATE REQUEST-----
  MIICvDCCAaQCAQAwdzELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWEx
  ...
  -----END CERTIFICATE REQUEST-----
  ```

![Sign CSR Modal Dialog](https://raw.githubusercontent.com/cbrosius/homelab_cert_manager/main/static/screenshots/09_sign_csr_modal_dark.png)

### Step 4: Specify Validity
Set the validity duration using the interactive range slider, number input, or quick presets (1, 2, 5, 10, or 30 Years).

### Step 5: Sign & Issue
Click **Sign CSR**.

HomeLab Cert Manager will:
- Parse and validate the cryptographic signature of the CSR using Go's `crypto/x509` standard library.
- Automatically extract all Subject information (CommonName, Organization, Country, etc.).
- Extract all Subject Alternative Names (SANs):
  - DNS Names
  - IP Addresses
  - Email Addresses
  - Uniform Resource Identifiers (URIs)
- Sign the certificate with your HomeLab Root CA using SHA-256 and a random 128-bit serial number.

---

## 3. Protected Private Key Handling & Dashboard Badge

Once signed, the certificate appears in your dashboard table with a prominent **CSR** badge:

![Dashboard with Issued Certificates and CSR Badge](https://raw.githubusercontent.com/cbrosius/homelab_cert_manager/main/static/screenshots/10_dashboard_with_certificates_dark.png)

- **Download Certificate:** Download the signed `.pem` file or the full certificate bundle (leaf cert + Root CA).
- **Protected Key Notice:** The "Download Key" and PKCS#12 (`.pfx`) export actions are cleanly disabled for CSR-issued certificates, preventing confusion since the private key was never submitted to or stored by HomeLab Cert Manager.

---

## 4. Installing the Signed Certificate on Your Appliance

Download the signed `.pem` certificate from HomeLab Cert Manager, navigate back to your appliance (e.g. Proxmox VE Web UI > Node > System > Certificates > Upload Custom Certificate), and upload the certificate file. 

Because your client devices already trust your **HomeLab Root CA**, your appliance's web interface will immediately show a verified, trusted HTTPS connection.
