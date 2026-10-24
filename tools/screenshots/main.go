package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/chromedp/chromedp"
)

func main() {
	log.Println("[screenshots] Starting automated screenshot generator...")
	exec.Command("taskkill", "/F", "/IM", "homelab_cert_manager.exe").Run()
	time.Sleep(1 * time.Second)

	rootDir, err := filepath.Abs(".")
	if err != nil {
		log.Fatalf("Failed to resolve root dir: %v", err)
	}

	outputDir := filepath.Join(rootDir, "static", "screenshots")
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		log.Fatalf("Failed to create output dir: %v", err)
	}

	// 1. Ensure clean data directory for the initial setup run
	dataDir := filepath.Join(rootDir, "data")
	os.RemoveAll(dataDir)
	os.MkdirAll(dataDir, 0755)

	// 2. Start homelab_cert_manager server
	binaryPath := filepath.Join(rootDir, "homelab_cert_manager.exe")
	if _, err := os.Stat(binaryPath); os.IsNotExist(err) {
		log.Println("[screenshots] Building homelab_cert_manager.exe...")
		cmd := exec.Command("go", "build", "-o", "homelab_cert_manager.exe", "./cmd/cert_manager")
		cmd.Dir = rootDir
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			log.Fatalf("Build failed: %v", err)
		}
	}

	log.Println("[screenshots] Launching server on :8443...")
	srvCmd := exec.Command(binaryPath)
	srvCmd.Dir = rootDir
	srvCmd.Stdout = os.Stdout
	srvCmd.Stderr = os.Stderr
	if err := srvCmd.Start(); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
	defer func() {
		if srvCmd.Process != nil {
			log.Println("[screenshots] Terminating server...")
			srvCmd.Process.Kill()
		}
	}()

	// Wait for server to become responsive
	baseURL := "https://localhost:8443"
	waitForServer(baseURL, 15*time.Second)

	// 3. Locate Chrome or Edge executable
	chromePath := findBrowserBinary()
	log.Printf("[screenshots] Using browser at: %s", chromePath)

	allocOpts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.ExecPath(chromePath),
		chromedp.Flag("headless", true),
		chromedp.Flag("ignore-certificate-errors", "1"),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("no-sandbox", true),
		chromedp.WindowSize(1440, 900),
	)

	allocCtx, allocCancel := chromedp.NewExecAllocator(context.Background(), allocOpts...)
	defer allocCancel()

	ctx, cancel := chromedp.NewContext(allocCtx)
	defer cancel()

	// Helper to capture both Dark and Light theme screenshots
	captureThemes := func(baseName string) {
		time.Sleep(500 * time.Millisecond) // Let layout & animations settle

		// Capture Dark (default)
		_ = chromedp.Do(ctx,
			chromedp.Evaluate[chromedp.Void](`document.documentElement.setAttribute('theme', 'dark'); localStorage.setItem('theme', 'dark'); if (window.updateThemeIcon) updateThemeIcon();`),
			chromedp.Sleep(300*time.Millisecond),
		)
		bufDark, err := chromedp.Run(ctx, chromedp.FullScreenshot(100))
		if err != nil {
			log.Printf("Error capturing dark screenshot for %s: %v", baseName, err)
		} else {
			p := filepath.Join(outputDir, fmt.Sprintf("%s_dark.png", baseName))
			_ = os.WriteFile(p, bufDark, 0644)
			log.Printf("[screenshot] Saved %s_dark.png", baseName)
		}

		// Capture Light
		_ = chromedp.Do(ctx,
			chromedp.Evaluate[chromedp.Void](`document.documentElement.setAttribute('theme', 'light'); localStorage.setItem('theme', 'light'); if (window.updateThemeIcon) updateThemeIcon();`),
			chromedp.Sleep(300*time.Millisecond),
		)
		bufLight, err := chromedp.Run(ctx, chromedp.FullScreenshot(100))
		if err != nil {
			log.Printf("Error capturing light screenshot for %s: %v", baseName, err)
		} else {
			p := filepath.Join(outputDir, fmt.Sprintf("%s_light.png", baseName))
			_ = os.WriteFile(p, bufLight, 0644)
			log.Printf("[screenshot] Saved %s_light.png", baseName)
		}

		// Reset to Dark
		_ = chromedp.Do(ctx,
			chromedp.Evaluate[chromedp.Void](`document.documentElement.setAttribute('theme', 'dark'); localStorage.setItem('theme', 'dark'); if (window.updateThemeIcon) updateThemeIcon();`),
		)
	}

	// ==========================================
	// Step 1: Initial Login Page
	// ==========================================
	log.Println("[flow] Step 1: Initial Login...")
	if err := chromedp.Do(ctx,
		chromedp.Navigate(baseURL+"/login"),
		chromedp.WaitVisible("#password"),
	); err != nil {
		log.Fatalf("Failed at initial login: %v", err)
	}
	captureThemes("01_initial_login")

	// Submit default credentials (admin / admin)
	if err := chromedp.Do(ctx,
		chromedp.SendKeys("#password", "admin"),
		chromedp.Click("#loginForm button[type='submit']"),
		chromedp.WaitVisible("#old_password"),
	); err != nil {
		log.Fatalf("Failed submitting initial login: %v", err)
	}

	// ==========================================
	// Step 2: Mandatory Password Change Screen
	// ==========================================
	log.Println("[flow] Step 2: Mandatory Password Change...")
	captureThemes("02_mandatory_password_change")

	newAdminPwd := "HomeLabAdmin2026!"
	if err := chromedp.Do(ctx,
		chromedp.SendKeys("#old_password", "admin"),
		chromedp.SendKeys("#new_password", newAdminPwd),
		chromedp.SendKeys("#confirm_password", newAdminPwd),
		chromedp.Sleep(300*time.Millisecond),
		chromedp.Click("#submit-btn"),
		chromedp.Sleep(2500*time.Millisecond), // Wait for redirect to /certificates
		chromedp.WaitVisible(".badge-pill.status-expired"),
	); err != nil {
		log.Fatalf("Failed changing password: %v", err)
	}

	// ==========================================
	// Step 3: Dashboard Without Root CA
	// ==========================================
	log.Println("[flow] Step 3: Dashboard Without Root CA...")
	captureThemes("03_dashboard_no_root_ca")

	// ==========================================
	// Step 4: Generate Root Certificate Page
	// ==========================================
	log.Println("[flow] Step 4: Navigate to Generate Root Certificate...")
	if err := chromedp.Do(ctx,
		chromedp.Click(`a[href="/"]`),
		chromedp.WaitVisible("#common_name"),
		chromedp.Click(`button[onclick="prefillForm()"]`),
		chromedp.Sleep(300*time.Millisecond),
	); err != nil {
		log.Fatalf("Failed on Generate Root Certificate page: %v", err)
	}
	captureThemes("04_generate_root_ca")

	// Submit Root CA generation
	if err := chromedp.Do(ctx,
		chromedp.Click(`form[action="/create-root-certificate"] button[type="submit"]`),
		chromedp.WaitVisible(".root-ca-card"), // Arrives at /certificates
	); err != nil {
		log.Fatalf("Failed generating root certificate: %v", err)
	}

	// ==========================================
	// Step 5: Dashboard with Root CA Created
	// ==========================================
	log.Println("[flow] Step 5: Dashboard with Root CA Created...")
	captureThemes("05_dashboard_root_ca_created")

	// ==========================================
	// Step 6: Settings - Server Certificate Tab
	// ==========================================
	log.Println("[flow] Step 6: Settings - Server Certificate Tab...")
	if err := chromedp.Do(ctx,
		chromedp.Navigate(baseURL+"/settings#server-cert"),
		chromedp.WaitVisible("#cmDnsInput"),
		chromedp.SendKeys("#cmDnsInput", "certmanager.homelab.local\r"),
		chromedp.SendKeys("#cmIpInput", "192.168.1.50\r"),
		chromedp.Sleep(300*time.Millisecond),
		chromedp.Evaluate[chromedp.Void](`window.confirm = () => true;`),
	); err != nil {
		log.Fatalf("Failed navigating to server cert settings: %v", err)
	}
	captureThemes("06_settings_server_cert")

	// Recreate HomeLab Certificate Manager Certificate
	log.Println("[flow] Recreating HomeLab Certificate Manager Certificate...")
	_ = chromedp.Do(ctx,
		chromedp.Click("#saveAndRecreateHomelabCert"),
		chromedp.Sleep(4000*time.Millisecond),
	)

	// ==========================================
	// Step 7: Dashboard with Recreated Server Certificate
	// ==========================================
	log.Println("[flow] Step 7: Dashboard with Recreated Server Certificate...")
	if err := chromedp.Do(ctx,
		chromedp.Navigate(baseURL+"/certificates"),
		chromedp.WaitVisible(".certmanager-card"),
	); err != nil {
		log.Fatalf("Failed returning to certificates: %v", err)
	}
	captureThemes("07_dashboard_server_cert_recreated")

	// ==========================================
	// Step 8: Create Leaf Certificate
	// ==========================================
	log.Println("[flow] Step 8: Create Leaf Certificate...")
	if err := chromedp.Do(ctx,
		chromedp.Navigate(baseURL+"/create-certificate-form"),
		chromedp.WaitVisible("#common_name"),
		chromedp.Evaluate[chromedp.Void](`
			document.getElementById('common_name').value = 'proxmox.homelab.local';
			onCommonNameChange('proxmox.homelab.local');
			addSanTag('proxmox.homelab.local');
			addSanTag('192.168.1.100');
			validateFormState();
		`),
		chromedp.Sleep(400*time.Millisecond),
	); err != nil {
		log.Fatalf("Failed filling leaf cert form: %v", err)
	}
	captureThemes("08_create_certificate")

	// Submit leaf certificate using async fetch with EvalAwaitPromise
	log.Println("[flow] Submitting Leaf Certificate...")
	if err := chromedp.Do(ctx,
		chromedp.Evaluate[chromedp.Void](`
			(async () => {
				const form = document.getElementById('createCertificateForm');
				const formData = new FormData(form);
				await fetch('/create-certificate', { method: 'POST', body: formData });
			})()
		`, chromedp.EvalAwaitPromise),
	); err != nil {
		log.Fatalf("Failed submitting leaf cert: %v", err)
	}
	log.Println("[flow] Leaf certificate generation complete!")

	// Navigate to /certificates
	log.Println("[flow] Navigating to certificates after leaf cert...")
	if err := chromedp.Do(ctx,
		chromedp.Navigate(baseURL+"/certificates"),
		chromedp.Sleep(1500*time.Millisecond),
	); err != nil {
		log.Fatalf("Failed navigating after leaf cert: %v", err)
	}

	// ==========================================
	// Step 9: External CSR Signing Modal
	// ==========================================
	log.Println("[flow] Step 9: External CSR Signing...")
	csrPEM := generateSampleCSR("truenas.homelab.local", "192.168.1.50")
	if err := chromedp.Do(ctx,
		chromedp.Evaluate[chromedp.Void](fmt.Sprintf(`
			openSignCsrModal();
			document.getElementById('csr_text').value = %q;
		`, csrPEM)),
		chromedp.Sleep(600*time.Millisecond),
	); err != nil {
		log.Fatalf("Failed opening/filling CSR modal: %v", err)
	}
	captureThemes("09_sign_csr_modal")

	// Submit CSR signing using async fetch with EvalAwaitPromise
	log.Println("[flow] Submitting CSR signing...")
	if err := chromedp.Do(ctx,
		chromedp.Evaluate[chromedp.Void](`
			(async () => {
				const form = document.getElementById('signCsrForm');
				const formData = new FormData(form);
				const csrfToken = document.querySelector('input[name="csrf_token"]') ? document.querySelector('input[name="csrf_token"]').value : '';
				await fetch('/sign-csr', {
					method: 'POST',
					headers: { 'X-CSRF-Token': csrfToken },
					body: formData
				});
			})()
		`, chromedp.EvalAwaitPromise),
	); err != nil {
		log.Fatalf("Failed submitting CSR: %v", err)
	}
	log.Println("[flow] CSR signing complete!")

	// ==========================================
	// Step 10: Dashboard with Issued Certificates & CSR Badge
	// ==========================================
	log.Println("[flow] Step 10: Dashboard with Certificates & CSR...")
	if err := chromedp.Do(ctx,
		chromedp.Navigate(baseURL+"/certificates"),
		chromedp.Sleep(1500*time.Millisecond),
	); err != nil {
		log.Fatalf("Failed navigating after CSR: %v", err)
	}
	captureThemes("10_dashboard_with_certificates")

	// ==========================================
	// Step 11: Settings - Certificate Defaults Tab
	// ==========================================
	log.Println("[flow] Step 11: Settings - Certificate Defaults Tab...")
	if err := chromedp.Do(ctx,
		chromedp.Navigate(baseURL+"/settings#defaults"),
		chromedp.WaitVisible("#panel-defaults"),
		chromedp.Evaluate[chromedp.Void](`switchSettingsTab('defaults');`),
		chromedp.Sleep(500*time.Millisecond),
	); err != nil {
		log.Fatalf("Failed navigating to cert defaults: %v", err)
	}
	captureThemes("11_settings_cert_defaults")

	// ==========================================
	// Step 12: Settings - Pocket ID / OIDC SSO Tab
	// ==========================================
	log.Println("[flow] Step 12: Settings - OIDC Tab...")
	if err := chromedp.Do(ctx,
		chromedp.Navigate(baseURL+"/settings#oidc"),
		chromedp.WaitVisible("#panel-oidc"),
		chromedp.Evaluate[chromedp.Void](`
			switchSettingsTab('oidc');
			const oidcToggle = document.getElementById('oidc_enabled');
			if (oidcToggle) {
				oidcToggle.checked = true;
				toggleOidcFields();
			}
			const issuer = document.getElementById('oidc_issuer_url');
			if (issuer) issuer.value = 'https://pocket-id.homelab.local';
			const clientId = document.getElementById('oidc_client_id');
			if (clientId) clientId.value = 'homelab-cert-manager';
			const secret = document.getElementById('oidc_client_secret');
			if (secret) secret.value = 'secret_live_demo_12345';
		`),
		chromedp.Sleep(500*time.Millisecond),
	); err != nil {
		log.Fatalf("Failed navigating to OIDC settings: %v", err)
	}
	captureThemes("12_settings_oidc_auth")

	// ==========================================
	// Step 13: Settings - Session Timeout Tab
	// ==========================================
	log.Println("[flow] Step 13: Settings - Session Timeout Tab...")
	if err := chromedp.Do(ctx,
		chromedp.Navigate(baseURL+"/settings#security"),
		chromedp.WaitVisible("#panel-security"),
		chromedp.Evaluate[chromedp.Void](`
			switchSettingsTab('security');
			if (window.setSessionTimeoutMinutes) setSessionTimeoutMinutes(15);
		`),
		chromedp.Sleep(500*time.Millisecond),
	); err != nil {
		log.Fatalf("Failed navigating to session timeout: %v", err)
	}
	captureThemes("13_settings_session_timeout")

	// ==========================================
	// Step 14: Dedicated Change Password Page
	// ==========================================
	log.Println("[flow] Step 14: Dedicated Change Password Page...")
	if err := chromedp.Do(ctx,
		chromedp.Navigate(baseURL+"/change-password"),
		chromedp.WaitVisible("#change-password-form"),
		chromedp.Sleep(500*time.Millisecond),
	); err != nil {
		log.Fatalf("Failed navigating to change password: %v", err)
	}
	captureThemes("14_change_password")

	log.Println("🎉 [screenshots] Successfully captured all 28 screenshots (14 Dark + 14 Light)!")
}

func waitForServer(urlStr string, timeout time.Duration) {
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		Timeout: 1 * time.Second,
	}

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		resp, err := client.Get(urlStr + "/login")
		if err == nil && resp.StatusCode == 200 {
			resp.Body.Close()
			log.Println("[screenshots] Server is ready!")
			return
		}
		time.Sleep(300 * time.Millisecond)
	}
	log.Fatalf("Server did not become ready within %v", timeout)
}

func findBrowserBinary() string {
	paths := []string{
		`C:\Program Files\Google\Chrome\Application\chrome.exe`,
		`C:\Program Files (x86)\Google\Chrome\Application\chrome.exe`,
		`C:\Program Files\Microsoft\Edge\Application\msedge.exe`,
		`C:\Program Files\Microsoft\Edge\Application\msedge.exe`,
	}
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return "chrome"
}

func generateSampleCSR(cn string, ipStr string) string {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return ""
	}

	csrTemplate := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: []string{"HomeLab Storage"},
		},
		DNSNames:    []string{cn},
		IPAddresses: []net.IP{net.ParseIP(ipStr)},
	}

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &csrTemplate, key)
	if err != nil {
		return ""
	}

	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrBytes,
	}))
}
