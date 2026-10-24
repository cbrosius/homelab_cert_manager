package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"html/template"
	"math/big"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

func setupEphemeralRootCA(certPath, keyPath string) error {
	_ = os.MkdirAll(filepath.Dir(certPath), 0700)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return err
	}

	tmpl := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   "HomeLab Test Root CA",
			Organization: []string{"HomeLab Test CA"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return err
	}

	certOut, err := os.OpenFile(certPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer certOut.Close()
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		return err
	}

	keyOut, err := os.OpenFile(keyPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer keyOut.Close()
	return pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
}

func TestMain(m *testing.M) {
	if _, err := os.Stat("templates"); os.IsNotExist(err) {
		if _, err := os.Stat("../../templates"); err == nil {
			_ = os.Chdir("../..")
		}
	}

	// Backup live settings.json before any tests run
	originalSettings, origSettingsErr := os.ReadFile("data/settings.json")

	_ = os.MkdirAll(filepath.Join("data", "certs"), 0750)
	rootCertDir := filepath.Join("data", "root-cert")
	_ = os.MkdirAll(rootCertDir, 0700)

	certPath := filepath.Join(rootCertDir, "HomeLab_Root_CA.pem")
	keyPath := filepath.Join(rootCertDir, "HomeLab_Root_CA.key")

	created := false
	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		if err := setupEphemeralRootCA(certPath, keyPath); err == nil {
			created = true
		}
	}

	code := m.Run()

	if created {
		_ = os.Remove(certPath)
		_ = os.Remove(keyPath)
	}

	// Restore live settings.json after all tests complete
	if origSettingsErr == nil {
		_ = os.WriteFile("data/settings.json", originalSettings, 0600)
		_ = initSettings()
	}

	os.Exit(code)
}

func generateTestCSR(commonName string, dnsNames []string, ips []net.IP) ([]byte, *rsa.PrivateKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	csrTemplate := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"Homelab Test Org"},
		},
		DNSNames:    dnsNames,
		IPAddresses: ips,
	}

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &csrTemplate, key)
	if err != nil {
		return nil, nil, err
	}

	var buf bytes.Buffer
	if err := pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes}); err != nil {
		return nil, nil, err
	}

	return buf.Bytes(), key, nil
}

func TestSignCSR_Success(t *testing.T) {
	cn := "test-device-csr.local"
	dns := []string{"test-device-csr.local", "alt.test-device-csr.local"}
	ips := []net.IP{net.ParseIP("192.168.1.100")}

	csrPEM, _, err := generateTestCSR(cn, dns, ips)
	if err != nil {
		t.Fatalf("Failed to generate test CSR: %v", err)
	}

	// Sign CSR
	err = SignCSR(csrPEM, 90)
	if err != nil {
		t.Fatalf("SignCSR failed: %v", err)
	}

	certPath := filepath.Join("data", "certs", cn+".pem")
	defer os.Remove(certPath) // Cleanup

	// Verify certificate was written
	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		t.Fatalf("Expected signed cert file %s to exist", certPath)
	}

	// Parse signed certificate
	certBytes, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("Failed to read signed cert: %v", err)
	}

	block, _ := pem.Decode(certBytes)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatalf("Expected valid CERTIFICATE PEM block, got %v", block)
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse signed certificate: %v", err)
	}

	if cert.Subject.CommonName != cn {
		t.Errorf("Expected CommonName %q, got %q", cn, cert.Subject.CommonName)
	}
	if len(cert.DNSNames) != len(dns) || cert.DNSNames[0] != dns[0] {
		t.Errorf("DNSNames mismatch: expected %v, got %v", dns, cert.DNSNames)
	}
	if len(cert.IPAddresses) != 1 || !cert.IPAddresses[0].Equal(ips[0]) {
		t.Errorf("IPAddresses mismatch: expected %v, got %v", ips, cert.IPAddresses)
	}

	// Verify it does NOT have a private key
	keyPath := filepath.Join("data", "certs", cn+".key")
	if _, err := os.Stat(keyPath); err == nil {
		t.Errorf("CSR-signed cert should not have a private key file at %s", keyPath)
	}
}

func TestSignCSR_MissingCN_UsesSAN(t *testing.T) {
	dns := []string{"headless-device.local"}
	csrPEM, _, err := generateTestCSR("", dns, nil)
	if err != nil {
		t.Fatalf("Failed to generate test CSR: %v", err)
	}

	err = SignCSR(csrPEM, 30)
	if err != nil {
		t.Fatalf("SignCSR failed for CSR with empty CN but valid SAN: %v", err)
	}

	certPath := filepath.Join("data", "certs", "headless-device.local.pem")
	defer os.Remove(certPath)

	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		t.Fatalf("Expected cert file %s to exist", certPath)
	}
}

func TestSignCSR_InvalidPEM(t *testing.T) {
	err := SignCSR([]byte("not a pem block at all"), 30)
	if err == nil {
		t.Fatalf("Expected error for non-PEM input, got nil")
	}
	if !strings.Contains(err.Error(), "no valid PEM data found") {
		t.Errorf("Unexpected error message: %v", err)
	}
}

func TestSignCSR_InvalidSignature(t *testing.T) {
	cn := "tampered-csr.local"
	csrPEM, _, err := generateTestCSR(cn, nil, nil)
	if err != nil {
		t.Fatalf("Failed to generate test CSR: %v", err)
	}

	block, _ := pem.Decode(csrPEM)
	// Tamper with the raw DER bytes of the CSR to break its signature
	if len(block.Bytes) > 10 {
		block.Bytes[len(block.Bytes)-5] ^= 0xFF
	}
	tamperedPEM := pem.EncodeToMemory(block)

	err = SignCSR(tamperedPEM, 30)
	if err == nil {
		t.Fatalf("Expected error for CSR with invalid signature, got nil")
	}
}

func TestHandleSignCSR_EmptyInput(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/sign-csr", handleSignCSR)

	// Send request with no file and no text
	req, _ := http.NewRequest(http.MethodPost, "/sign-csr", nil)
	req.Header.Set("Accept", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400 Bad Request for empty CSR submission, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "Please provide a CSR") {
		t.Errorf("Expected body to ask for CSR, got %s", w.Body.String())
	}
}

func TestHandleSignCSR_MultipartUpload(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/sign-csr", handleSignCSR)

	cn := "multipart-test.local"
	csrPEM, _, err := generateTestCSR(cn, []string{cn}, nil)
	if err != nil {
		t.Fatalf("Failed to generate test CSR: %v", err)
	}

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	part, err := writer.CreateFormFile("csr_file", "device.csr")
	if err != nil {
		t.Fatalf("Failed to create form file: %v", err)
	}
	part.Write(csrPEM)
	writer.WriteField("validity_days", "60")
	writer.Close()

	req, _ := http.NewRequest(http.MethodPost, "/sign-csr", body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("Accept", "application/json")

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	certPath := filepath.Join("data", "certs", cn+".pem")
	defer os.Remove(certPath)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK, got %d. Body: %s", w.Code, w.Body.String())
	}
	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		t.Fatalf("Expected certificate file %s to exist", certPath)
	}
}

func TestHandleSignCSR_ValidityYears(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/sign-csr", handleSignCSR)

	cn := "validity-years-test.local"
	csrPEM, _, err := generateTestCSR(cn, []string{cn}, nil)
	if err != nil {
		t.Fatalf("Failed to generate test CSR: %v", err)
	}

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	writer.WriteField("csr_text", string(csrPEM))
	writer.WriteField("validity_years", "5")
	writer.Close()

	req, _ := http.NewRequest(http.MethodPost, "/sign-csr", body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("Accept", "application/json")

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	certPath := filepath.Join("data", "certs", cn+".pem")
	defer os.Remove(certPath)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK, got %d. Body: %s", w.Code, w.Body.String())
	}

	cert, err := readCertificate(certPath)
	if err != nil {
		t.Fatalf("Failed to read signed cert: %v", err)
	}

	// Verify expiry is approximately 5 years out
	approxDays := cert.NotAfter.Sub(cert.NotBefore).Hours() / 24
	if approxDays < 1800 || approxDays > 1850 {
		t.Errorf("Expected ~1825 days for 5 years, got %f", approxDays)
	}
}

func TestCheckRootCertAndListCerts_HasPrivateKey(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.SetFuncMap(template.FuncMap{
		"toJson": toJson,
	})
	r.LoadHTMLGlob("templates/*")
	r.GET("/certificates", checkRootCertAndListCerts)

	// Create a test CSR cert (without private key)
	cn := "csr-metadata-test.local"
	csrPEM, _, err := generateTestCSR(cn, []string{cn}, nil)
	if err != nil {
		t.Fatalf("Failed to generate CSR: %v", err)
	}
	if err := SignCSR(csrPEM, 30); err != nil {
		t.Fatalf("Failed to sign CSR: %v", err)
	}
	defer os.Remove(filepath.Join("data", "certs", cn+".pem"))

	req, _ := http.NewRequest(http.MethodGet, "/certificates", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK, got %d. Body: %s", w.Code, w.Body.String())
	}

	body := w.Body.String()
	// Should render the certificate name and the CSR badge
	if !strings.Contains(body, cn) {
		t.Errorf("Expected cert list to contain %q", cn)
	}
	if !strings.Contains(body, "CSR</span>") {
		t.Errorf("Expected cert list to contain CSR badge for CSR certificate")
	}
}
