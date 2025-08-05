package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/spf13/viper"
)

// Helper function to create a mock gin.Context
func GetTestContext(w *httptest.ResponseRecorder) *gin.Context {
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = &http.Request{
		Header: make(http.Header),
		URL:	&url.URL{},
	}
	return ctx
}

func TestConvertIPsToStrings(t *testing.T) {
	tests := []struct {
		name string
		ips  []net.IP
		want []string
	}{
		{
			name: "empty slice",
			ips:  []net.IP{},
			want: nil,
		},
		{
			name: "single IPv4",
			ips:  []net.IP{net.ParseIP("192.168.1.1")},
			want: []string{"192.168.1.1"},
		},
		{
			name: "multiple IPv4s",
			ips:  []net.IP{net.ParseIP("10.0.0.1"), net.ParseIP("172.16.0.10")},
			want: []string{"10.0.0.1", "172.16.0.10"},
		},
		{
			name: "single IPv6",
			ips:  []net.IP{net.ParseIP("::1")},
			want: []string{"::1"},
		},
		{
			name: "mixed IPv4 and IPv6",
			ips:  []net.IP{net.ParseIP("192.168.1.1"), net.ParseIP("2001:0db8::1")},
			want: []string{"192.168.1.1", "2001:db8::1"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := convertIPsToStrings(tt.ips)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("convertIPsToStrings() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestReadCertificate(t *testing.T) {
	// Create a temporary directory for test files
	tempDir, err := os.MkdirTemp("", "cert_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir) // Clean up after test

	// Generate a dummy certificate
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(2023),
		Subject: pkix.Name{
			Organization: []string{"Test Org"},
			CommonName:   "Test CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	caPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate CA private key: %v", err)
	}
	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
			t.Fatalf("Failed to create CA certificate: %v", err)
	}

	certPath := filepath.Join(tempDir, "test_cert.pem")
	certFile, err := os.Create(certPath)
	if err != nil {
		t.Fatalf("Failed to create cert file: %v", err)
	}
	defer certFile.Close()
	pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: caBytes})

	// Test case 1: Valid certificate file
	t.Run("valid certificate", func(t *testing.T) {
		cert, err := readCertificate(certPath)
		if err != nil {
			t.Errorf("readCertificate() error = %v, want nil", err)
		}
		if cert == nil {
			t.Error("readCertificate() got nil certificate, want non-nil")
		}
		if cert.Subject.CommonName != "Test CA" {
			t.Errorf("readCertificate() got common name %q, want %q", cert.Subject.CommonName, "Test CA")
		}
	})

	// Test case 2: Non-existent file
	t.Run("non-existent file", func(t *testing.T) {
		_, err := readCertificate(filepath.Join(tempDir, "non_existent.pem"))
		if err == nil {
			t.Error("readCertificate() got nil error for non-existent file, want error")
		}
	})

	// Test case 3: Invalid PEM content
	t.Run("invalid pem content", func(t *testing.T) {
		invalidCertPath := filepath.Join(tempDir, "invalid_cert.pem")
		err := os.WriteFile(invalidCertPath, []byte("this is not a valid pem"), 0644)
		if err != nil {
			t.Fatalf("Failed to write invalid cert file: %v", err)
		}
		_, err = readCertificate(invalidCertPath)
		if err == nil {
			t.Error("readCertificate() got nil error for invalid PEM, want error")
		}
	})
}

func TestFindRootCertAndKey(t *testing.T) {
	// Temporarily change the working directory to the project root for this test
	originalDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get current working directory: %v", err)
	}
	err = os.Chdir("c:\\Projekte\\GO\\homelab_cert_manager")
	if err != nil {
		t.Fatalf("Failed to change directory to project root: %v", err)
	}
	defer os.Chdir(originalDir) // Restore original working directory

	// Test case 1: Valid root certificate and key found
	t.Run("valid root cert and key", func(t *testing.T) {
		tempDir, err := os.MkdirTemp("", "root_cert_test_valid")
		if err != nil {
			t.Fatalf("Failed to create temp dir: %v", err)
		}
		defer os.RemoveAll(tempDir)

		rootCertDir := filepath.Join(tempDir, "data", "root-cert")
		err = os.MkdirAll(rootCertDir, 0755)
		if err != nil {
			t.Fatalf("Failed to create root-cert dir: %v", err)
		}

		ca := &x509.Certificate{
			SerialNumber: big.NewInt(2024),
			Subject: pkix.Name{
				Organization: []string{"Root CA Org"},
				CommonName:   "Root CA",
			},
			NotBefore:             time.Now(),
			NotAfter:              time.Now().AddDate(1, 0, 0),
			IsCA:                  true,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
			KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
			BasicConstraintsValid: true,
		}
		caPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("Failed to generate CA private key: %v", err)
		}
		caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &caPrivKey.PublicKey, caPrivKey)
		if err != nil {
			t.Fatalf("Failed to create CA certificate: %v", err)
		}

		certPath := filepath.Join(rootCertDir, "root_cert.pem")
		certFile, err := os.Create(certPath)
		if err != nil {
			t.Fatalf("Failed to create cert file: %v", err)
		}
		defer certFile.Close()
		pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: caBytes})

		keyPath := filepath.Join(rootCertDir, "root_key.key")
		keyFile, err := os.Create(keyPath)
		if err != nil {
			t.Fatalf("Failed to create key file: %v", err)
		}
		defer keyFile.Close()
		pem.Encode(keyFile, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(caPrivKey)})

		// Temporarily change the working directory to the tempDir for this sub-test
		subTestOriginalDir, err := os.Getwd()
		if err != nil {
			t.Fatalf("Failed to get current working directory: %v", err)
		}
		err = os.Chdir(tempDir)
		if err != nil {
			t.Fatalf("Failed to change directory to tempDir: %v", err)
		}
		defer os.Chdir(subTestOriginalDir) // Restore original working directory for sub-test

		cert, key, err := findRootCertAndKey()
		if err != nil {
			t.Errorf("findRootCertAndKey() error = %v, want nil", err)
		}
		if cert == nil {
			t.Error("findRootCertAndKey() got nil certificate, want non-nil")
		}
		if key == nil {
			t.Error("findRootCertAndKey() got nil key, want non-nil")
		}
		if cert.Subject.CommonName != "Root CA" {
			t.Errorf("findRootCertAndKey() got common name %q, want %q", cert.Subject.CommonName, "Root CA")
		}
	})

	// Test case 2: Missing root certificate
	t.Run("missing root certificate", func(t *testing.T) {
		tempDir, err := os.MkdirTemp("", "root_cert_test_missing_cert")
		if err != nil {
			t.Fatalf("Failed to create temp dir: %v", err)
		}
		defer os.RemoveAll(tempDir)

		rootCertDir := filepath.Join(tempDir, "data", "root-cert")
		err = os.MkdirAll(rootCertDir, 0755)
		if err != nil {
			t.Fatalf("Failed to create root-cert dir: %v", err)
		}

		// Only create key file, not cert file
		caPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("Failed to generate CA private key: %v", err)
		}
		keyPath := filepath.Join(rootCertDir, "root_key.key")
		keyFile, err := os.Create(keyPath)
		if err != nil {
			t.Fatalf("Failed to create key file: %v", err)
		}
		defer keyFile.Close()
		pem.Encode(keyFile, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(caPrivKey)})

		// Temporarily change the working directory to the tempDir for this sub-test
		subTestOriginalDir, err := os.Getwd()
		if err != nil {
			t.Fatalf("Failed to get current working directory: %v", err)
		}
		err = os.Chdir(tempDir)
		if err != nil {
			t.Fatalf("Failed to change directory to tempDir: %v", err)
		}
		defer os.Chdir(subTestOriginalDir) // Restore original working directory for sub-test

		_, _, err = findRootCertAndKey()
		if err == nil {
			t.Error("findRootCertAndKey() got nil error for missing cert, want error")
		}
	})

	// Test case 3: Missing root key
	t.Run("missing root key", func(t *testing.T) {
		tempDir, err := os.MkdirTemp("", "root_cert_test_missing_key")
		if err != nil {
			t.Fatalf("Failed to create temp dir: %v", err)
		}
		defer os.RemoveAll(tempDir)

		rootCertDir := filepath.Join(tempDir, "data", "root-cert")
		err = os.MkdirAll(rootCertDir, 0755)
		if err != nil {
			t.Fatalf("Failed to create root-cert dir: %v", err)
		}

		// Only create cert file, not key file
		ca := &x509.Certificate{
			SerialNumber: big.NewInt(2024),
			Subject: pkix.Name{
				Organization: []string{"Root CA Org"},
				CommonName:   "Root CA",
			},
			NotBefore:             time.Now(),
			NotAfter:              time.Now().AddDate(1, 0, 0),
			IsCA:                  true,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
			KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
			BasicConstraintsValid: true,
		}
		caPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("Failed to generate CA private key: %v", err)
		}
		caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &caPrivKey.PublicKey, caPrivKey)
		if err != nil {
			t.Fatalf("Failed to create CA certificate: %v", err)
		}
		certPath := filepath.Join(rootCertDir, "root_cert.pem")
		certFile, err := os.Create(certPath)
		if err != nil {
			t.Fatalf("Failed to create cert file: %v", err)
		}
		defer certFile.Close()
		pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: caBytes})

		// Temporarily change the working directory to the tempDir for this sub-test
		subTestOriginalDir, err := os.Getwd()
		if err != nil {
			t.Fatalf("Failed to get current working directory: %v", err)
		}
		err = os.Chdir(tempDir)
		if err != nil {
			t.Fatalf("Failed to change directory to tempDir: %v", err)
		}
		defer os.Chdir(subTestOriginalDir) // Restore original working directory for sub-test

		_, _, err = findRootCertAndKey()
		if err == nil {
			t.Error("findRootCertAndKey() got nil error for missing key, want error")
		}
	})
}

func TestCheckRootCertAndListCerts(t *testing.T) {
	// Set Gin to TestMode
	gin.SetMode(gin.TestMode)

	// Set up a temporary directory for test data
	tempDir, err := os.MkdirTemp("", "test_data")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Backup original working directory and change to tempDir
	originalDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get current working directory: %v", err)
	}
	err = os.Chdir(tempDir)
	if err != nil {
		t.Fatalf("Failed to change directory to tempDir: %v", err)
	}
	defer os.Chdir(originalDir)

	// Create necessary directories
	os.MkdirAll(filepath.Join("data", "root-cert"), 0755)
	os.MkdirAll(filepath.Join("data", "certmanager-cert"), 0755)
	os.MkdirAll(filepath.Join("data", "certs"), 0755)

	// Create a dummy templates directory and cert_list.html
	templatesDir := filepath.Join(tempDir, "templates")
	os.MkdirAll(templatesDir, 0755)
	ioutil.WriteFile(filepath.Join(templatesDir, "cert_list.html"), []byte("<html><body>Cert List</body></html>"), 0644)

	// Mock viper settings
	viper.Set("password", "mocked_hashed_password")
	viper.Set("general_cert_options.organization", "Test Org")
	viper.Set("general_cert_options.organization_unit", "Test OU")
	viper.Set("general_cert_options.country", "US")
	viper.Set("general_cert_options.state", "CA")
	viper.Set("general_cert_options.location", "Test City")

	// Create dummy root certificate
	rootCert := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "HomeLab Root CA",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(10, 0, 0),
		IsCA:      true,
		KeyUsage:  x509.KeyUsageCertSign,
	}
	rootPrivKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	rootCertBytes, _ := x509.CreateCertificate(rand.Reader, rootCert, rootCert, &rootPrivKey.PublicKey, rootPrivKey)
	ioutil.WriteFile(filepath.Join("data", "root-cert", "HomeLab_Root_CA.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootCertBytes}), 0644)

	// Create dummy homelab certificate
	homelabCert := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName: "homelab_certificate_manager",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(1, 0, 0),
	}
	homelabPrivKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	homelabCertBytes, _ := x509.CreateCertificate(rand.Reader, homelabCert, rootCert, &homelabPrivKey.PublicKey, rootPrivKey)
	ioutil.WriteFile(filepath.Join("data", "certmanager-cert", "homelab_certificate_manager.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: homelabCertBytes}), 0644)

	// Create dummy self-signed certificate
	selfSignedCert := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject: pkix.Name{
			CommonName: "selfsigned",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(1, 0, 0),
	}
	selfSignedPrivKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	selfSignedCertBytes, _ := x509.CreateCertificate(rand.Reader, selfSignedCert, selfSignedCert, &selfSignedPrivKey.PublicKey, selfSignedPrivKey)
	ioutil.WriteFile(filepath.Join("data", "certmanager-cert", "selfsigned.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: selfSignedCertBytes}), 0644)

	// Create dummy client certificate
	clientCert := &x509.Certificate{
		SerialNumber: big.NewInt(4),
		Subject: pkix.Name{
			CommonName: "client_cert",
		},
		DNSNames:  []string{"client.example.com"},
		IPAddresses: []net.IP{net.ParseIP("192.168.1.100")},
		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(1, 0, 0),
	}
	clientPrivKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	clientCertBytes, _ := x509.CreateCertificate(rand.Reader, clientCert, rootCert, &clientPrivKey.PublicKey, rootPrivKey)
	ioutil.WriteFile(filepath.Join("data", "certs", "client_cert.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientCertBytes}), 0644)

	// Create a Gin engine and load templates
	r := gin.New()
	r.LoadHTMLGlob(filepath.Join(templatesDir, "*.html"))
	r.GET("/certificates", checkRootCertAndListCerts)

	// Create a request to the handler
	req, _ := http.NewRequest(http.MethodGet, "/certificates", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
	}

	// Verify that the HTML content contains expected strings
	expectedContent := "Cert List"
	if !strings.Contains(w.Body.String(), expectedContent) {
		t.Errorf("Expected response body to contain \"%s\", got \"%s\"", expectedContent, w.Body.String())
	}

	// Note: Directly verifying the data passed to c.HTML is complex without refactoring
	// the original function or using a more advanced mocking library. For now, we rely
	// on the status code and a simple content check.
}

func TestCreateCertificate(t *testing.T) {
	// Set up a temporary directory for test data
	tempDir, err := os.MkdirTemp("", "test_create_cert")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Backup original working directory and change to tempDir
	originalDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get current working directory: %v", err)
	}
	err = os.Chdir(tempDir)
	if err != nil {
		t.Fatalf("Failed to change directory to tempDir: %v", err)
	}
	defer os.Chdir(originalDir)

	// Create necessary directories
	os.MkdirAll(filepath.Join("data", "root-cert"), 0755)
	os.MkdirAll(filepath.Join("data", "certs"), 0755)

	// Create dummy root certificate and key
	rootCert := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "HomeLab Root CA",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(10, 0, 0),
		IsCA:      true,
		KeyUsage:  x509.KeyUsageCertSign,
	}
	rootPrivKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	rootCertBytes, _ := x509.CreateCertificate(rand.Reader, rootCert, rootCert, &rootPrivKey.PublicKey, rootPrivKey)
	ioutil.WriteFile(filepath.Join("data", "root-cert", "HomeLab_Root_CA.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootCertBytes}), 0644)
	ioutil.WriteFile(filepath.Join("data", "root-cert", "HomeLab_Root_CA.key"), pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rootPrivKey)}), 0644)

	// Set Gin to TestMode
	gin.SetMode(gin.TestMode)

	// Create a Gin engine and register the handler
	r := gin.New()
	r.POST("/create", createCertificate)

	t.Run("successful certificate creation", func(t *testing.T) {
		// Create a new multipart writer
		body := &bytes.Buffer{}
		writer := multipart.NewWriter(body)

		writer.WriteField("common_name", "test_cert")
		writer.WriteField("validity_years", "1")
		writer.WriteField("organization", "Test Org")
		writer.WriteField("organization_unit", "Test OU")
		writer.WriteField("country", "US")
		writer.WriteField("state", "CA")
		writer.WriteField("location", "Test City")
		writer.WriteField("email", "test@example.com")
		writer.WriteField("dns", "test.example.com")
		writer.WriteField("ip", "192.168.1.1")
		writer.Close()

		req, _ := http.NewRequest(http.MethodPost, "/create", body)
		req.Header.Set("Content-Type", writer.FormDataContentType())
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status %d, got %d. Response: %s", http.StatusOK, w.Code, w.Body.String())
		}

		var response map[string]string
		err = json.Unmarshal(w.Body.Bytes(), &response)
		if err != nil {
			t.Fatalf("Failed to unmarshal response: %v", err)
		}

		if response["message"] != "Certificate created successfully" {
			t.Errorf("Expected success message, got %s", response["message"])
		}
		if response["redirect"] != "/certificates" {
			t.Errorf("Expected redirect to /certificates, got %s", response["redirect"])
		}

		// Verify files are created
		if _, err := os.Stat(filepath.Join("data", "certs", "test_cert.pem")); os.IsNotExist(err) {
			t.Error("Certificate file not created")
		}
		if _, err := os.Stat(filepath.Join("data", "certs", "test_cert.key")); os.IsNotExist(err) {
			t.Error("Key file not created")
		}
		if _, err := os.Stat(filepath.Join("data", "certs", "test_cert.pfx")); os.IsNotExist(err) {
			t.Error("PFX file not created")
		}
	})

	t.Run("certificate already exists without overwrite", func(t *testing.T) {
		// Create a dummy certificate file to simulate existing one
		ioutil.WriteFile(filepath.Join("data", "certs", "existing_cert.pem"), []byte("dummy cert"), 0644)

		body := &bytes.Buffer{}
		writer := multipart.NewWriter(body)
		writer.WriteField("common_name", "existing_cert")
		writer.WriteField("validity_years", "1")
		writer.Close()

		req, _ := http.NewRequest(http.MethodPost, "/create", body)
		req.Header.Set("Content-Type", writer.FormDataContentType())
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		if w.Code != http.StatusOK { // It returns 200 with an error message
			t.Errorf("Expected status %d, got %d. Response: %s", http.StatusOK, w.Code, w.Body.String())
		}

		var response map[string]string
		err = json.Unmarshal(w.Body.Bytes(), &response)
		if err != nil {
			t.Fatalf("Failed to unmarshal response: %v", err)
		}

		expectedError := "A certificate with the same common name already exists. Do you want to overwrite it?"
		if response["error"] != expectedError {
			t.Errorf("Expected error message '%s', got '%s'", expectedError, response["error"])
		}
	})

	t.Run("certificate already exists with overwrite", func(t *testing.T) {
		// Create a dummy certificate file to simulate existing one
		ioutil.WriteFile(filepath.Join("data", "certs", "overwrite_cert.pem"), []byte("dummy cert"), 0644)

		body := &bytes.Buffer{}
		writer := multipart.NewWriter(body)
		writer.WriteField("common_name", "overwrite_cert")
		writer.WriteField("validity_years", "1")
		writer.WriteField("overwrite", "yes") // Set overwrite to "yes"
		writer.WriteField("organization", "Test Org")
		writer.WriteField("organization_unit", "Test OU")
		writer.WriteField("country", "US")
		writer.WriteField("state", "CA")
		writer.WriteField("location", "Test City")
		writer.WriteField("email", "overwrite@example.com")
		writer.Close()

		req, _ := http.NewRequest(http.MethodPost, "/create", body)
		req.Header.Set("Content-Type", writer.FormDataContentType())
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status %d, got %d. Response: %s", http.StatusOK, w.Code, w.Body.String())
		}

		var response map[string]string
		err = json.Unmarshal(w.Body.Bytes(), &response)
		if err != nil {
			t.Fatalf("Failed to unmarshal response: %v", err)
		}

		if response["message"] != "Certificate created successfully" {
			t.Errorf("Expected success message, got %s", response["message"])
		}
		if response["redirect"] != "/certificates" {
			t.Errorf("Expected redirect to /certificates, got %s", response["redirect"])
		}

		// Verify files are created (overwritten)
		if _, err := os.Stat(filepath.Join("data", "certs", "overwrite_cert.pem")); os.IsNotExist(err) {
			t.Error("Certificate file not created (overwritten)")
		}
		if _, err := os.Stat(filepath.Join("data", "certs", "overwrite_cert.key")); os.IsNotExist(err) {
			t.Error("Key file not created (overwritten)")
		}
		if _, err := os.Stat(filepath.Join("data", "certs", "overwrite_cert.pfx")); os.IsNotExist(err) {
			t.Error("PFX file not created (overwritten)")
		}
	})

	t.Run("invalid validity years", func(t *testing.T) {
		body := &bytes.Buffer{}
		writer := multipart.NewWriter(body)
		writer.WriteField("common_name", "invalid_cert")
		writer.WriteField("validity_years", "abc") // Invalid input
		writer.Close()

		req, _ := http.NewRequest(http.MethodPost, "/create", body)
		req.Header.Set("Content-Type", writer.FormDataContentType())
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("Expected status %d, got %d", http.StatusBadRequest, w.Code)
		}

		var response map[string]string
		err = json.Unmarshal(w.Body.Bytes(), &response)
		if err != nil {
			t.Fatalf("Failed to unmarshal response: %v", err)
		}

		if response["error"] != "Invalid validity period" {
			t.Errorf("Expected error message 'Invalid validity period', got %s", response["error"])
		}
	})
}

func TestDownloadCertificate(t *testing.T) {
	// Set up a temporary directory for test data
	tempDir, err := os.MkdirTemp("", "test_download_cert")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Backup original working directory and change to tempDir
	originalDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get current working directory: %v", err)
	}
	err = os.Chdir(tempDir)
	if err != nil {
		t.Fatalf("Failed to change directory to tempDir: %v", err)
	}
	defer os.Chdir(originalDir)

	// Create necessary directories
	os.MkdirAll(filepath.Join("data", "root-cert"), 0755)
	os.MkdirAll(filepath.Join("data", "certs"), 0755)

	// Create dummy files for testing download
	ioutil.WriteFile(filepath.Join("data", "root-cert", "root.pem"), []byte("root cert content"), 0644)
	ioutil.WriteFile(filepath.Join("data", "certs", "server.pem"), []byte("server cert content"), 0644)
	ioutil.WriteFile(filepath.Join("data", "certs", "server.key"), []byte("server key content"), 0644)
	ioutil.WriteFile(filepath.Join("data", "certs", "server.pfx"), []byte("server pfx content"), 0644)
	ioutil.WriteFile(filepath.Join("data", "certs", "other.txt"), []byte("other file content"), 0644)

	// Set Gin to TestMode
	gin.SetMode(gin.TestMode)

	// Create a Gin engine and register the handler
	r := gin.New()
	r.GET("/download/:certType/:filename", downloadCertificate)

	tests := []struct {
		name       string
		certType   string
		filename   string
		expectedStatus int
		expectedContent string
		expectedContentType string
	}{
		{
			name:       "download root pem",
			certType:   "root-cert",
			filename:   "root.pem",
			expectedStatus: http.StatusOK,
			expectedContent: "root cert content",
			expectedContentType: "application/x-pem-file",
		},
		{
			name:       "download server pem",
			certType:   "certs",
			filename:   "server.pem",
			expectedStatus: http.StatusOK,
			expectedContent: "server cert content",
			expectedContentType: "application/x-pem-file",
		},
		{
			name:       "download server key",
			certType:   "certs",
			filename:   "server.key",
			expectedStatus: http.StatusOK,
			expectedContent: "server key content",
			expectedContentType: "application/x-pem-file",
		},
		{
			name:       "download server pfx",
			certType:   "certs",
			filename:   "server.pfx",
			expectedStatus: http.StatusOK,
			expectedContent: "server pfx content",
			expectedContentType: "application/x-pkcs12",
		},
		{
			name:       "download other file type",
			certType:   "certs",
			filename:   "other.txt",
			expectedStatus: http.StatusOK,
			expectedContent: "other file content",
			expectedContentType: "application/octet-stream",
		},
		{
			name:       "file not found",
			certType:   "certs",
			filename:   "non_existent.pem",
			expectedStatus: http.StatusNotFound,
			expectedContent: "File not found",
			expectedContentType: "text/plain; charset=utf-8",
		},
		{
			name:       "invalid cert type",
			certType:   "invalid",
			filename:   "some_file.pem",
			expectedStatus: http.StatusBadRequest,
			expectedContent: "Invalid certificate type",
			expectedContentType: "text/plain; charset=utf-8",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("/download/%s/%s", tt.certType, tt.filename), nil)
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d for %s", tt.expectedStatus, w.Code, tt.name)
			}
			if w.Body.String() != tt.expectedContent {
				t.Errorf("Expected content '%s', got '%s' for %s", tt.expectedContent, w.Body.String(), tt.name)
			}
			if w.Header().Get("Content-Type") != tt.expectedContentType {
				t.Errorf("Expected Content-Type '%s', got '%s' for %s", tt.expectedContentType, w.Header().Get("Content-Type"), tt.name)
			}
		})
	}
}

func TestDeleteCertificate(t *testing.T) {
	// Set up a temporary directory for test data
	tempDir, err := os.MkdirTemp("", "test_delete_cert")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Backup original working directory and change to tempDir
	originalDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get current working directory: %v", err)
	}
	err = os.Chdir(tempDir)
	if err != nil {
		t.Fatalf("Failed to change directory to tempDir: %v", err)
	}
	defer os.Chdir(originalDir)

	// Create necessary directories
	os.MkdirAll(filepath.Join("data", "certs"), 0755)

	// Set Gin to TestMode
	gin.SetMode(gin.TestMode)

	// Create a Gin engine and register the handler
	r := gin.New()
	r.GET("/delete/:filename", deleteCertificate)

	t.Run("successful deletion", func(t *testing.T) {
		// Create dummy files to be deleted
		ioutil.WriteFile(filepath.Join("data", "certs", "to_delete.pem"), []byte("cert"), 0644)
		ioutil.WriteFile(filepath.Join("data", "certs", "to_delete.key"), []byte("key"), 0644)
		ioutil.WriteFile(filepath.Join("data", "certs", "to_delete.pfx"), []byte("pfx"), 0644)

		req, _ := http.NewRequest(http.MethodGet, "/delete/to_delete.pem", nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		if w.Code != http.StatusSeeOther {
			t.Errorf("Expected status %d, got %d", http.StatusSeeOther, w.Code)
		}
		if w.Header().Get("Location") != "/certificates" {
			t.Errorf("Expected redirect to /certificates, got %s", w.Header().Get("Location"))
		}

		// Verify files are deleted
		if _, err := os.Stat(filepath.Join("data", "certs", "to_delete.pem")); !os.IsNotExist(err) {
			t.Error("Certificate file not deleted")
		}
		if _, err := os.Stat(filepath.Join("data", "certs", "to_delete.key")); !os.IsNotExist(err) {
			t.Error("Key file not deleted")
		}
		if _, err := os.Stat(filepath.Join("data", "certs", "to_delete.pfx")); !os.IsNotExist(err) {
			t.Error("PFX file not deleted")
		}
	})

	t.Run("delete non-existent certificate", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, "/delete/non_existent.pem", nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		// Should still redirect even if file not found, as per current implementation
		if w.Code != http.StatusInternalServerError {
			t.Errorf("Expected status %d, got %d", http.StatusInternalServerError, w.Code)
		}
		if !strings.Contains(w.Body.String(), "Error deleting certificate") {
			t.Errorf("Expected error message, got %s", w.Body.String())
		}
	})
}

func TestViewCertificate(t *testing.T) {
	// Set up a temporary directory for test data
	tempDir, err := os.MkdirTemp("", "test_view_cert")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Backup original working directory and change to tempDir
	originalDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get current working directory: %v", err)
	}
	err = os.Chdir(tempDir)
	if err != nil {
		t.Fatalf("Failed to change directory to tempDir: %v", err)
	}
	defer os.Chdir(originalDir)

	// Create necessary directories
	os.MkdirAll(filepath.Join("data", "certs"), 0755)
	os.MkdirAll(filepath.Join("data", "certmanager-cert"), 0755)

	// Create dummy root certificate (needed for signing client cert)
	rootCert := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "HomeLab Root CA",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(10, 0, 0),
		IsCA:      true,
		KeyUsage:  x509.KeyUsageCertSign,
	}
	rootPrivKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	rootCertBytes, _ := x509.CreateCertificate(rand.Reader, rootCert, rootCert, &rootPrivKey.PublicKey, rootPrivKey)
	ioutil.WriteFile(filepath.Join("data", "root-cert", "HomeLab_Root_CA.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootCertBytes}), 0644)

	// Set Gin to TestMode
	gin.SetMode(gin.TestMode)

	// Create a Gin engine and register the handler
	r := gin.New()
	r.GET("/view/:filename", viewCertificate)


	t.Run("view client certificate", func(t *testing.T) {
		// Create a dummy client certificate
		clientCert := &x509.Certificate{
			SerialNumber: big.NewInt(100),
			Subject: pkix.Name{
				CommonName: "client.example.com",
				Organization: []string{"Client Org"},
			},
			DNSNames:    []string{"client.example.com", "www.client.example.com"},
			IPAddresses: []net.IP{net.ParseIP("192.168.1.100"), net.ParseIP("10.0.0.5")},
			NotBefore:   time.Now().Add(-1 * time.Hour),
			NotAfter:    time.Now().Add(24 * time.Hour),
		}
		clientPrivKey, _ := rsa.GenerateKey(rand.Reader, 2048)
		clientCertBytes, _ := x509.CreateCertificate(rand.Reader, clientCert, rootCert, &clientPrivKey.PublicKey, rootPrivKey)
		ioutil.WriteFile(filepath.Join("data", "certs", "client.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientCertBytes}), 0644)

		req, _ := http.NewRequest(http.MethodGet, "/view/client.pem", nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status %d, got %d. Response: %s", http.StatusOK, w.Code, w.Body.String())
		}

		var response map[string]string
		err = json.Unmarshal(w.Body.Bytes(), &response)
		if err != nil {
			t.Fatalf("Failed to unmarshal response: %v", err)
		}

		decodedContent := response["decoded"]
		if !strings.Contains(decodedContent, "Issuer: CN=HomeLab Root CA") {
			t.Errorf("Decoded content missing issuer info: %s", decodedContent)
		}
		if !strings.Contains(decodedContent, "Subject: CN=client.example.com,O=Client Org") {
			t.Errorf("Decoded content missing subject info: %s", decodedContent)
		}
		if !strings.Contains(decodedContent, "DNS: client.example.com") || !strings.Contains(decodedContent, "DNS: www.client.example.com") {
			t.Errorf("Decoded content missing DNS SANs: %s", decodedContent)
		}
		if !strings.Contains(decodedContent, "IP: 192.168.1.100") || !strings.Contains(decodedContent, "IP: 10.0.0.5") {
			t.Errorf("Decoded content missing IP SANs: %s", decodedContent)
		}
	})

	t.Run("view homelab certificate manager certificate", func(t *testing.T) {
		// Create a dummy homelab certificate
		homelabCert := &x509.Certificate{
			SerialNumber: big.NewInt(200),
			Subject: pkix.Name{
				CommonName: "homelab_certificate_manager",
			},
			NotBefore: time.Now().Add(-2 * time.Hour),
			NotAfter:  time.Now().Add(48 * time.Hour),
		}
		homelabPrivKey, _ := rsa.GenerateKey(rand.Reader, 2048)
		homelabCertBytes, _ := x509.CreateCertificate(rand.Reader, homelabCert, rootCert, &homelabPrivKey.PublicKey, rootPrivKey)
		ioutil.WriteFile(filepath.Join("data", "certmanager-cert", "homelab_certificate_manager.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: homelabCertBytes}), 0644)

		req, _ := http.NewRequest(http.MethodGet, "/view/homelab_certificate_manager.pem", nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status %d, got %d. Response: %s", http.StatusOK, w.Code, w.Body.String())
		}

		var response map[string]string
		err = json.Unmarshal(w.Body.Bytes(), &response)
		if err != nil {
			t.Fatalf("Failed to unmarshal response: %v", err)
		}

		decodedContent := response["decoded"]
		if !strings.Contains(decodedContent, "Subject: CN=homelab_certificate_manager") {
			t.Errorf("Decoded content missing subject info: %s", decodedContent)
		}
	})

	t.Run("certificate not found", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, "/view/non_existent.pem", nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		if w.Code != http.StatusNotFound {
			t.Errorf("Expected status %d, got %d", http.StatusNotFound, w.Code)
		}
		if w.Body.String() != "File not found" {
			t.Errorf("Expected content 'File not found', got '%s'", w.Body.String())
		}
	})

	t.Run("invalid certificate content", func(t *testing.T) {
		ioutil.WriteFile(filepath.Join("data", "certs", "invalid.pem"), []byte("not a cert"), 0644)

		req, _ := http.NewRequest(http.MethodGet, "/view/invalid.pem", nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		if w.Code != http.StatusInternalServerError {
			t.Errorf("Expected status %d, got %d", http.StatusInternalServerError, w.Code)
		}
		if !strings.Contains(w.Body.String(), "failed to parse certificate PEM") {
			t.Errorf("Expected error about parsing PEM, got %s", w.Body.String())
		}
	})
}

func TestRecreateHomelabCertificate(t *testing.T) {
	// Set up a temporary directory for test data
	tempDir, err := os.MkdirTemp("", "test_recreate_homelab_cert")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Backup original working directory and change to tempDir
	originalDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get current working directory: %v", err)
	}
	err = os.Chdir(tempDir)
	if err != nil {
		t.Fatalf("Failed to change directory to tempDir: %v", err)
	}
	defer os.Chdir(originalDir)

	// Create necessary directories
	os.MkdirAll(filepath.Join("data", "root-cert"), 0755)
	os.MkdirAll(filepath.Join("data", "certmanager-cert"), 0755)

	// Mock viper settings
	viper.Set("certificate_manager_certificate.dns_names", []string{"homelab.example.com", "manager.example.com"})
	viper.Set("certificate_manager_certificate.ip_addresses", []string{"192.168.1.1", "10.0.0.1"})
	viper.Set("general_cert_options.organization", "Homelab Inc.")
	viper.Set("general_cert_options.organization_unit", "IT")
	viper.Set("general_cert_options.country", "DE")
	viper.Set("general_cert_options.state", "Berlin")
	viper.Set("general_cert_options.location", "Berlin")

	// Set Gin to TestMode
	gin.SetMode(gin.TestMode)

	// Create a Gin engine and register the handler
	r := gin.New()
	r.GET("/recreate", recreateHomelabCertificate)

	t.Run("successful recreation", func(t *testing.T) {
		// Create dummy root certificate and key
		rootCert := &x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject: pkix.Name{
				CommonName: "HomeLab Root CA",
			},
			NotBefore: time.Now(),
			NotAfter:  time.Now().AddDate(10, 0, 0),
			IsCA:      true,
			KeyUsage:  x509.KeyUsageCertSign,
		}
		rootPrivKey, _ := rsa.GenerateKey(rand.Reader, 2048)
		rootCertBytes, _ := x509.CreateCertificate(rand.Reader, rootCert, rootCert, &rootPrivKey.PublicKey, rootPrivKey)
		ioutil.WriteFile(filepath.Join("data", "root-cert", "HomeLab_Root_CA.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootCertBytes}), 0644)
		ioutil.WriteFile(filepath.Join("data", "root-cert", "HomeLab_Root_CA.key"), pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rootPrivKey)}), 0644)

		req, _ := http.NewRequest(http.MethodGet, "/recreate", nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status %d, got %d. Response: %s", http.StatusOK, w.Code, w.Body.String())
		}

		var response map[string]string
		err = json.Unmarshal(w.Body.Bytes(), &response)
		if err != nil {
			t.Fatalf("Failed to unmarshal response: %v", err)
		}

		if response["message"] != "Certificate recreated successfully" {
			t.Errorf("Expected success message, got %s", response["message"])
		}

		// Verify files are created
		certPath := filepath.Join("data", "certmanager-cert", "homelab_certificate_manager.pem")
		keyPath := filepath.Join("data", "certmanager-cert", "homelab_certificate_manager.key")

		if _, err := os.Stat(certPath); os.IsNotExist(err) {
			t.Error("Homelab certificate file not created")
		}
		if _, err := os.Stat(keyPath); os.IsNotExist(err) {
			t.Error("Homelab key file not created")
		}

		// Verify certificate content (SANs)
		cert, err := readCertificate(certPath)
		if err != nil {
			t.Fatalf("Failed to read recreated homelab certificate: %v", err)
		}
		expectedDNS := []string{"homelab.example.com", "manager.example.com"}
		if !reflect.DeepEqual(cert.DNSNames, expectedDNS) {
			t.Errorf("Expected DNSNames %v, got %v", expectedDNS, cert.DNSNames)
		}
		expectedIPs := []net.IP{net.ParseIP("192.168.1.1"), net.ParseIP("10.0.0.1")}
		if !reflect.DeepEqual(cert.IPAddresses, expectedIPs) {
			t.Errorf("Expected IPAddresses %v, got %v", expectedIPs, cert.IPAddresses)
		}
	})

	t.Run("root certificate not found", func(t *testing.T) {
		// Ensure no root cert/key exists
		os.RemoveAll(filepath.Join("data", "root-cert"))
		os.MkdirAll(filepath.Join("data", "root-cert"), 0755)

		req, _ := http.NewRequest(http.MethodGet, "/recreate", nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("Expected status %d, got %d", http.StatusBadRequest, w.Code)
		}

		var response map[string]string
		err = json.Unmarshal(w.Body.Bytes(), &response)
		if err != nil {
			t.Fatalf("Failed to unmarshal response: %v", err)
		}

		if response["error"] != "Root certificate not found" {
			t.Errorf("Expected error message 'Root certificate not found', got %s", response["error"])
		}
	})
}