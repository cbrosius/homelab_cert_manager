package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/sessions"
	"github.com/spf13/viper"
)

func setupTestOidcRouter() *gin.Engine {
	if store == nil {
		store = sessions.NewCookieStore([]byte("0123456789012345678901234567890123456789012345678901234567890123"))
	}
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(gin.Recovery())

	r.GET("/login", showLoginPage)
	r.GET("/auth/oidc/login", handleOIDCLogin)
	r.GET("/auth/oidc/callback", handleOIDCCallback)

	authorized := r.Group("/")
	authorized.GET("/settings/oidc", handleOIDCSettings)
	authorized.POST("/settings/oidc", handleOIDCSettings)

	return r
}

func TestOidcSettings_GettersAndEnvOverrides(t *testing.T) {
	// Clean environment
	os.Unsetenv("OIDC_ENABLED")
	os.Unsetenv("OIDC_ISSUER_URL")
	os.Unsetenv("OIDC_CLIENT_ID")
	os.Unsetenv("OIDC_CLIENT_SECRET")
	os.Unsetenv("OIDC_REDIRECT_URL")

	viper.Set("oidc_settings.enabled", false)
	viper.Set("oidc_settings.issuer_url", "")
	viper.Set("oidc_settings.client_id", "")
	viper.Set("oidc_settings.client_secret", "")
	viper.Set("oidc_settings.redirect_url", "")

	if isOidcEnabled() {
		t.Fatal("Expected isOidcEnabled to be false by default")
	}

	// Test settings via viper
	viper.Set("oidc_settings.enabled", true)
	viper.Set("oidc_settings.issuer_url", "https://id.example.local")
	viper.Set("oidc_settings.client_id", "my-app")
	if !isOidcEnabled() {
		t.Fatal("Expected isOidcEnabled to be true when enabled, issuer and client_id are set")
	}

	// Test environment variable overrides
	t.Setenv("OIDC_ENABLED", "false")
	if isOidcEnabled() {
		t.Fatal("Expected OIDC_ENABLED=false to override viper setting")
	}

	t.Setenv("OIDC_ENABLED", "true")
	t.Setenv("OIDC_ISSUER_URL", "https://env-id.example.local")
	t.Setenv("OIDC_CLIENT_ID", "env-client-id")
	t.Setenv("OIDC_CLIENT_SECRET", "env-secret")
	t.Setenv("OIDC_REDIRECT_URL", "https://env-app.local/callback")

	cfg := getOidcSettings()
	if !cfg.Enabled || cfg.IssuerURL != "https://env-id.example.local" || cfg.ClientID != "env-client-id" || cfg.ClientSecret != "env-secret" || cfg.RedirectURL != "https://env-app.local/callback" {
		t.Fatalf("Unexpected config from env overrides: %+v", cfg)
	}
}

func TestOidcSettings_SaveAndValidation(t *testing.T) {
	os.Unsetenv("OIDC_ENABLED")
	os.Unsetenv("OIDC_ISSUER_URL")
	os.Unsetenv("OIDC_CLIENT_ID")
	os.Unsetenv("OIDC_CLIENT_SECRET")
	os.Unsetenv("OIDC_REDIRECT_URL")

	r := setupTestOidcRouter()

	// 1. Invalid payload when enabling OIDC without issuer
	badReqBody, _ := json.Marshal(OidcConfig{
		Enabled:   true,
		IssuerURL: "",
		ClientID:  "test-id",
	})
	req, _ := http.NewRequest(http.MethodPost, "/settings/oidc", bytes.NewReader(badReqBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("Expected 400 Bad Request for missing issuer URL, got %d", w.Code)
	}

	// 2. Invalid payload with bad URL scheme
	badSchemeBody, _ := json.Marshal(OidcConfig{
		Enabled:   true,
		IssuerURL: "ftp://invalid-url.com",
		ClientID:  "test-id",
	})
	req, _ = http.NewRequest(http.MethodPost, "/settings/oidc", bytes.NewReader(badSchemeBody))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("Expected 400 Bad Request for invalid URL scheme, got %d", w.Code)
	}

	// 3. Valid payload save
	validBody, _ := json.Marshal(OidcConfig{
		Enabled:      true,
		IssuerURL:    "https://auth.homelab.local",
		ClientID:     "cert-manager",
		ClientSecret: "super-secret",
		RedirectURL:  "https://certmanager.homelab.local:8443/auth/oidc/callback",
	})
	req, _ = http.NewRequest(http.MethodPost, "/settings/oidc", bytes.NewReader(validBody))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK for valid OIDC settings, got %d: %s", w.Code, w.Body.String())
	}

	// 4. GET /settings/oidc
	req, _ = http.NewRequest(http.MethodGet, "/settings/oidc", nil)
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK for GET /settings/oidc, got %d", w.Code)
	}

	var savedCfg OidcConfig
	if err := json.Unmarshal(w.Body.Bytes(), &savedCfg); err != nil {
		t.Fatalf("Failed to parse GET /settings/oidc response: %v", err)
	}
	if !savedCfg.Enabled || savedCfg.IssuerURL != "https://auth.homelab.local" || savedCfg.ClientID != "cert-manager" {
		t.Fatalf("Mismatch in saved OIDC configuration: %+v", savedCfg)
	}
}

func TestOIDCHTTPClient_TrustPool(t *testing.T) {
	// Generate a temporary CA certificate and save in data/root-cert/
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate test key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(12345),
		Subject: pkix.Name{
			CommonName: "Test Temporary Homelab Root CA",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("Failed to create test cert: %v", err)
	}

	testDir := filepath.Join("data", "root-cert")
	_ = os.MkdirAll(testDir, 0755)
	testCertPath := filepath.Join(testDir, "test_custom_root.crt")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	if err := os.WriteFile(testCertPath, certPEM, 0644); err != nil {
		t.Fatalf("Failed to write temporary test CA cert: %v", err)
	}
	defer os.Remove(testCertPath)

	client := getOIDCHTTPClient()
	if client == nil {
		t.Fatal("Expected non-nil OIDC HTTP client")
	}
	if client.Timeout != 30*time.Second {
		t.Fatalf("Expected 30s timeout, got %v", client.Timeout)
	}

	transport, ok := client.Transport.(*http.Transport)
	if !ok || transport == nil {
		t.Fatal("Expected *http.Transport")
	}
	if transport.TLSClientConfig == nil || transport.TLSClientConfig.RootCAs == nil {
		t.Fatal("Expected non-nil RootCAs in TLSClientConfig")
	}
}

func TestOIDCLogin_DisabledRedirects(t *testing.T) {
	os.Unsetenv("OIDC_ENABLED")
	os.Unsetenv("OIDC_ISSUER_URL")
	viper.Set("oidc_settings.enabled", false)

	r := setupTestOidcRouter()

	req, _ := http.NewRequest(http.MethodGet, "/auth/oidc/login", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("Expected 303 redirect when OIDC is disabled, got %d", w.Code)
	}
	if !strings.Contains(w.Header().Get("Location"), "/login?error=") {
		t.Fatalf("Expected redirect to /login with error query param, got %s", w.Header().Get("Location"))
	}
}

func TestOIDCCallback_StateValidation(t *testing.T) {
	os.Unsetenv("OIDC_ENABLED")
	os.Unsetenv("OIDC_ISSUER_URL")
	viper.Set("oidc_settings.enabled", true)
	viper.Set("oidc_settings.issuer_url", "https://id.test.local")
	viper.Set("oidc_settings.client_id", "test-client")

	r := setupTestOidcRouter()

	// 1. Missing cookie state
	req, _ := http.NewRequest(http.MethodGet, "/auth/oidc/callback?state=expected_state&code=test_code", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("Expected 303 redirect, got %d", w.Code)
	}
	if !strings.Contains(w.Header().Get("Location"), "Invalid+or+expired") {
		t.Fatalf("Expected invalid state error, got %s", w.Header().Get("Location"))
	}

	// 2. Mismatched state
	req, _ = http.NewRequest(http.MethodGet, "/auth/oidc/callback?state=wrong_state&code=test_code", nil)
	req.AddCookie(&http.Cookie{
		Name:  "oidc_state",
		Value: "correct_state",
	})
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("Expected 303 redirect, got %d", w.Code)
	}
	if !strings.Contains(w.Header().Get("Location"), "Invalid+or+expired") {
		t.Fatalf("Expected invalid state error on mismatch, got %s", w.Header().Get("Location"))
	}

	// 3. Provider error passed in query
	req, _ = http.NewRequest(http.MethodGet, "/auth/oidc/callback?state=test_state&error=access_denied&error_description=User+cancelled", nil)
	req.AddCookie(&http.Cookie{
		Name:  "oidc_state",
		Value: "test_state",
	})
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("Expected 303 redirect, got %d", w.Code)
	}
	if !strings.Contains(w.Header().Get("Location"), "access_denied") {
		t.Fatalf("Expected provider error in redirect location, got %s", w.Header().Get("Location"))
	}

	// 4. Missing code
	req, _ = http.NewRequest(http.MethodGet, "/auth/oidc/callback?state=test_state", nil)
	req.AddCookie(&http.Cookie{
		Name:  "oidc_state",
		Value: "test_state",
	})
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("Expected 303 redirect, got %d", w.Code)
	}
	if !strings.Contains(w.Header().Get("Location"), "Missing+authorization+code") {
		t.Fatalf("Expected missing authorization code error, got %s", w.Header().Get("Location"))
	}
}

func TestCheckPasswordChange_OIDCProviderBypass(t *testing.T) {
	if store == nil {
		store = sessions.NewCookieStore([]byte("0123456789012345678901234567890123456789012345678901234567890123"))
	}
	config := &Config{
		MustChangePassword: true,
	}

	r := gin.New()
	r.Use(func(c *gin.Context) {
		session, _ := store.Get(c.Request, "session")
		session.Values["authenticated"] = true
		session.Values["auth_provider"] = "oidc"
		session.Values["last_activity"] = time.Now().Unix()
		_ = session.Save(c.Request, c.Writer)
		c.Next()
	})
	r.Use(CheckPasswordChange(config))
	r.GET("/protected-page", func(c *gin.Context) {
		c.String(http.StatusOK, "Welcome OIDC User")
	})

	req, _ := http.NewRequest(http.MethodGet, "/protected-page", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK for OIDC user bypassing MustChangePassword, got %d", w.Code)
	}
	if w.Body.String() != "Welcome OIDC User" {
		t.Fatalf("Expected body 'Welcome OIDC User', got %q", w.Body.String())
	}
}
