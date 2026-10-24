package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"html/template"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/sessions"
	"github.com/spf13/viper"
	"golang.org/x/crypto/bcrypt"
)

type Config struct {
	Password           string `json:"password" mapstructure:"password"`
	SessionKey         string `json:"session_key" mapstructure:"session_key"`
	CSRFKey            string `json:"csrf_key" mapstructure:"csrf_key"`
	MustChangePassword bool   `json:"must_change_password" mapstructure:"must_change_password"`
}

// create variable for session handling (login/logout)
var store *sessions.CookieStore

// loginLimiter protects the login endpoint against brute-force attacks (5 failed attempts, 5-minute lockout)
var loginLimiter = NewLoginRateLimiter(5, 5*time.Minute)

// maxBodySizeMiddleware limits incoming request body size to prevent memory exhaustion and DoS attacks.
func maxBodySizeMiddleware(maxBytes int64) gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.Body != nil {
			c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxBytes)
		}
		c.Next()
	}
}

// toJson converts a Go data structure to a JSON string
func toJson(v interface{}) (string, error) {
	bytes, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

func main() {
	if err := Run(); err != nil {
		log.Fatalf("Application error: %v", err)
	}
}

func Run() error {
	os.MkdirAll("data/certs", 0750)
	os.MkdirAll("data/root-cert", 0700)
	os.MkdirAll("data/certmanager-cert", 0750)
	os.MkdirAll("data", 0750)

	// Initialize settings
	if conf_error := initSettings(); conf_error != nil {
		return fmt.Errorf("failed to initialize settings: %w", conf_error)
	}

	// Load configuration
	config, conf_error := loadConfig()
	if conf_error != nil {
		return fmt.Errorf("error loading configuration: %w", conf_error)
	}

	// Initialize logging defaults
	initLoggingDefaults()

	// Initialize CSRF key
	initCSRFKey(config.CSRFKey)

	// First check if any .pem file exists in the certmanager-cert directory
	certManagerCertExists := false
	err := filepath.Walk("data/certmanager-cert", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && filepath.Ext(info.Name()) == ".pem" {
			certManagerCertExists = true
			return filepath.SkipDir
		}
		return nil
	})

	if err != nil {
		log.Printf("Error checking certmanager-cert directory: %v", err)
	} else if certManagerCertExists {
		debugLog("Certificate Manager certificate already exists")
	} else {
		debugLog("Certificate Manager certificate not found")
		// Generate self-signed certificate for Certificate Manager
		certKey, err := rsa.GenerateKey(rand.Reader, 4096)
		if err != nil {
			return fmt.Errorf("failed to generate private key: %w", err)
		}

		serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
		if err != nil {
			return fmt.Errorf("failed to generate serial number: %w", err)
		}

		template := x509.Certificate{
			SerialNumber: serialNumber,
			Subject: pkix.Name{
				CommonName: "HomeLab Certificate Manager",
			},
			NotBefore: time.Now(),
			NotAfter:  time.Now().AddDate(10, 0, 0), // Valid for 10 years
			KeyUsage:  x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
			ExtKeyUsage: []x509.ExtKeyUsage{
				x509.ExtKeyUsageServerAuth,
			},
			BasicConstraintsValid: true,
		}

		certBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &certKey.PublicKey, certKey)
		if err != nil {
			return fmt.Errorf("failed to create certificate: %w", err)
		}

		// Save private key with restricted permissions
		keyFile, err := createFileWithPermissions("data/certmanager-cert/selfsigned.key", 0600)
		if err != nil {
			return fmt.Errorf("failed to create key file: %w", err)
		}
		defer keyFile.Close()

		err = pem.Encode(keyFile, &pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(certKey),
		})
		if err != nil {
			return fmt.Errorf("failed to write key file: %w", err)
		}

		// Save certificate with standard read permissions
		certFile, err := createFileWithPermissions("data/certmanager-cert/selfsigned.pem", 0644)
		if err != nil {
			return fmt.Errorf("failed to create certificate file: %w", err)
		}
		defer certFile.Close()

		err = pem.Encode(certFile, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: certBytes,
		})
		if err != nil {
			return fmt.Errorf("failed to write certificate file: %w", err)
		}

		log.Println("Certificate Manager certificate generated successfully")

	}

	rootCertExists := false
	err = filepath.Walk("data/root-cert", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && filepath.Ext(info.Name()) == ".pem" {
			rootCertExists = true
			return filepath.SkipDir
		}
		return nil
	})
	if err != nil {
		log.Printf("Error checking root-cert directory: %v", err)
	} else if rootCertExists {
		debugLog("Root certificate exists")
	} else {
		debugLog("Root certificate not found")
	}

	r := gin.Default()

	// Add security headers middleware
	r.Use(securityHeadersMiddleware())

	// Limit request body size to 5MB to prevent memory exhaustion / DoS
	r.Use(maxBodySizeMiddleware(5 * 1024 * 1024))

	r.Static("/static", "./static") // Konfiguration, um statische Dateien zu bedienen

	// Add CSRF middleware
	r.Use(csrfMiddleware())

	// Add the toJson function to the template's function map
	r.SetFuncMap(template.FuncMap{
		"toJson": toJson,
	})

	// Load templates with the function map
	r.LoadHTMLGlob("templates/*")

	r.GET("/login", showLoginPage)
	r.POST("/login", loginLimiter.Middleware(), func(c *gin.Context) {
		handleLogin(c, config)
	})
	r.GET("/logout", handleLogout)

	// OIDC authentication routes
	r.GET("/auth/oidc/login", handleOIDCLogin)
	r.GET("/auth/oidc/callback", handleOIDCCallback)

	authorized := r.Group("/")
	authorized.Use(AuthRequired)
	authorized.Use(CheckPasswordChange(config))
	{
		authorized.GET("/", showHomePage)
		authorized.GET("/certificates", checkRootCertAndListCerts) // Ensure this route calls the correct function
		authorized.GET("/certificates/view/:filename", viewCertificate)
		authorized.POST("/certificates/delete/:filename", deleteCertificate)
		authorized.GET("/certificates/download/:filename", func(c *gin.Context) {
			c.Params = append(c.Params, gin.Param{Key: "certType", Value: "certs"})
			downloadCertificate(c)
		})
		authorized.POST("/create-root-certificate", createRootCertificate)
		authorized.GET("/certificates/download/root-cert/:filename", func(c *gin.Context) {
			c.Params = append(c.Params, gin.Param{Key: "certType", Value: "root-cert"})
			downloadCertificate(c)
		})
		authorized.GET("/certificates/download/certmanager-cert/:filename", func(c *gin.Context) {
			c.Params = append(c.Params, gin.Param{Key: "certType", Value: "certmanager-cert"})
			downloadCertificate(c)
		})
		authorized.GET("/create-certificate-form", showCreateCertificateForm) // Route for certificate form
		authorized.POST("/create-certificate", createCertificate)
		authorized.POST("/sign-csr", handleSignCSR)

		authorized.POST("/certificates/delete/root-cert/:filename", deleteRootCertificate) // Route for deleting root certificate
		authorized.GET("/settings", showSettingsPage)                                      // Route for settings page
		// r.POST("/settings", handleSettings)                                       // Route for saving settings
		authorized.POST("/recreate-homelab-cert", recreateHomelabCertificate)

		authorized.GET("/settings/certmanager", handleCertManagerSettings)
		authorized.POST("/settings/certmanager", handleCertManagerSettings)

		authorized.GET("/settings/generalcertoptions", handleGeneralCertOptions)
		authorized.POST("/settings/generalcertoptions", handleGeneralCertOptions)

		authorized.GET("/settings/session", handleSessionSettings)
		authorized.POST("/settings/session", handleSessionSettings)
		authorized.GET("/api/session/status", handleSessionStatus)
		authorized.POST("/api/session/ping", handleSessionPing)

		authorized.GET("/settings/oidc", handleOIDCSettings)
		authorized.POST("/settings/oidc", handleOIDCSettings)

		authorized.POST("/change-password", func(c *gin.Context) {
			changePassword(c, config)
		})

		authorized.GET("/change-password", func(c *gin.Context) {
			isDefaultPassword := checkPasswordHash("admin", viper.GetString("password"))
			c.HTML(http.StatusOK, "change_password.html", gin.H{
				"MustChangePassword": config.MustChangePassword,
				"defaultPassword":    isDefaultPassword,
				"csrfToken":          getCSRFToken(c.Request),
			})
		})
	}
	// Determine which certificate to use
	selfSignedCert := filepath.Join("data", "certmanager-cert", "selfsigned.pem")
	selfSignedKey := filepath.Join("data", "certmanager-cert", "selfsigned.key")
	homelabCert := filepath.Join("data", "certmanager-cert", "homelab_certificate_manager.pem")
	homelabKey := filepath.Join("data", "certmanager-cert", "homelab_certificate_manager.key")

	var certFile, keyFile string

	if _, err := os.Stat(homelabCert); err == nil {
		certFile = homelabCert
		keyFile = homelabKey

		// Remove self-signed certificate and key if homelab certificate exists
		if err := os.Remove(selfSignedCert); err != nil && !os.IsNotExist(err) {
			log.Printf("Warning: Failed to remove self-signed certificate: %v", err)
		}
		if err := os.Remove(selfSignedKey); err != nil && !os.IsNotExist(err) {
			log.Printf("Warning: Failed to remove self-signed key: %v", err)
		}
	} else if _, err := os.Stat(selfSignedCert); err == nil {
		certFile = selfSignedCert
		keyFile = selfSignedKey
	} else {
		return fmt.Errorf("no valid certificate found: please generate either selfsigned.pem or homelab_certificate_manager.pem")
	}

	// Start the server with hardened TLS configuration and timeouts (Slowloris protection)
	srv := &http.Server{
		Addr:              ":8443",
		Handler:           r,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}

	log.Printf("Starting secure server on https://localhost:8443 (TLS 1.2+)")
	if err := srv.ListenAndServeTLS(certFile, keyFile); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("server failed to start: %w", err)
	}
	return nil
}

func showHomePage(c *gin.Context) {
	// Check if any .pem file exists in the root-cert directory
	rootCertExists := false
	err := filepath.Walk("data/root-cert", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && filepath.Ext(info.Name()) == ".pem" {
			rootCertExists = true
			return filepath.SkipDir
		}
		return nil
	})
	if err != nil {
		c.String(http.StatusInternalServerError, "Error checking root-cert directory: %v", err)
		return
	}

	if rootCertExists {
		c.Redirect(http.StatusSeeOther, "/certificates")
		return
	}

	renderTemplate(c, "index.html", gin.H{
		"rootExists": rootCertExists,
		"csrfToken":  getCSRFToken(c.Request),
	})
}

func showCreateCertificateForm(c *gin.Context) {
	rootCertExists := false
	if _, err := os.Stat("data/root-cert/HomeLab_Root_CA.pem"); err == nil {
		rootCertExists = true
	}

	generalCertOptions := gin.H{
		"ValidityPeriod":   viper.GetString("general_cert_options.validity_period"),
		"Organization":     viper.GetString("general_cert_options.organization"),
		"OrganizationUnit": viper.GetString("general_cert_options.organization_unit"),
		"Country":          viper.GetString("general_cert_options.country"),
		"State":            viper.GetString("general_cert_options.state"),
		"Location":         viper.GetString("general_cert_options.location"),
		"Email":            viper.GetString("general_cert_options.email"),
	}
	renderTemplate(c, "create_certificate.html", gin.H{
		"rootCertExists":     rootCertExists,
		"generalCertOptions": generalCertOptions,
		"csrfToken":          getCSRFToken(c.Request),
	})
}

func handleSignCSR(c *gin.Context) {
	debugLog("handleSignCSR called")

	// Check if Root CA exists
	if _, err := os.Stat("data/root-cert/HomeLab_Root_CA.pem"); err != nil {
		isAjax := strings.Contains(c.GetHeader("Accept"), "application/json") || c.GetHeader("X-Requested-With") == "XMLHttpRequest"
		if isAjax {
			c.JSON(http.StatusBadRequest, gin.H{"error": "No Root CA certificate found. Please create a Root CA before signing CSRs."})
		} else {
			c.Redirect(http.StatusSeeOther, "/certificates?error="+url.QueryEscape("No Root CA certificate found. Please create a Root CA first."))
		}
		return
	}

	validityDays := 365
	validityYearsStr := c.PostForm("validity_years")
	validityDaysStr := c.PostForm("validity_days")
	if validityYearsStr != "" {
		if years, err := strconv.Atoi(validityYearsStr); err == nil && years > 0 && years <= 100 {
			validityDays = years * 365
		}
	} else if validityDaysStr != "" {
		if days, err := strconv.Atoi(validityDaysStr); err == nil && days > 0 && days <= 36500 {
			validityDays = days
		}
	} else {
		periodYears := viper.GetInt("general_cert_options.validity_period")
		if periodYears > 0 {
			validityDays = periodYears * 365
		}
	}

	var csrBytes []byte
	file, err := c.FormFile("csr_file")
	if err == nil && file != nil {
		f, err := file.Open()
		if err == nil {
			defer f.Close()
			csrBytes, _ = io.ReadAll(f)
		}
	}

	if len(bytes.TrimSpace(csrBytes)) == 0 {
		csrText := c.PostForm("csr_text")
		csrBytes = []byte(strings.TrimSpace(csrText))
	}

	isAjax := strings.Contains(c.GetHeader("Accept"), "application/json") || c.GetHeader("X-Requested-With") == "XMLHttpRequest"

	if len(csrBytes) == 0 {
		if isAjax {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Please provide a CSR via file upload or by pasting the PEM content."})
		} else {
			c.Redirect(http.StatusSeeOther, "/certificates?error="+url.QueryEscape("Please provide a CSR via file upload or paste"))
		}
		return
	}

	if err := SignCSR(csrBytes, validityDays); err != nil {
		log.Printf("Error signing CSR: %v", err)
		if isAjax {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		} else {
			c.Redirect(http.StatusSeeOther, "/certificates?error="+url.QueryEscape(err.Error()))
		}
		return
	}

	if isAjax {
		c.JSON(http.StatusOK, gin.H{"message": "CSR signed successfully", "redirect": "/certificates"})
	} else {
		c.Redirect(http.StatusSeeOther, "/certificates?signed=1")
	}
}

func showSettingsPage(c *gin.Context) {
	isDefaultPassword := checkPasswordHash("admin", viper.GetString("password"))
	oidcCfg := getOidcSettings()
	oidcCfg.ClientSecret = maskClientSecret(oidcCfg.ClientSecret)

	c.HTML(http.StatusOK, "settings.html", gin.H{
		"certManagerSettings": gin.H{
			"DnsNames":    viper.GetStringSlice("certificate_manager_certificate.dns_names"),
			"IpAddresses": viper.GetStringSlice("certificate_manager_certificate.ip_addresses"),
		},
		"generalCertOptions": gin.H{
			"ValidityPeriod":   viper.GetString("general_cert_options.validity_period"),
			"Organization":     viper.GetString("general_cert_options.organization"),
			"OrganizationUnit": viper.GetString("general_cert_options.organization_unit"),
			"Country":          viper.GetString("general_cert_options.country"),
			"State":            viper.GetString("general_cert_options.state"),
			"Location":         viper.GetString("general_cert_options.location"),
			"Email":            viper.GetString("general_cert_options.email"),
		},
		"sessionTimeoutMinutes": getSessionTimeoutMinutes(),
		"oidcSettings":          oidcCfg,
		"defaultPassword":       isDefaultPassword,
		"csrfToken":             getCSRFToken(c.Request),
	})
}

func loadRootCertAndKey() (*x509.Certificate, *rsa.PrivateKey, error) {
	// Read root certificate
	certPEM, err := os.ReadFile("data/root-cert/HomeLab_Root_CA.pem")
	if err != nil {
		return nil, nil, err
	}
	block, _ := pem.Decode(certPEM)
	rootCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, err
	}

	// Read root private key
	keyPEM, err := os.ReadFile("data/root-cert/HomeLab_Root_CA.key")
	if err != nil {
		return nil, nil, err
	}
	block, _ = pem.Decode(keyPEM)
	rootKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, nil, err
	}

	return rootCert, rootKey, nil
}

func handleCertManagerSettings(c *gin.Context) {
	debugLog("handleCertManagerSettings called")

	if c.Request.Method == "GET" {
		c.JSON(http.StatusOK, gin.H{
			"dns_names":    viper.GetStringSlice("certificate_manager_certificate.dns_names"),
			"ip_addresses": viper.GetStringSlice("certificate_manager_certificate.ip_addresses"),
		})
		return
	}

	var certSettings struct {
		DnsNames    []string `json:"dns_names"`
		IpAddresses []string `json:"ip_addresses"`
	}
	if err := c.BindJSON(&certSettings); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	for _, dns := range certSettings.DnsNames {
		if err := validateDNSName(dns); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
	}

	for _, ip := range certSettings.IpAddresses {
		if _, err := validateIPAddress(ip); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
	}

	if err := saveCertManagerSettings(certSettings.DnsNames, certSettings.IpAddresses); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, certSettings)
}

func handleGeneralCertOptions(c *gin.Context) {
	debugLog("handleGeneralCertOptions called")

	if c.Request.Method == "GET" {
		c.JSON(http.StatusOK, gin.H{
			"validity_period":   viper.GetString("general_cert_options.validity_period"),
			"organization":      viper.GetString("general_cert_options.organization"),
			"organization_unit": viper.GetString("general_cert_options.organization_unit"),
			"country":           viper.GetString("general_cert_options.country"),
			"state":             viper.GetString("general_cert_options.state"),
			"location":          viper.GetString("general_cert_options.location"),
			"email":             viper.GetString("general_cert_options.email"),
		})
		return
	}

	var generalCertOptions struct {
		ValidityPeriod   string `json:"validity_period"`
		Organization     string `json:"organization"`
		OrganizationUnit string `json:"organization_unit"`
		Country          string `json:"country"`
		State            string `json:"state"`
		Location         string `json:"location"`
		Email            string `json:"email"`
	}

	if err := c.BindJSON(&generalCertOptions); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if _, err := validateValidityYears(generalCertOptions.ValidityPeriod, 1, 100); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := validateEmail(generalCertOptions.Email); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := validateCountry(generalCertOptions.Country); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := saveGeneralCertOptions(
		generalCertOptions.ValidityPeriod,
		generalCertOptions.Organization,
		generalCertOptions.OrganizationUnit,
		generalCertOptions.Country,
		generalCertOptions.State,
		generalCertOptions.Location,
		generalCertOptions.Email,
	); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, generalCertOptions)
}

func handleSessionSettings(c *gin.Context) {
	debugLog("handleSessionSettings called")

	if c.Request.Method == "GET" {
		c.JSON(http.StatusOK, gin.H{
			"timeout_minutes": getSessionTimeoutMinutes(),
		})
		return
	}

	var req struct {
		TimeoutMinutes int `json:"timeout_minutes"`
	}
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := saveSessionSettings(req.TimeoutMinutes); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"timeout_minutes": req.TimeoutMinutes,
	})
}

func handleSessionStatus(c *gin.Context) {
	session, err := store.Get(c.Request, "session")
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_session"})
		return
	}

	timeoutMinutes := getSessionTimeoutMinutes()
	var lastActivity int64
	switch v := session.Values["last_activity"].(type) {
	case int64:
		lastActivity = v
	case int:
		lastActivity = int64(v)
	case float64:
		lastActivity = int64(v)
	default:
		lastActivity = time.Now().Unix()
	}

	elapsed := int(time.Since(time.Unix(lastActivity, 0)).Seconds())
	totalSeconds := timeoutMinutes * 60
	remainingSeconds := totalSeconds - elapsed
	if remainingSeconds < 0 {
		remainingSeconds = 0
	}

	c.JSON(http.StatusOK, gin.H{
		"timeout_minutes":   timeoutMinutes,
		"total_seconds":     totalSeconds,
		"remaining_seconds": remainingSeconds,
	})
}

func handleSessionPing(c *gin.Context) {
	session, err := store.Get(c.Request, "session")
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_session"})
		return
	}

	timeoutMinutes := getSessionTimeoutMinutes()
	session.Values["last_activity"] = time.Now().Unix()
	if err := session.Save(c.Request, c.Writer); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed_to_save_session"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status":            "ok",
		"timeout_minutes":   timeoutMinutes,
		"remaining_seconds": timeoutMinutes * 60,
	})
}

func renderTemplate(c *gin.Context, templateName string, data gin.H) {
	if data == nil {
		data = gin.H{}
	}
	c.HTML(http.StatusOK, templateName, data)
}

func showLoginPage(c *gin.Context) {
	var errorMsg string
	if c.Query("timeout") == "1" {
		errorMsg = "Your session expired due to inactivity. Please log in again."
	} else if c.Query("csrf_error") == "1" {
		errorMsg = "Your security token expired. Please log in again."
	} else if qErr := c.Query("error"); qErr != "" {
		errorMsg = qErr
	}
	c.HTML(http.StatusOK, "login.html", gin.H{
		"error":       errorMsg,
		"oidcEnabled": isOidcEnabled(),
		"csrfToken":   getCSRFToken(c.Request),
	})
}

func handleLogin(c *gin.Context, config *Config) {
	username := c.PostForm("username")
	if username == "" {
		username = "admin"
	}
	password := c.PostForm("password")

	// Check if the stored password is a bcrypt hash
	isBcrypt := strings.HasPrefix(config.Password, "$2a$") || strings.HasPrefix(config.Password, "$2b$")

	passwordMatch := false
	if isBcrypt {
		// Compare with bcrypt hash
		passwordMatch = checkPasswordHash(password, config.Password)
	} else {
		// Compare with old SHA-512 hash (for migration)
		hash := sha512.New()
		hash.Write([]byte(password))
		passwordMatch = hex.EncodeToString(hash.Sum(nil)) == config.Password
	}

	if username == "admin" && passwordMatch {
		// If using the old hash, migrate to bcrypt
		if !isBcrypt {
			newHash, err := hashPassword(password)
			if err == nil {
				config.Password = newHash
				saveConfig(config)
			}
		}

		session, err := store.Get(c.Request, "session")
		if err != nil {
			// An error here usually indicates an invalid, expired, or rotated cookie from an older session.
			// Since the user is authenticating with valid credentials, we replace the invalid session.
			log.Printf("Notice: replacing invalid/expired session cookie during login: %v", err)
		}
		if session == nil {
			session = sessions.NewSession(store, "session")
			session.Options = store.Options
		}

		session.Values["authenticated"] = true
		session.Values["last_activity"] = time.Now().Unix()
		if err := session.Save(c.Request, c.Writer); err != nil {
			log.Printf("Failed to save session: %v", err)
			c.HTML(http.StatusInternalServerError, "login.html", gin.H{
				"error":     "Session error",
				"csrfToken": getCSRFToken(c.Request),
			})
			return
		}
		loginLimiter.Reset(c.ClientIP())
		c.Redirect(http.StatusSeeOther, "/certificates")
	} else {
		loginLimiter.RecordFailure(c.ClientIP())
		c.HTML(http.StatusUnauthorized, "login.html", gin.H{
			"error":     "Invalid credentials",
			"csrfToken": getCSRFToken(c.Request),
		})
	}
}

func handleLogout(c *gin.Context) {
	session, err := store.Get(c.Request, "session")
	if session != nil {
		if err != nil {
			log.Printf("Notice: session error during logout: %v", err)
		}
		session.Values["authenticated"] = false
		session.Values["last_activity"] = int64(0)
		session.Options.MaxAge = -1 // expire cookie
		if err := session.Save(c.Request, c.Writer); err != nil {
			log.Printf("Failed to save session during logout: %v", err)
		}
	}
	c.Redirect(http.StatusSeeOther, "/login")
}

func AuthRequired(c *gin.Context) {
	session, err := store.Get(c.Request, "session")
	if err != nil {
		log.Printf("Session error in AuthRequired: %v", err)
		c.Redirect(http.StatusSeeOther, "/login")
		c.Abort()
		return
	}

	if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
		if c.GetHeader("X-Requested-With") == "XMLHttpRequest" || strings.HasPrefix(c.Request.URL.Path, "/api/") || strings.Contains(c.GetHeader("Accept"), "application/json") {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		} else {
			c.Redirect(http.StatusSeeOther, "/login")
		}
		c.Abort()
		return
	}

	// Inactivity session timeout check
	var lastActivity int64
	switch v := session.Values["last_activity"].(type) {
	case int64:
		lastActivity = v
	case int:
		lastActivity = int64(v)
	case float64:
		lastActivity = int64(v)
	default:
		lastActivity = 0
	}

	timeoutMinutes := getSessionTimeoutMinutes()
	timeoutDuration := time.Duration(timeoutMinutes) * time.Minute

	if lastActivity == 0 {
		lastActivity = time.Now().Unix()
		session.Values["last_activity"] = lastActivity
		_ = session.Save(c.Request, c.Writer)
	} else if time.Since(time.Unix(lastActivity, 0)) > timeoutDuration {
		log.Printf("Session timed out after %v of inactivity", time.Since(time.Unix(lastActivity, 0)))
		session.Values["authenticated"] = false
		session.Values["last_activity"] = int64(0)
		session.Options.MaxAge = -1
		_ = session.Save(c.Request, c.Writer)

		if c.GetHeader("X-Requested-With") == "XMLHttpRequest" || strings.HasPrefix(c.Request.URL.Path, "/api/") || strings.Contains(c.GetHeader("Accept"), "application/json") {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "session_expired", "message": "Session expired due to inactivity"})
		} else {
			c.Redirect(http.StatusSeeOther, "/login?timeout=1")
		}
		c.Abort()
		return
	}

	// Update last_activity on user interactions (do not refresh on passive status polling)
	if c.Request.URL.Path != "/api/session/status" {
		session.Values["last_activity"] = time.Now().Unix()
		_ = session.Save(c.Request, c.Writer)
	}

	c.Next()
}

func CheckPasswordChange(config *Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		session, _ := store.Get(c.Request, "session")
		if session != nil && session.Values["auth_provider"] == "oidc" {
			c.Next()
			return
		}
		if config.MustChangePassword {
			if c.Request.URL.Path != "/change-password" {
				c.Redirect(http.StatusSeeOther, "/change-password")
				c.Abort()
				return
			}
		}
		c.Next()
	}
}

func loadConfig() (*Config, error) {
	viper.SetConfigName("settings")
	viper.SetConfigType("json")
	viper.AddConfigPath("data")

	var config Config
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			// Config file not found; create a new one
			hashedPassword, err := hashPassword("admin")
			if err != nil {
				return nil, err
			}
			config.Password = hashedPassword
			config.MustChangePassword = true
			// Generate a new session key
			key := make([]byte, 64)
			if _, err := rand.Read(key); err != nil {
				return nil, err
			}
			config.SessionKey = hex.EncodeToString(key)

			// Generate a persistent CSRF key
			csrfBytes := make([]byte, 32)
			if _, err := rand.Read(csrfBytes); err != nil {
				return nil, err
			}
			config.CSRFKey = hex.EncodeToString(csrfBytes)

			if saveErr := saveConfig(&config); saveErr != nil {
				return nil, saveErr
			}
		} else {
			// Some other error occurred
			return nil, err
		}
	} else {
		if err := viper.Unmarshal(&config); err != nil {
			return nil, err
		}
	}

	// Ensure password and session key exist, create them if they don't
	madeChanges := false
	if config.Password == "" {
		hashedPassword, err := hashPassword("admin")
		if err != nil {
			return nil, err
		}
		config.Password = hashedPassword
		config.MustChangePassword = true
		madeChanges = true
	}
	// Ensure persistent CSRF key exists
	if config.CSRFKey == "" {
		csrfBytes := make([]byte, 32)
		if _, err := rand.Read(csrfBytes); err != nil {
			return nil, err
		}
		config.CSRFKey = hex.EncodeToString(csrfBytes)
		madeChanges = true
	}

	// Invalidate previous session keys on service restart by generating a fresh random key
	key := make([]byte, 64)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	config.SessionKey = hex.EncodeToString(key)
	madeChanges = true

	if madeChanges {
		if err := saveConfig(&config); err != nil {
			return nil, err
		}
	}
	// Initialize the session store with the key from the config and secure cookie options
	store = sessions.NewCookieStore([]byte(config.SessionKey))
	sessionSecure := !viper.GetBool("debug")
	if viper.IsSet("session_secure") {
		sessionSecure = viper.GetBool("session_secure")
	}
	store.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   86400 * 7, // 7 days
		HttpOnly: true,
		Secure:   sessionSecure,
		SameSite: http.SameSiteLaxMode,
	}

	return &config, nil
}

func saveConfig(config *Config) error {
	viper.Set("password", config.Password)
	viper.Set("session_key", config.SessionKey)
	viper.Set("csrf_key", config.CSRFKey)
	viper.Set("must_change_password", config.MustChangePassword)
	return saveViperConfig()
}

func changePassword(c *gin.Context, config *Config) {
	var req struct {
		OldPassword string `json:"old_password"`
		NewPassword string `json:"new_password"`
	}

	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "Invalid request"})
		return
	}

	// Check the old password
	isBcrypt := strings.HasPrefix(config.Password, "$2a$") || strings.HasPrefix(config.Password, "$2b$")
	passwordMatch := false
	if isBcrypt {
		passwordMatch = checkPasswordHash(req.OldPassword, config.Password)
	} else {
		hash := sha512.New()
		hash.Write([]byte(req.OldPassword))
		passwordMatch = hex.EncodeToString(hash.Sum(nil)) == config.Password
	}
	if !passwordMatch {
		c.JSON(http.StatusUnauthorized, gin.H{"success": false, "message": "Old password is incorrect"})
		return
	}

	// Validate the new password against password security policy
	if err := validatePassword(req.NewPassword, req.OldPassword); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": err.Error()})
		return
	}

	// Hash the new password before saving it
	newHashedPassword, err := hashPassword(req.NewPassword)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": "Failed to hash new password"})
		return
	}
	config.Password = newHashedPassword
	config.MustChangePassword = false
	if err := saveConfig(config); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": "Failed to save new password"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "message": "Password changed successfully"})
}

func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

func checkPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}
