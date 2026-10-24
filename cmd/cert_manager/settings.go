package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"os"
	"strings"

	"github.com/spf13/viper"
)

type Settings struct {
	CertManagerCertificate struct {
		DnsNames    []string `mapstructure:"dns_names"`
		IpAddresses []string `mapstructure:"ip_addresses"`
	} `mapstructure:"certificate_manager_certificate"`

	GeneralCertOptions struct {
		ValidityPeriod   string `mapstructure:"validity_period"`
		Organization     string `mapstructure:"organization"`
		OrganizationUnit string `mapstructure:"organization_unit"`
		Country          string `mapstructure:"country"`
		State            string `mapstructure:"state"`
		Location         string `mapstructure:"location"`
		Email            string `mapstructure:"email"`
	} `mapstructure:"general_cert_options"`

	SessionSettings struct {
		TimeoutMinutes int `mapstructure:"timeout_minutes"`
	} `mapstructure:"session_settings"`

	OidcSettings struct {
		Enabled      bool   `mapstructure:"enabled"`
		IssuerURL    string `mapstructure:"issuer_url"`
		ClientID     string `mapstructure:"client_id"`
		ClientSecret string `mapstructure:"client_secret"`
		RedirectURL  string `mapstructure:"redirect_url"`
	} `mapstructure:"oidc_settings"`
}

type OidcConfig struct {
	Enabled      bool   `json:"enabled" mapstructure:"enabled"`
	IssuerURL    string `json:"issuer_url" mapstructure:"issuer_url"`
	ClientID     string `json:"client_id" mapstructure:"client_id"`
	ClientSecret string `json:"client_secret" mapstructure:"client_secret"`
	RedirectURL  string `json:"redirect_url" mapstructure:"redirect_url"`
}

const encryptedSecretPrefix = "enc:"

func getSecretEncryptionKey() []byte {
	k := viper.GetString("csrf_key")
	if k == "" {
		k = "homelab-cert-manager-secret-encryption-salt"
	}
	hash := sha256.Sum256([]byte(k))
	return hash[:]
}

func encryptSecret(plaintext string) (string, error) {
	if plaintext == "" {
		return "", nil
	}
	key := getSecretEncryptionKey()
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return encryptedSecretPrefix + base64.StdEncoding.EncodeToString(ciphertext), nil
}

func decryptSecret(ciphertext string) string {
	if !strings.HasPrefix(ciphertext, encryptedSecretPrefix) {
		return ciphertext
	}
	raw := strings.TrimPrefix(ciphertext, encryptedSecretPrefix)
	data, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return ciphertext
	}
	key := getSecretEncryptionKey()
	block, err := aes.NewCipher(key)
	if err != nil {
		return ciphertext
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return ciphertext
	}
	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return ciphertext
	}
	nonce, ct := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return ciphertext
	}
	return string(plaintext)
}

func maskClientSecret(secret string) string {
	secret = strings.TrimSpace(secret)
	if secret == "" {
		return ""
	}
	if len(secret) <= 4 {
		return secret + "••••••••"
	}
	return secret[:4] + "••••••••"
}

func initSettings() error {
	debugLog("initSettings called")
	viper.SetConfigName("settings")
	viper.SetConfigType("json")
	viper.AddConfigPath("data")

	// Set defaults
	viper.SetDefault("certificate_manager_certificate.dns_names", []string{})
	viper.SetDefault("certificate_manager_certificate.ip_addresses", []string{})

	viper.SetDefault("general_cert_options.validity_period", "10")
	viper.SetDefault("general_cert_options.organization", "")
	viper.SetDefault("general_cert_options.organization_unit", "")
	viper.SetDefault("general_cert_options.country", "")
	viper.SetDefault("general_cert_options.state", "")
	viper.SetDefault("general_cert_options.location", "")
	viper.SetDefault("general_cert_options.email", "")

	viper.SetDefault("session_settings.timeout_minutes", 2)

	viper.SetDefault("oidc_settings.enabled", false)
	viper.SetDefault("oidc_settings.issuer_url", "")
	viper.SetDefault("oidc_settings.client_id", "")
	viper.SetDefault("oidc_settings.client_secret", "")
	viper.SetDefault("oidc_settings.redirect_url", "")

	_ = viper.BindEnv("oidc_settings.enabled", "OIDC_ENABLED")
	_ = viper.BindEnv("oidc_settings.issuer_url", "OIDC_ISSUER_URL")
	_ = viper.BindEnv("oidc_settings.client_id", "OIDC_CLIENT_ID")
	_ = viper.BindEnv("oidc_settings.client_secret", "OIDC_CLIENT_SECRET")
	_ = viper.BindEnv("oidc_settings.redirect_url", "OIDC_REDIRECT_URL")

	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			return viper.SafeWriteConfig()
		}
		return err
	}

	// Automatically migrate plaintext client_secret to encrypted at rest
	rawSecret := viper.GetString("oidc_settings.client_secret")
	if rawSecret != "" && !strings.HasPrefix(rawSecret, encryptedSecretPrefix) {
		if enc, err := encryptSecret(rawSecret); err == nil {
			viper.Set("oidc_settings.client_secret", enc)
			_ = saveViperConfig()
		}
	}

	return nil
}

// getOidcSettings returns the effective OIDC configuration, applying environment variable overrides.
func getOidcSettings() OidcConfig {
	enabled := viper.GetBool("oidc_settings.enabled")
	if env := os.Getenv("OIDC_ENABLED"); env != "" {
		enabled = strings.ToLower(env) == "true" || env == "1"
	}
	issuerURL := viper.GetString("oidc_settings.issuer_url")
	if env := os.Getenv("OIDC_ISSUER_URL"); env != "" {
		issuerURL = env
	}
	clientID := viper.GetString("oidc_settings.client_id")
	if env := os.Getenv("OIDC_CLIENT_ID"); env != "" {
		clientID = env
	}
	clientSecret := decryptSecret(viper.GetString("oidc_settings.client_secret"))
	if env := os.Getenv("OIDC_CLIENT_SECRET"); env != "" {
		clientSecret = env
	}
	redirectURL := viper.GetString("oidc_settings.redirect_url")
	if env := os.Getenv("OIDC_REDIRECT_URL"); env != "" {
		redirectURL = env
	}

	return OidcConfig{
		Enabled:      enabled,
		IssuerURL:    strings.TrimSpace(issuerURL),
		ClientID:     strings.TrimSpace(clientID),
		ClientSecret: strings.TrimSpace(clientSecret),
		RedirectURL:  strings.TrimSpace(redirectURL),
	}
}

// isOidcEnabled returns true if OIDC is enabled and minimum configuration (issuer URL and client ID) is provided.
func isOidcEnabled() bool {
	cfg := getOidcSettings()
	return cfg.Enabled && cfg.IssuerURL != "" && cfg.ClientID != ""
}

// saveOidcSettings persists OIDC configuration to settings.json.
func saveOidcSettings(enabled bool, issuerURL, clientID, clientSecret, redirectURL string) error {
	debugLog("saveOidcSettings called: enabled=%v", enabled)
	viper.Set("oidc_settings.enabled", enabled)
	viper.Set("oidc_settings.issuer_url", strings.TrimSpace(issuerURL))
	viper.Set("oidc_settings.client_id", strings.TrimSpace(clientID))
	viper.Set("oidc_settings.redirect_url", strings.TrimSpace(redirectURL))

	trimmedSecret := strings.TrimSpace(clientSecret)
	existingRaw := viper.GetString("oidc_settings.client_secret")
	existingDecrypted := decryptSecret(existingRaw)

	// If the user submitted a masked secret (e.g. contains bullets or equals masked value), keep existing
	if strings.Contains(trimmedSecret, "•") || (existingDecrypted != "" && trimmedSecret == maskClientSecret(existingDecrypted)) {
		if !strings.HasPrefix(existingRaw, encryptedSecretPrefix) && existingDecrypted != "" {
			enc, err := encryptSecret(existingDecrypted)
			if err == nil {
				viper.Set("oidc_settings.client_secret", enc)
			}
		}
	} else if trimmedSecret != "" {
		enc, err := encryptSecret(trimmedSecret)
		if err != nil {
			viper.Set("oidc_settings.client_secret", trimmedSecret)
		} else {
			viper.Set("oidc_settings.client_secret", enc)
		}
	} else {
		viper.Set("oidc_settings.client_secret", "")
	}

	return saveViperConfig()
}

// getSessionTimeoutMinutes returns the configured session timeout between 1 and 30 minutes (default 2).
func getSessionTimeoutMinutes() int {
	mins := viper.GetInt("session_settings.timeout_minutes")
	if mins < 1 || mins > 30 {
		return 2
	}
	return mins
}

// saveViperConfig persists the viper configuration and ensures restricted 0600 file permissions.
func saveViperConfig() error {
	configFile := viper.ConfigFileUsed()
	if configFile == "" {
		configFile = "data/settings.json"
	}
	err := viper.WriteConfig()
	if err != nil {
		err = viper.WriteConfigAs(configFile)
	}
	if err != nil {
		return err
	}
	_ = os.Chmod(configFile, 0660)
	return nil
}

// saveSessionSettings saves the session timeout setting after validation.
func saveSessionSettings(timeoutMinutes int) error {
	debugLog("saveSessionSettings called with %d", timeoutMinutes)
	if err := validateSessionTimeout(timeoutMinutes); err != nil {
		return err
	}
	viper.Set("session_settings.timeout_minutes", timeoutMinutes)
	return saveViperConfig()
}

func saveCertManagerSettings(dnsNames []string, ipAddresses []string) error {
	debugLog("saveCertManagerSettings called")
	// Strip leading and trailing spaces from DNS names
	for i, dns := range dnsNames {
		dnsNames[i] = strings.TrimSpace(dns)
	}

	// Strip leading and trailing spaces from IP addresses
	for i, ip := range ipAddresses {
		ipAddresses[i] = strings.TrimSpace(ip)
	}

	viper.Set("certificate_manager_certificate.dns_names", dnsNames)
	viper.Set("certificate_manager_certificate.ip_addresses", ipAddresses)
	return saveViperConfig()
}

func saveGeneralCertOptions(validityPeriod, organization, organizationUnit, country, state, location, email string) error {
	debugLog("saveGeneralCertOptions called")
	viper.Set("general_cert_options.validity_period", strings.TrimSpace(validityPeriod))
	viper.Set("general_cert_options.organization", strings.TrimSpace(organization))
	viper.Set("general_cert_options.organization_unit", strings.TrimSpace(organizationUnit))
	viper.Set("general_cert_options.country", strings.TrimSpace(country))
	viper.Set("general_cert_options.state", strings.TrimSpace(state))
	viper.Set("general_cert_options.location", strings.TrimSpace(location))
	viper.Set("general_cert_options.email", strings.TrimSpace(email))
	return saveViperConfig()
}
