package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"
)

// getOIDCHTTPClient builds an HTTP client configured with the system root CAs plus
// any local Homelab Root CAs in data/root-cert/ so that connection to a self-hosted
// Pocket ID / OIDC provider succeeds seamlessly.
func getOIDCHTTPClient() *http.Client {
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}

	candidatePaths := []string{
		filepath.Join("data", "root-cert", "HomeLab_Root_CA.pem"),
		filepath.Join("data", "rootCA.crt"),
		filepath.Join("data", "root-cert", "HomeLab_Root_CA.crt"),
	}

	if entries, err := os.ReadDir(filepath.Join("data", "root-cert")); err == nil {
		for _, entry := range entries {
			if !entry.IsDir() {
				ext := strings.ToLower(filepath.Ext(entry.Name()))
				if ext == ".pem" || ext == ".crt" {
					candidatePaths = append(candidatePaths, filepath.Join("data", "root-cert", entry.Name()))
				}
			}
		}
	}

	seen := make(map[string]bool)
	for _, path := range candidatePaths {
		if seen[path] {
			continue
		}
		seen[path] = true
		if certBytes, err := os.ReadFile(path); err == nil && len(certBytes) > 0 {
			if ok := pool.AppendCertsFromPEM(certBytes); ok {
				debugLog("Added Root CA from %s to OIDC client trust pool", path)
			}
		}
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs: pool,
		},
		ForceAttemptHTTP2:   true,
		MaxIdleConns:        10,
		IdleConnTimeout:     30 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
	}

	return &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}
}

// resolveOIDCRedirectURL returns the configured redirect URL or computes one from the request.
func resolveOIDCRedirectURL(c *gin.Context, configuredURL string) string {
	if configuredURL != "" {
		return configuredURL
	}
	proto := "https"
	if c.Request.TLS == nil && c.Request.Header.Get("X-Forwarded-Proto") != "https" {
		proto = "http"
	}
	return fmt.Sprintf("%s://%s/auth/oidc/callback", proto, c.Request.Host)
}

// handleOIDCLogin initiates the OIDC authorization code flow.
func handleOIDCLogin(c *gin.Context) {
	if !isOidcEnabled() {
		c.Redirect(http.StatusSeeOther, "/login?error="+url.QueryEscape("OIDC authentication is not enabled"))
		return
	}

	cfg := getOidcSettings()

	// Generate random 32-byte CSRF state
	stateBytes := make([]byte, 32)
	if _, err := rand.Read(stateBytes); err != nil {
		log.Printf("Failed to generate OIDC state: %v", err)
		c.Redirect(http.StatusSeeOther, "/login?error="+url.QueryEscape("Failed to generate security state"))
		return
	}
	state := hex.EncodeToString(stateBytes)

	// Set state cookie (SameSite Lax required for IdP redirects)
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie("oidc_state", state, 600, "/", "", c.Request.TLS != nil, true)

	httpClient := getOIDCHTTPClient()
	ctx := oidc.ClientContext(c.Request.Context(), httpClient)
	ctx = context.WithValue(ctx, oauth2.HTTPClient, httpClient)

	provider, err := oidc.NewProvider(ctx, cfg.IssuerURL)
	if err != nil {
		log.Printf("Failed to query OIDC provider at %s: %v", cfg.IssuerURL, err)
		c.Redirect(http.StatusSeeOther, "/login?error="+url.QueryEscape("Unable to connect to OIDC identity provider: "+err.Error()))
		return
	}

	redirectURL := resolveOIDCRedirectURL(c, cfg.RedirectURL)
	oauthConfig := &oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		RedirectURL:  redirectURL,
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}

	authURL := oauthConfig.AuthCodeURL(state)
	c.Redirect(http.StatusSeeOther, authURL)
}

// handleOIDCCallback processes the authorization code returned by the OIDC provider.
func handleOIDCCallback(c *gin.Context) {
	if !isOidcEnabled() {
		c.Redirect(http.StatusSeeOther, "/login?error="+url.QueryEscape("OIDC authentication is not enabled"))
		return
	}

	cfg := getOidcSettings()

	cookieState, err := c.Cookie("oidc_state")
	queryState := c.Query("state")

	// Clear state cookie
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie("oidc_state", "", -1, "/", "", c.Request.TLS != nil, true)

	if err != nil || cookieState == "" || cookieState != queryState {
		log.Printf("OIDC state validation failed: cookie=%q query=%q err=%v", cookieState, queryState, err)
		c.Redirect(http.StatusSeeOther, "/login?error="+url.QueryEscape("Invalid or expired login session state"))
		return
	}

	if idpErr := c.Query("error"); idpErr != "" {
		desc := c.Query("error_description")
		log.Printf("OIDC provider error returned: %s (%s)", idpErr, desc)
		msg := "Identity provider returned an error: " + idpErr
		if desc != "" {
			msg += " (" + desc + ")"
		}
		c.Redirect(http.StatusSeeOther, "/login?error="+url.QueryEscape(msg))
		return
	}

	code := c.Query("code")
	if code == "" {
		c.Redirect(http.StatusSeeOther, "/login?error="+url.QueryEscape("Missing authorization code from identity provider"))
		return
	}

	httpClient := getOIDCHTTPClient()
	ctx := oidc.ClientContext(c.Request.Context(), httpClient)
	ctx = context.WithValue(ctx, oauth2.HTTPClient, httpClient)

	provider, err := oidc.NewProvider(ctx, cfg.IssuerURL)
	if err != nil {
		log.Printf("Failed to re-initialize OIDC provider at %s: %v", cfg.IssuerURL, err)
		c.Redirect(http.StatusSeeOther, "/login?error="+url.QueryEscape("Failed to reach identity provider"))
		return
	}

	redirectURL := resolveOIDCRedirectURL(c, cfg.RedirectURL)
	oauthConfig := &oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		RedirectURL:  redirectURL,
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}

	token, err := oauthConfig.Exchange(ctx, code)
	if err != nil {
		log.Printf("OIDC token exchange failed: %v", err)
		c.Redirect(http.StatusSeeOther, "/login?error="+url.QueryEscape("Failed to exchange authorization code for token"))
		return
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		log.Printf("OIDC response did not include id_token")
		c.Redirect(http.StatusSeeOther, "/login?error="+url.QueryEscape("Identity provider did not return an ID token"))
		return
	}

	verifier := provider.Verifier(&oidc.Config{ClientID: cfg.ClientID})
	idToken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		log.Printf("OIDC ID token verification failed: %v", err)
		c.Redirect(http.StatusSeeOther, "/login?error="+url.QueryEscape("ID token verification failed"))
		return
	}

	var claims struct {
		Email             string `json:"email"`
		PreferredUsername string `json:"preferred_username"`
		Name              string `json:"name"`
	}
	_ = idToken.Claims(&claims)

	username := claims.PreferredUsername
	if username == "" {
		username = claims.Email
	}
	if username == "" {
		username = claims.Name
	}
	if username == "" {
		username = idToken.Subject
	}

	session, err := store.Get(c.Request, "session")
	if err != nil || session == nil {
		session, err = store.New(c.Request, "session")
		if err != nil || session == nil {
			log.Printf("Failed to create session on OIDC login: %v", err)
			c.Redirect(http.StatusSeeOther, "/login?error="+url.QueryEscape("Failed to create user session"))
			return
		}
	}

	session.Values["authenticated"] = true
	session.Values["last_activity"] = time.Now().Unix()
	session.Values["auth_provider"] = "oidc"
	session.Values["username"] = username
	if err := session.Save(c.Request, c.Writer); err != nil {
		log.Printf("Failed to save session after OIDC authentication: %v", err)
		c.Redirect(http.StatusSeeOther, "/login?error="+url.QueryEscape("Failed to persist user session"))
		return
	}

	loginLimiter.Reset(c.ClientIP())
	log.Printf("User successfully authenticated via OIDC: %s (subject: %s)", username, idToken.Subject)
	c.Redirect(http.StatusSeeOther, "/certificates")
}

// handleOIDCSettings manages viewing and updating OIDC configuration via the web interface.
func handleOIDCSettings(c *gin.Context) {
	debugLog("handleOIDCSettings called with method %s", c.Request.Method)

	if c.Request.Method == "GET" {
		cfg := getOidcSettings()
		c.JSON(http.StatusOK, cfg)
		return
	}

	var req OidcConfig
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body: " + err.Error()})
		return
	}

	if req.Enabled {
		if req.IssuerURL == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Issuer URL is required when OIDC is enabled"})
			return
		}
		parsedURL, err := url.Parse(req.IssuerURL)
		if err != nil || (parsedURL.Scheme != "http" && parsedURL.Scheme != "https") || parsedURL.Host == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Issuer URL must be a valid HTTP or HTTPS URL (e.g. https://id.example.com)"})
			return
		}

		if req.ClientID == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Client ID is required when OIDC is enabled"})
			return
		}

		if req.RedirectURL != "" {
			parsedRedirect, err := url.Parse(req.RedirectURL)
			if err != nil || (parsedRedirect.Scheme != "http" && parsedRedirect.Scheme != "https") || parsedRedirect.Host == "" {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Redirect URL must be a valid HTTP or HTTPS URL if specified"})
				return
			}
		}
	}

	if err := saveOidcSettings(req.Enabled, req.IssuerURL, req.ClientID, req.ClientSecret, req.RedirectURL); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save OIDC settings: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "OIDC settings saved successfully",
		"config":  getOidcSettings(),
	})
}
