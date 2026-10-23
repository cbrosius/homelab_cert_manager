package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestCSRFMiddlewareTokenGeneration(t *testing.T) {
	gin.SetMode(gin.TestMode)
	initCSRFKey("0123456789012345678901234567890123456789")

	r := gin.New()
	r.Use(csrfMiddleware())

	var token string
	r.GET("/test-csrf", func(c *gin.Context) {
		token = getCSRFToken(c.Request)
		c.String(http.StatusOK, "token: %s", token)
	})

	req, _ := http.NewRequest(http.MethodGet, "/test-csrf", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	req.URL.Scheme = "https"

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected status 200, got %d. Body: %s", w.Code, w.Body.String())
	}

	if token == "" {
		t.Errorf("Expected non-empty CSRF token, got empty string")
	}

	cookie := w.Header().Get("Set-Cookie")
	if !strings.Contains(cookie, "csrf_token=") {
		t.Errorf("Expected Set-Cookie header with csrf_token, got: %s", cookie)
	}
}

func TestCSRFLoginPost(t *testing.T) {
	gin.SetMode(gin.TestMode)
	initCSRFKey("0123456789012345678901234567890123456789")

	r := gin.New()
	r.Use(csrfMiddleware())

	var retrievedToken string
	r.GET("/login", func(c *gin.Context) {
		retrievedToken = getCSRFToken(c.Request)
		c.String(http.StatusOK, retrievedToken)
	})

	r.POST("/login", func(c *gin.Context) {
		c.String(http.StatusOK, "login successful")
	})

	// 1. First perform GET /login
	getReq, _ := http.NewRequest(http.MethodGet, "/login", nil)
	getReq.Header.Set("X-Forwarded-Proto", "https")
	getReq.URL.Scheme = "https"
	getW := httptest.NewRecorder()
	r.ServeHTTP(getW, getReq)

	if getW.Code != http.StatusOK {
		t.Fatalf("GET /login failed: code %d", getW.Code)
	}
	cookie := getW.Header().Get("Set-Cookie")
	if cookie == "" {
		t.Fatalf("No Set-Cookie header received on GET /login")
	}

	// Extract cookie raw value before semicolon
	parts := strings.Split(cookie, ";")
	cookieValue := parts[0] // csrf_token=...

	// 2. Perform POST /login with the token and cookie
	formData := url.Values{}
	formData.Set("csrf_token", retrievedToken)
	formData.Set("username", "admin")
	formData.Set("password", "admin")

	postReq, _ := http.NewRequest(http.MethodPost, "/login", strings.NewReader(formData.Encode()))
	postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	postReq.Header.Set("Cookie", cookieValue)
	postReq.Header.Set("X-Forwarded-Proto", "https")
	postReq.Header.Set("Referer", "https://example.com/login")
	postReq.Host = "example.com"
	postReq.URL.Host = "example.com"
	postReq.URL.Scheme = "https"

	postW := httptest.NewRecorder()
	r.ServeHTTP(postW, postReq)

	if postW.Code != http.StatusOK {
		t.Fatalf("POST /login failed with code %d: %s", postW.Code, postW.Body.String())
	}

	if postW.Body.String() != "login successful" {
		t.Errorf("Unexpected body: %s", postW.Body.String())
	}
}

func TestLoadConfig(t *testing.T) {
	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig failed: %v", err)
	}
	if cfg.SessionKey == "" {
		t.Errorf("Expected non-empty SessionKey")
	}
}

func TestLoginWithInvalidSessionCookie(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig failed: %v", err)
	}

	r := gin.New()
	r.POST("/login", func(c *gin.Context) {
		handleLogin(c, cfg)
	})

	formData := url.Values{}
	formData.Set("username", "admin")
	formData.Set("password", "admin") // In default test config

	postReq, _ := http.NewRequest(http.MethodPost, "/login", strings.NewReader(formData.Encode()))
	postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// Send an invalid/corrupted session cookie
	postReq.Header.Set("Cookie", "session=corrupted_or_outdated_cookie_value")

	postW := httptest.NewRecorder()
	r.ServeHTTP(postW, postReq)

	// Even if password does not match (if changed in settings.json), it shouldn't return 500 session error
	if postW.Code == http.StatusInternalServerError {
		t.Fatalf("Login failed with 500 session error when invalid cookie sent!")
	}
	t.Logf("Response code with invalid cookie: %d", postW.Code)
}
