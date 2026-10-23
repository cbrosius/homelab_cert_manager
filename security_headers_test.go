package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/spf13/viper"
)

func TestSecurityHeadersMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)
	viper.Set("debug", false)

	r := gin.New()
	r.Use(securityHeadersMiddleware())
	r.GET("/test-headers", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	req, _ := http.NewRequest(http.MethodGet, "/test-headers", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected status 200, got %d", w.Code)
	}

	headers := w.Header()

	expectedHeaders := map[string]string{
		"X-Frame-Options":           "DENY",
		"X-Content-Type-Options":    "nosniff",
		"Referrer-Policy":           "strict-origin-when-cross-origin",
		"X-XSS-Protection":          "1; mode=block",
		"Strict-Transport-Security": "max-age=31536000; includeSubDomains",
	}

	for header, expectedValue := range expectedHeaders {
		actual := headers.Get(header)
		if actual != expectedValue {
			t.Errorf("Header %q: expected %q, got %q", header, expectedValue, actual)
		}
	}

	csp := headers.Get("Content-Security-Policy")
	if !strings.Contains(csp, "default-src 'self'") {
		t.Errorf("CSP missing default-src 'self', got: %q", csp)
	}
	if !strings.Contains(csp, "frame-ancestors 'none'") {
		t.Errorf("CSP missing frame-ancestors 'none', got: %q", csp)
	}
}

func TestSecurityHeadersHSTSDisabledInDebug(t *testing.T) {
	gin.SetMode(gin.TestMode)
	viper.Set("debug", true)
	defer viper.Set("debug", false)

	r := gin.New()
	r.Use(securityHeadersMiddleware())
	r.GET("/test-debug-hsts", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	req, _ := http.NewRequest(http.MethodGet, "/test-debug-hsts", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if hsts := w.Header().Get("Strict-Transport-Security"); hsts != "" {
		t.Errorf("Expected no HSTS in debug mode, got %q", hsts)
	}
}
