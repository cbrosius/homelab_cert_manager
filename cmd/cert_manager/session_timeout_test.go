package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/sessions"
	"github.com/spf13/viper"
)

func backupAndRestoreSettings(t *testing.T) {
	originalContent, err := os.ReadFile("data/settings.json")
	origOidc := getOidcSettings()
	origTimeout := viper.GetInt("session_settings.timeout_minutes")
	t.Cleanup(func() {
		if err == nil {
			_ = os.WriteFile("data/settings.json", originalContent, 0600)
		}
		viper.Set("session_settings.timeout_minutes", origTimeout)
		_ = saveOidcSettings(origOidc.Enabled, origOidc.IssuerURL, origOidc.ClientID, origOidc.ClientSecret, origOidc.RedirectURL)
		_ = initSettings()
	})
}

func setupTestSessionStore() {
	store = sessions.NewCookieStore([]byte("0123456789012345678901234567890123456789012345678901234567890123"))
	store.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   3600,
		HttpOnly: true,
		Secure:   false,
		SameSite: http.SameSiteLaxMode,
	}
}

func TestGetSessionTimeoutMinutes_DefaultsAndBounds(t *testing.T) {
	backupAndRestoreSettings(t)
	viper.Set("session_settings.timeout_minutes", 0)
	if got := getSessionTimeoutMinutes(); got != 2 {
		t.Errorf("Expected fallback 2 minutes for 0, got %d", got)
	}

	viper.Set("session_settings.timeout_minutes", -5)
	if got := getSessionTimeoutMinutes(); got != 2 {
		t.Errorf("Expected fallback 2 minutes for -5, got %d", got)
	}

	viper.Set("session_settings.timeout_minutes", 31)
	if got := getSessionTimeoutMinutes(); got != 2 {
		t.Errorf("Expected fallback 2 minutes for 31, got %d", got)
	}

	viper.Set("session_settings.timeout_minutes", 45)
	if got := getSessionTimeoutMinutes(); got != 2 {
		t.Errorf("Expected fallback 2 minutes for 45, got %d", got)
	}

	viper.Set("session_settings.timeout_minutes", 20)
	if got := getSessionTimeoutMinutes(); got != 20 {
		t.Errorf("Expected 20 minutes, got %d", got)
	}
}

func TestHandleSessionSettings(t *testing.T) {
	backupAndRestoreSettings(t)
	gin.SetMode(gin.TestMode)
	setupTestSessionStore()
	viper.Set("session_settings.timeout_minutes", 2)

	r := gin.New()
	r.GET("/settings/session", handleSessionSettings)
	r.POST("/settings/session", handleSessionSettings)

	// GET test
	reqGet, _ := http.NewRequest(http.MethodGet, "/settings/session", nil)
	wGet := httptest.NewRecorder()
	r.ServeHTTP(wGet, reqGet)

	if wGet.Code != http.StatusOK {
		t.Fatalf("GET /settings/session returned code %d", wGet.Code)
	}
	var resGet map[string]interface{}
	if err := json.Unmarshal(wGet.Body.Bytes(), &resGet); err != nil {
		t.Fatalf("Failed to parse GET response: %v", err)
	}
	if resGet["timeout_minutes"] != float64(2) {
		t.Errorf("Expected timeout_minutes 2, got %v", resGet["timeout_minutes"])
	}

	// POST valid timeout (25)
	reqPostValid, _ := http.NewRequest(http.MethodPost, "/settings/session", strings.NewReader(`{"timeout_minutes": 25}`))
	reqPostValid.Header.Set("Content-Type", "application/json")
	wPostValid := httptest.NewRecorder()
	r.ServeHTTP(wPostValid, reqPostValid)

	if wPostValid.Code != http.StatusOK {
		t.Fatalf("POST /settings/session valid returned code %d: %s", wPostValid.Code, wPostValid.Body.String())
	}
	if getSessionTimeoutMinutes() != 25 {
		t.Errorf("Expected timeout setting updated to 25, got %d", getSessionTimeoutMinutes())
	}

	// POST invalid timeout (0)
	reqPostLow, _ := http.NewRequest(http.MethodPost, "/settings/session", strings.NewReader(`{"timeout_minutes": 0}`))
	reqPostLow.Header.Set("Content-Type", "application/json")
	wPostLow := httptest.NewRecorder()
	r.ServeHTTP(wPostLow, reqPostLow)

	if wPostLow.Code != http.StatusBadRequest {
		t.Errorf("Expected 400 Bad Request for timeout 0, got %d", wPostLow.Code)
	}

	// POST invalid timeout (31)
	reqPostHigh, _ := http.NewRequest(http.MethodPost, "/settings/session", strings.NewReader(`{"timeout_minutes": 31}`))
	reqPostHigh.Header.Set("Content-Type", "application/json")
	wPostHigh := httptest.NewRecorder()
	r.ServeHTTP(wPostHigh, reqPostHigh)

	if wPostHigh.Code != http.StatusBadRequest {
		t.Errorf("Expected 400 Bad Request for timeout 31, got %d", wPostHigh.Code)
	}
}

func TestHandleSessionStatusAndPing(t *testing.T) {
	backupAndRestoreSettings(t)
	gin.SetMode(gin.TestMode)
	setupTestSessionStore()
	viper.Set("session_settings.timeout_minutes", 10)

	r := gin.New()
	r.GET("/api/session/status", handleSessionStatus)
	r.POST("/api/session/ping", handleSessionPing)

	// Create request with authenticated session
	reqInit, _ := http.NewRequest(http.MethodGet, "/api/session/status", nil)
	wInit := httptest.NewRecorder()
	sess, _ := store.Get(reqInit, "session")
	sess.Values["authenticated"] = true
	sess.Values["last_activity"] = time.Now().Unix()
	_ = sess.Save(reqInit, wInit)
	cookie := wInit.Header().Get("Set-Cookie")

	// Call status
	reqStatus, _ := http.NewRequest(http.MethodGet, "/api/session/status", nil)
	reqStatus.Header.Set("Cookie", cookie)
	wStatus := httptest.NewRecorder()
	r.ServeHTTP(wStatus, reqStatus)

	if wStatus.Code != http.StatusOK {
		t.Fatalf("GET /api/session/status returned %d: %s", wStatus.Code, wStatus.Body.String())
	}
	var resStatus map[string]interface{}
	if err := json.Unmarshal(wStatus.Body.Bytes(), &resStatus); err != nil {
		t.Fatalf("Failed to parse status response: %v", err)
	}
	if resStatus["timeout_minutes"] != float64(10) {
		t.Errorf("Expected timeout_minutes 10, got %v", resStatus["timeout_minutes"])
	}
	remaining := resStatus["remaining_seconds"].(float64)
	if remaining < 590 || remaining > 600 {
		t.Errorf("Expected remaining_seconds close to 600, got %v", remaining)
	}

	// Call ping
	reqPing, _ := http.NewRequest(http.MethodPost, "/api/session/ping", nil)
	reqPing.Header.Set("Cookie", cookie)
	wPing := httptest.NewRecorder()
	r.ServeHTTP(wPing, reqPing)

	if wPing.Code != http.StatusOK {
		t.Fatalf("POST /api/session/ping returned %d: %s", wPing.Code, wPing.Body.String())
	}
	var resPing map[string]interface{}
	if err := json.Unmarshal(wPing.Body.Bytes(), &resPing); err != nil {
		t.Fatalf("Failed to parse ping response: %v", err)
	}
	if resPing["status"] != "ok" {
		t.Errorf("Expected status 'ok', got %v", resPing["status"])
	}
}

func TestAuthRequired_InactivityTimeout(t *testing.T) {
	backupAndRestoreSettings(t)
	gin.SetMode(gin.TestMode)
	setupTestSessionStore()
	viper.Set("session_settings.timeout_minutes", 5)

	r := gin.New()
	authorized := r.Group("/")
	authorized.Use(AuthRequired)
	authorized.GET("/dashboard", func(c *gin.Context) {
		c.String(http.StatusOK, "dashboard-ok")
	})

	// 1. Valid active session
	reqActive, _ := http.NewRequest(http.MethodGet, "/dashboard", nil)
	wActiveCookie := httptest.NewRecorder()
	sess, _ := store.Get(reqActive, "session")
	sess.Values["authenticated"] = true
	sess.Values["last_activity"] = time.Now().Unix()
	_ = sess.Save(reqActive, wActiveCookie)
	cookie := wActiveCookie.Header().Get("Set-Cookie")

	reqActive.Header.Set("Cookie", cookie)
	wActive := httptest.NewRecorder()
	r.ServeHTTP(wActive, reqActive)

	if wActive.Code != http.StatusOK || wActive.Body.String() != "dashboard-ok" {
		t.Fatalf("Expected 200 dashboard-ok for active session, got %d: %s", wActive.Code, wActive.Body.String())
	}

	// 2. Expired session - Browser request redirected to /login?timeout=1
	reqExpired, _ := http.NewRequest(http.MethodGet, "/dashboard", nil)
	wExpiredCookie := httptest.NewRecorder()
	sessExpired, _ := store.Get(reqExpired, "session")
	sessExpired.Values["authenticated"] = true
	sessExpired.Values["last_activity"] = time.Now().Add(-10 * time.Minute).Unix() // 10 mins ago, timeout is 5 mins
	_ = sessExpired.Save(reqExpired, wExpiredCookie)
	cookieExpired := wExpiredCookie.Header().Get("Set-Cookie")

	reqExpired.Header.Set("Cookie", cookieExpired)
	wExpired := httptest.NewRecorder()
	r.ServeHTTP(wExpired, reqExpired)

	if wExpired.Code != http.StatusSeeOther {
		t.Fatalf("Expected 303 See Other redirect for expired browser session, got %d", wExpired.Code)
	}
	if loc := wExpired.Header().Get("Location"); loc != "/login?timeout=1" {
		t.Errorf("Expected redirect location '/login?timeout=1', got '%s'", loc)
	}

	// 3. Expired session - AJAX / API request returns 401
	reqExpiredAjax, _ := http.NewRequest(http.MethodGet, "/dashboard", nil)
	reqExpiredAjax.Header.Set("Cookie", cookieExpired)
	reqExpiredAjax.Header.Set("X-Requested-With", "XMLHttpRequest")
	wExpiredAjax := httptest.NewRecorder()
	r.ServeHTTP(wExpiredAjax, reqExpiredAjax)

	if wExpiredAjax.Code != http.StatusUnauthorized {
		t.Fatalf("Expected 401 Unauthorized for expired AJAX request, got %d", wExpiredAjax.Code)
	}
	var resAjax map[string]interface{}
	if err := json.Unmarshal(wExpiredAjax.Body.Bytes(), &resAjax); err != nil {
		t.Fatalf("Failed to parse AJAX error response: %v", err)
	}
	if resAjax["error"] != "session_expired" {
		t.Errorf("Expected error 'session_expired', got %v", resAjax["error"])
	}
}

func TestSessionTimeoutPersistenceAcrossReboot(t *testing.T) {
	backupAndRestoreSettings(t)

	// First initialize as main() does
	if err := initSettings(); err != nil {
		t.Fatalf("setup initSettings failed: %v", err)
	}
	if _, err := loadConfig(); err != nil {
		t.Fatalf("setup loadConfig failed: %v", err)
	}

	// 1. Save custom timeout (7 minutes)
	if err := saveSessionSettings(7); err != nil {
		t.Fatalf("Failed to save session settings: %v", err)
	}

	valBeforeReboot := getSessionTimeoutMinutes()
	t.Logf("Value before reboot: %d", valBeforeReboot)
	if valBeforeReboot != 7 {
		t.Fatalf("Expected 7 before reboot, got %d", valBeforeReboot)
	}

	// 2. Simulate complete restart by resetting viper and running main()'s startup sequence
	viper.Reset()

	if err := initSettings(); err != nil {
		t.Fatalf("reboot initSettings failed: %v", err)
	}
	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("reboot loadConfig failed: %v", err)
	}
	_ = cfg

	valAfterInitSettings := getSessionTimeoutMinutes()
	t.Logf("Value after reboot initSettings: %d", valAfterInitSettings)

	if valAfterInitSettings != 7 {
		t.Fatalf("Expected 7 minutes after reboot, got %d", valAfterInitSettings)
	}
}
