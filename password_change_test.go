package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/spf13/viper"
)

func TestCheckPasswordChangeMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)

	config := &Config{
		MustChangePassword: true,
	}

	r := gin.New()
	r.Use(CheckPasswordChange(config))
	r.GET("/certificates", func(c *gin.Context) {
		c.String(http.StatusOK, "certificates page")
	})
	r.GET("/change-password", func(c *gin.Context) {
		c.String(http.StatusOK, "change password page")
	})

	// When MustChangePassword is true, accessing /certificates should redirect to /change-password
	req, _ := http.NewRequest(http.MethodGet, "/certificates", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("Expected redirect 303, got %d", w.Code)
	}
	if loc := w.Header().Get("Location"); loc != "/change-password" {
		t.Fatalf("Expected Location /change-password, got %s", loc)
	}

	// Accessing /change-password directly should be allowed
	req2, _ := http.NewRequest(http.MethodGet, "/change-password", nil)
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, req2)

	if w2.Code != http.StatusOK {
		t.Fatalf("Expected status 200 on /change-password, got %d", w2.Code)
	}

	// When MustChangePassword is false, accessing /certificates should be allowed
	config.MustChangePassword = false
	req3, _ := http.NewRequest(http.MethodGet, "/certificates", nil)
	w3 := httptest.NewRecorder()
	r.ServeHTTP(w3, req3)

	if w3.Code != http.StatusOK {
		t.Fatalf("Expected status 200 on /certificates after password change, got %d", w3.Code)
	}
}

func TestChangePasswordHandler(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Set temporary test config in viper
	viper.Set("password", "")
	viper.Set("must_change_password", true)

	oldPassHash, err := hashPassword("admin")
	if err != nil {
		t.Fatalf("Failed to hash initial password: %v", err)
	}

	config := &Config{
		Password:           oldPassHash,
		MustChangePassword: true,
	}

	r := gin.New()
	r.POST("/change-password", func(c *gin.Context) {
		changePassword(c, config)
	})

	// Case 1: Incorrect old password
	body, _ := json.Marshal(map[string]string{
		"old_password": "wrongpassword",
		"new_password": "newSecurePassword123",
	})
	req, _ := http.NewRequest(http.MethodPost, "/change-password", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401 for incorrect old password, got %d", w.Code)
	}

	// Case 2: New password too short (< 8 chars)
	body, _ = json.Marshal(map[string]string{
		"old_password": "admin",
		"new_password": "short",
	})
	req, _ = http.NewRequest(http.MethodPost, "/change-password", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400 for short new password, got %d", w.Code)
	}

	// Case 3: New password cannot be "admin"
	body, _ = json.Marshal(map[string]string{
		"old_password": "admin",
		"new_password": "admin",
	})
	req, _ = http.NewRequest(http.MethodPost, "/change-password", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400 for new password = admin, got %d", w.Code)
	}

	// Case 4: Valid new password
	body, _ = json.Marshal(map[string]string{
		"old_password": "admin",
		"new_password": "MySecretPassword2026!",
	})
	req, _ = http.NewRequest(http.MethodPost, "/change-password", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200 for successful password change, got %d: %s", w.Code, w.Body.String())
	}

	if config.MustChangePassword != false {
		t.Errorf("Expected config.MustChangePassword to be false, got true")
	}

	if !checkPasswordHash("MySecretPassword2026!", config.Password) {
		t.Errorf("Expected new password hash to match 'MySecretPassword2026!'")
	}
}
