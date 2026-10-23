package main

import (
	"encoding/hex"
	"log"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/csrf"
	"github.com/spf13/viper"
)

// csrfKey is used for CSRF token generation (32 bytes required)
var csrfKey []byte

// initCSRFKey initializes the CSRF key from a hex string or raw key
func initCSRFKey(keyStr string) {
	bytes, err := hex.DecodeString(keyStr)
	if err == nil && len(bytes) == 32 {
		csrfKey = bytes
		return
	}
	// Fallback if not valid hex or not 32 bytes
	if len(keyStr) >= 32 {
		csrfKey = []byte(keyStr[:32])
	} else {
		csrfKey = make([]byte, 32)
		copy(csrfKey, keyStr)
	}
}

// customCSRFErrorHandler handles CSRF validation failures gracefully
func customCSRFErrorHandler(w http.ResponseWriter, r *http.Request) {
	reason := csrf.FailureReason(r)
	log.Printf("CSRF validation error on %s %s: %v", r.Method, r.URL.Path, reason)

	// Invalidate the broken or outdated csrf_token cookie so a clean one can be issued
	http.SetCookie(w, &http.Cookie{
		Name:     "csrf_token",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	})

	if r.Header.Get("X-Requested-With") == "XMLHttpRequest" || strings.Contains(r.Header.Get("Accept"), "application/json") {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"error":"csrf_invalid","message":"Security token expired or invalid. Please refresh the page."}`))
		return
	}

	http.Redirect(w, r, "/login?csrf_error=1", http.StatusSeeOther)
}

// csrfMiddleware is a Gin-compatible CSRF middleware wrapper
func csrfMiddleware() gin.HandlerFunc {
	secure := !viper.GetBool("debug")
	if viper.IsSet("csrf_secure") {
		secure = viper.GetBool("csrf_secure")
	}

	protector := csrf.Protect(
		csrfKey,
		csrf.Secure(secure),                 // Secure cookie by default, configurable for local dev
		csrf.HttpOnly(true),                 // HttpOnly cookie
		csrf.Path("/"),                      // Cookie path
		csrf.SameSite(csrf.SameSiteLaxMode), // Lax SameSite allows reliable form submissions
		csrf.CookieName("csrf_token"),       // Cookie name
		csrf.FieldName("csrf_token"),        // Form field name
		csrf.RequestHeader("X-CSRF-Token"),  // Header name for AJAX / fetch requests
		csrf.ErrorHandler(http.HandlerFunc(customCSRFErrorHandler)),
	)

	return func(c *gin.Context) {
		var handlerCalled bool
		protector(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handlerCalled = true
			c.Request = r
			c.Next()
		})).ServeHTTP(c.Writer, c.Request)

		if !handlerCalled {
			c.Abort()
		}
	}
}

// getCSRFToken retrieves the current CSRF token for the request
func getCSRFToken(r *http.Request) string {
	return csrf.Token(r)
}
