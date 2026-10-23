package main

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/csrf"
	"github.com/spf13/viper"
)

// csrfKey is used for CSRF token generation (32 bytes required)
// In production, this should come from a secure configuration
var csrfKey []byte

// initCSRFKey initializes the CSRF key from the session key
func initCSRFKey(sessionKey string) {
	// Use the first 32 bytes of the session key for CSRF
	if len(sessionKey) >= 32 {
		csrfKey = []byte(sessionKey[:32])
	} else {
		// Pad with zeros if session key is too short
		csrfKey = make([]byte, 32)
		copy(csrfKey, sessionKey)
	}
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
