package main

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/csrf"
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
	protector := csrf.Protect(
		csrfKey,
		csrf.Secure(true),                      // Requires HTTPS
		csrf.HttpOnly(true),                    // HttpOnly cookie
		csrf.Path("/"),                         // Cookie path
		csrf.SameSite(csrf.SameSiteStrictMode), // Strict SameSite
		csrf.CookieName("csrf_token"),          // Cookie name
		csrf.FieldName("csrf_token"),           // Form field name
	)

	return func(c *gin.Context) {
		// Skip CSRF for safe methods (GET, HEAD, OPTIONS, TRACE)
		if c.Request.Method == "GET" || c.Request.Method == "HEAD" ||
			c.Request.Method == "OPTIONS" || c.Request.Method == "TRACE" {
			c.Next()
			return
		}

		// Apply CSRF protection to state-changing methods
		protector(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c.Request = r
			c.Next()
		})).ServeHTTP(c.Writer, c.Request)
	}
}

// getCSRFToken retrieves the current CSRF token for the request
func getCSRFToken(r *http.Request) string {
	return csrf.Token(r)
}
