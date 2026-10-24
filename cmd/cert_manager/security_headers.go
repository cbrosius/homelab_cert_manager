package main

import (
	"github.com/gin-gonic/gin"
	"github.com/spf13/viper"
)

// securityHeadersMiddleware attaches standard defensive HTTP headers to every response.
func securityHeadersMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Prevent Clickjacking
		c.Header("X-Frame-Options", "DENY")
		// Prevent MIME-type sniffing
		c.Header("X-Content-Type-Options", "nosniff")
		// Referrer policy: send origin only on cross-origin requests
		c.Header("Referrer-Policy", "strict-origin-when-cross-origin")
		// Legacy XSS filter protection
		c.Header("X-XSS-Protection", "1; mode=block")
		// Content Security Policy restricting sources to self
		c.Header("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; font-src 'self'; img-src 'self' data:; frame-ancestors 'none'; form-action 'self';")

		// HTTP Strict Transport Security (HSTS) when not in debug mode
		if !viper.GetBool("debug") {
			c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}

		c.Next()
	}
}
