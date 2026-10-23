package main

import (
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

type clientAttempt struct {
	count      int
	lastFailed time.Time
}

// LoginRateLimiter provides thread-safe brute-force protection by IP address.
type LoginRateLimiter struct {
	mu              sync.Mutex
	attempts        map[string]*clientAttempt
	maxAttempts     int
	lockoutDuration time.Duration
}

// NewLoginRateLimiter creates a new LoginRateLimiter instance.
func NewLoginRateLimiter(maxAttempts int, lockoutDuration time.Duration) *LoginRateLimiter {
	return &LoginRateLimiter{
		attempts:        make(map[string]*clientAttempt),
		maxAttempts:     maxAttempts,
		lockoutDuration: lockoutDuration,
	}
}

// IsBlocked returns true and remaining lockout duration if the IP has exceeded max failed attempts.
func (l *LoginRateLimiter) IsBlocked(ip string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()

	attempt, exists := l.attempts[ip]
	if !exists {
		return false, 0
	}

	elapsed := time.Since(attempt.lastFailed)
	if elapsed >= l.lockoutDuration {
		// Lockout expired, clean up entry
		delete(l.attempts, ip)
		return false, 0
	}

	if attempt.count >= l.maxAttempts {
		return true, l.lockoutDuration - elapsed
	}

	return false, 0
}

// RecordFailure increments the failed attempt count for the given IP.
func (l *LoginRateLimiter) RecordFailure(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	attempt, exists := l.attempts[ip]
	if !exists || now.Sub(attempt.lastFailed) >= l.lockoutDuration {
		l.attempts[ip] = &clientAttempt{
			count:      1,
			lastFailed: now,
		}
	} else {
		attempt.count++
		attempt.lastFailed = now
	}

	// Opportunistic cleanup if map grows
	if len(l.attempts) > 100 {
		for k, v := range l.attempts {
			if now.Sub(v.lastFailed) >= l.lockoutDuration {
				delete(l.attempts, k)
			}
		}
	}
}

// Reset clears any recorded failures for the given IP after a successful login.
func (l *LoginRateLimiter) Reset(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	delete(l.attempts, ip)
}

// Middleware creates a Gin middleware that enforces brute-force lockout on login routes.
func (l *LoginRateLimiter) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		clientIP := c.ClientIP()
		blocked, remaining := l.IsBlocked(clientIP)
		if blocked {
			seconds := int(remaining.Seconds())
			if seconds < 1 {
				seconds = 1
			}
			c.Header("Retry-After", fmt.Sprintf("%d", seconds))
			c.HTML(http.StatusTooManyRequests, "login.html", gin.H{
				"error":     fmt.Sprintf("Too many failed login attempts. Please try again in %d seconds.", seconds),
				"csrfToken": getCSRFToken(c.Request),
			})
			c.Abort()
			return
		}
		c.Next()
	}
}
