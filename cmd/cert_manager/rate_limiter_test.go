package main

import (
	"html/template"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

func TestLoginRateLimiterBasic(t *testing.T) {
	limiter := NewLoginRateLimiter(3, 100*time.Millisecond)
	ip := "192.168.1.100"

	// Initial: not blocked
	if blocked, _ := limiter.IsBlocked(ip); blocked {
		t.Errorf("Expected IP not to be blocked initially")
	}

	// 1st failure
	limiter.RecordFailure(ip)
	if blocked, _ := limiter.IsBlocked(ip); blocked {
		t.Errorf("Expected IP not to be blocked after 1 failure")
	}

	// 2nd failure
	limiter.RecordFailure(ip)
	if blocked, _ := limiter.IsBlocked(ip); blocked {
		t.Errorf("Expected IP not to be blocked after 2 failures")
	}

	// 3rd failure (hits threshold)
	limiter.RecordFailure(ip)
	blocked, remaining := limiter.IsBlocked(ip)
	if !blocked {
		t.Errorf("Expected IP to be blocked after 3 failures")
	}
	if remaining <= 0 {
		t.Errorf("Expected positive remaining lockout duration, got %v", remaining)
	}

	// Reset on success
	limiter.Reset(ip)
	if blocked, _ := limiter.IsBlocked(ip); blocked {
		t.Errorf("Expected IP to be unblocked after Reset")
	}
}

func TestLoginRateLimiterExpiry(t *testing.T) {
	limiter := NewLoginRateLimiter(2, 50*time.Millisecond)
	ip := "10.0.0.1"

	limiter.RecordFailure(ip)
	limiter.RecordFailure(ip)

	if blocked, _ := limiter.IsBlocked(ip); !blocked {
		t.Fatalf("Expected IP to be blocked")
	}

	// Wait for lockout duration to expire
	time.Sleep(60 * time.Millisecond)

	if blocked, _ := limiter.IsBlocked(ip); blocked {
		t.Errorf("Expected IP to be unblocked after lockout duration expired")
	}
}

func TestLoginRateLimiterMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)
	limiter := NewLoginRateLimiter(2, 5*time.Second)

	r := gin.New()
	r.SetFuncMap(template.FuncMap{
		"toJson": toJson,
	})
	r.LoadHTMLGlob("templates/*")
	r.POST("/test-login", limiter.Middleware(), func(c *gin.Context) {
		c.String(http.StatusOK, "login endpoint reached")
	})

	ip := "1.2.3.4"

	// Request 1: should pass through
	req1, _ := http.NewRequest(http.MethodPost, "/test-login", nil)
	req1.RemoteAddr = ip + ":12345"
	w1 := httptest.NewRecorder()
	r.ServeHTTP(w1, req1)
	if w1.Code != http.StatusOK {
		t.Errorf("Request 1: expected 200, got %d", w1.Code)
	}

	// Record 2 failures for this IP
	limiter.RecordFailure(ip)
	limiter.RecordFailure(ip)

	// Request 2: should be blocked by middleware with 429
	req2, _ := http.NewRequest(http.MethodPost, "/test-login", nil)
	req2.RemoteAddr = ip + ":12345"
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, req2)

	if w2.Code != http.StatusTooManyRequests {
		t.Errorf("Request 2: expected 429 Too Many Requests, got %d", w2.Code)
	}

	retryAfter := w2.Header().Get("Retry-After")
	if retryAfter == "" {
		t.Errorf("Expected non-empty Retry-After header")
	}
}
