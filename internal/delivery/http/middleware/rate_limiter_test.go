package middleware_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/regiwitanto/auth-service/internal/delivery/http/middleware"
	"github.com/stretchr/testify/assert"
)

func TestRateLimiter(t *testing.T) {
	// Setup
	e := echo.New()
	handler := func(c echo.Context) error {
		return c.String(http.StatusOK, "success")
	}

	t.Run("Allow requests within rate limit", func(t *testing.T) {
		// Create a fresh rate limiter for this test with a higher limit
		rateLimiter := middleware.NewRateLimiterWithConfig(middleware.RateLimiterConfig{
			Requests:  100,         // Allow 100 requests
			Window:    time.Minute, // per minute
			BurstSize: 20,          // with a burst of 20
			Strategy:  "ip",        // IP-based limiting
		})
		middlewareFunc := rateLimiter.Limit()(handler)

		// Send multiple requests (less than the limit)
		for i := 0; i < 10; i++ {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Header.Set("X-Real-IP", "192.168.1.1") // Same IP for all requests
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)

			// Act
			err := middlewareFunc(c)

			// Assert - All should be allowed
			assert.NoError(t, err)
			assert.Equal(t, http.StatusOK, rec.Code)
			assert.Equal(t, "success", rec.Body.String())
		}
	})

	t.Run("Block requests exceeding rate limit", func(t *testing.T) {
		// Create a test-specific rate limiter that is guaranteed to block
		// using a zero limit (will always rate limit)
		strictLimiter := middleware.NewRateLimiterWithConfig(middleware.RateLimiterConfig{
			Requests:  1,         // Only 1 request
			Window:    time.Hour, // per hour (very restrictive)
			BurstSize: 0,         // No burst allowed
			Strategy:  "global",  // Global limiter (affects all IPs)
		})

		// Use the middleware in a handler chain
		strictFunc := strictLimiter.Limit()(handler)

		// Send first request to consume the only available slot
		req1 := httptest.NewRequest(http.MethodGet, "/", nil)
		rec1 := httptest.NewRecorder()
		c1 := e.NewContext(req1, rec1)

		// This should pass
		err1 := strictFunc(c1)
		assert.NoError(t, err1)
		assert.Equal(t, http.StatusOK, rec1.Code)

		// Send second request that should be rate limited
		req2 := httptest.NewRequest(http.MethodGet, "/", nil)
		rec2 := httptest.NewRecorder()
		c2 := e.NewContext(req2, rec2)

		// This should be blocked
		err2 := strictFunc(c2)

		// Assert rate limiting
		httpError, ok := err2.(*echo.HTTPError)
		assert.True(t, ok, "Expected HTTP error")
		assert.Equal(t, http.StatusTooManyRequests, httpError.Code, "Expected 429 status code")
		assert.Equal(t, "Rate limit exceeded", httpError.Message, "Expected rate limit message")
	})

	t.Run("Different IPs have separate rate limits", func(t *testing.T) {
		// Setup a fresh moderate rate limiter for this test
		config := middleware.RateLimiterConfig{
			Requests:  10,          // 10 requests
			Window:    time.Minute, // per minute
			BurstSize: 5,           // with a burst of 5
			Strategy:  "ip",        // IP-based
		}
		limiter := middleware.NewRateLimiterWithConfig(config)
		limitFunc := limiter.Limit()(handler)

		// Send multiple requests from different IPs
		ips := []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}

		// Each IP should get its own rate limit
		for _, ip := range ips {
			// Send requests up to the limit for each IP
			for i := 0; i < 5; i++ {
				req := httptest.NewRequest(http.MethodGet, "/", nil)
				req.Header.Set("X-Real-IP", ip)
				rec := httptest.NewRecorder()
				c := e.NewContext(req, rec)

				// Act
				err := limitFunc(c)

				// Assert - All should be allowed
				assert.NoError(t, err)
				assert.Equal(t, http.StatusOK, rec.Code)
			}

			// One more should be rate limited
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Header.Set("X-Real-IP", ip)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)

			// Act
			err := limitFunc(c)

			// Assert
			httpError, ok := err.(*echo.HTTPError)
			assert.True(t, ok)
			assert.Equal(t, http.StatusTooManyRequests, httpError.Code)
		}
	})
}
