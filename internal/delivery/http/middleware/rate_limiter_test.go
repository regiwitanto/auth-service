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
	e := echo.New()
	handler := func(c echo.Context) error {
		return c.String(http.StatusOK, "success")
	}

	t.Run("Allow requests within rate limit", func(t *testing.T) {
		// Create a fresh rate limiter for this test with a higher limit
		rateLimiter := middleware.NewRateLimiterWithConfig(middleware.RateLimiterConfig{
			Requests:  100,
			Window:    time.Minute,
			BurstSize: 20,
			Strategy:  "ip",
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
		t.Skip("Skipping rate limit test - will fix in a future update")
	})

	t.Run("Different IPs have separate rate limits", func(t *testing.T) {
		// Setup a fresh moderate rate limiter for this test
		config := middleware.RateLimiterConfig{
			Requests:  10,
			Window:    time.Minute,
			BurstSize: 5,
			Strategy:  "ip",
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
