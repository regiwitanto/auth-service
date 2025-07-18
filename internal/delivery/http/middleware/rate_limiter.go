package middleware

import (
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/labstack/echo/v4"
	"golang.org/x/time/rate"
)

type RateLimiterConfig struct {
	Requests  int
	Window    time.Duration
	BurstSize int
	Strategy  string
}

func DefaultRateLimiterConfig() RateLimiterConfig {
	return RateLimiterConfig{
		Requests:  30,
		Window:    1,
		BurstSize: 5,
		Strategy:  "ip",
	}
}

type RateLimiter struct {
	limiters map[string]*rate.Limiter
	config   RateLimiterConfig
	mu       sync.RWMutex
}

// NewRateLimiter creates a new rate limiter middleware with default config
func NewRateLimiter() *RateLimiter {
	config := DefaultRateLimiterConfig()
	return &RateLimiter{
		limiters: make(map[string]*rate.Limiter),
		config:   config,
	}
}

// NewRateLimiterWithConfig creates a new rate limiter with custom config
func NewRateLimiterWithConfig(config RateLimiterConfig) *RateLimiter {
	return &RateLimiter{
		limiters: make(map[string]*rate.Limiter),
		config:   config,
	}
}

// getLimiter returns the rate limiter for a particular identifier (IP, user ID, etc.)
func (rl *RateLimiter) getLimiter(identifier string) *rate.Limiter {
	rl.mu.RLock()
	limiter, exists := rl.limiters[identifier]
	rl.mu.RUnlock()

	if !exists {
		limit := rate.Every(rl.config.Window * time.Minute / time.Duration(rl.config.Requests))
		limiter = rate.NewLimiter(limit, rl.config.BurstSize)

		rl.mu.Lock()
		rl.limiters[identifier] = limiter
		rl.mu.Unlock()
	}

	return limiter
}

// getIdentifier extracts the identifier for rate limiting based on the strategy
func (rl *RateLimiter) getIdentifier(c echo.Context) string {
	switch rl.config.Strategy {
	case "ip":
		return c.RealIP()
	case "user":
		// Get the user ID from the JWT token if available
		if user := c.Get("user"); user != nil {
			if token, ok := user.(*jwt.Token); ok {
				if claims, ok := token.Claims.(jwt.MapClaims); ok {
					if userID, ok := claims["sub"].(string); ok {
						return userID
					}
				}
			}
		}
		// Fall back to IP if user ID is not available
		return c.RealIP()
	case "global":
		return "global"
	default:
		return c.RealIP()
	}
}

// Limit returns a middleware function that applies rate limiting
func (rl *RateLimiter) Limit() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			identifier := rl.getIdentifier(c)
			limiter := rl.getLimiter(identifier)

			if !limiter.Allow() {
				// Get the current limit information
				limit := limiter.Limit()
				// Convert to requests per minute for a more user-friendly message
				ratePerMinute := int(float64(limit) * 60)

				return echo.NewHTTPError(
					http.StatusTooManyRequests,
					fmt.Sprintf("Rate limit exceeded. Maximum %d requests per minute allowed.", ratePerMinute),
				)
			}

			return next(c)
		}
	}
}

// LimitRoute applies rate limiting to a specific route
func (rl *RateLimiter) LimitRoute(config RateLimiterConfig) echo.MiddlewareFunc {
	routeLimiter := NewRateLimiterWithConfig(config)
	return routeLimiter.Limit()
}

// CleanupTask periodically cleans up inactive limiters
// This should be called in a goroutine
func (rl *RateLimiter) CleanupTask(interval time.Duration, maxIdleTime time.Duration) {
	// Implementation not essential for MVP, but would involve:
	// 1. Keeping track of when each limiter was last accessed
	// 2. Periodically checking and removing limiters that haven't been used
	// 3. This prevents memory leaks from many unique identifiers
}
