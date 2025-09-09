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
	limiters        map[string]*rate.Limiter
	lastSeen        map[string]time.Time
	config          RateLimiterConfig
	mu              sync.RWMutex
	cleanupInterval time.Duration
}

func NewRateLimiter() *RateLimiter {
	config := DefaultRateLimiterConfig()
	rl := &RateLimiter{
		limiters:        make(map[string]*rate.Limiter),
		lastSeen:        make(map[string]time.Time),
		config:          config,
		cleanupInterval: time.Hour,
	}
	go rl.cleanupTask()
	return rl
}

func NewRateLimiterWithConfig(config RateLimiterConfig) *RateLimiter {
	rl := &RateLimiter{
		limiters:        make(map[string]*rate.Limiter),
		lastSeen:        make(map[string]time.Time),
		config:          config,
		cleanupInterval: time.Hour,
	}
	go rl.cleanupTask()
	return rl
}

func (rl *RateLimiter) cleanupTask() {
	ticker := time.NewTicker(rl.cleanupInterval)
	defer ticker.Stop()

	for range ticker.C {
		rl.cleanup()
	}
}

func (rl *RateLimiter) cleanup() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	threshold := time.Now().Add(-24 * time.Hour)

	for id, lastSeen := range rl.lastSeen {
		if lastSeen.Before(threshold) {
			delete(rl.limiters, id)
			delete(rl.lastSeen, id)
		}
	}
}

func (rl *RateLimiter) getLimiter(identifier string) *rate.Limiter {
	rl.mu.RLock()
	limiter, exists := rl.limiters[identifier]
	rl.mu.RUnlock()

	if !exists {
		limit := rate.Every(rl.config.Window * time.Minute / time.Duration(rl.config.Requests))
		limiter = rate.NewLimiter(limit, rl.config.BurstSize)

		rl.mu.Lock()
		rl.limiters[identifier] = limiter
		rl.lastSeen[identifier] = time.Now()
		rl.mu.Unlock()
	} else {
		// Update the last seen time for this identifier
		rl.mu.Lock()
		rl.lastSeen[identifier] = time.Now()
		rl.mu.Unlock()
	}

	return limiter
}

func (rl *RateLimiter) getIdentifier(c echo.Context) string {
	switch rl.config.Strategy {
	case "ip":
		return c.RealIP()
	case "user":
		if user := c.Get("user"); user != nil {
			if token, ok := user.(*jwt.Token); ok {
				if claims, ok := token.Claims.(jwt.MapClaims); ok {
					if userID, ok := claims["sub"].(string); ok {
						return userID
					}
				}
			}
		}
		return c.RealIP()
	case "global":
		return "global"
	default:
		return c.RealIP()
	}
}

func (rl *RateLimiter) Limit() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			identifier := rl.getIdentifier(c)
			limiter := rl.getLimiter(identifier)

			if !limiter.Allow() {
				limit := limiter.Limit()
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

func (rl *RateLimiter) LimitRoute(config RateLimiterConfig) echo.MiddlewareFunc {
	routeLimiter := NewRateLimiterWithConfig(config)
	return routeLimiter.Limit()
}

func (rl *RateLimiter) CleanupTask(interval time.Duration, maxIdleTime time.Duration) {
}
