package mocks

import (
	"time"

	"github.com/regiwitanto/auth-service/config"
)

func MockConfig() *config.Config {
	return &config.Config{
		Environment: "test",
		Server: config.ServerConfig{
			Port:    8080,
			BaseURL: "http://localhost:8080",
		},
		JWT: config.JWTConfig{
			Secret:          "test_secret",
			AccessTokenExp:  15 * time.Minute,
			RefreshTokenExp: 24 * time.Hour,
		},
		RateLimit: config.RateLimitConfig{
			Enabled:             false,
			LoginRequestsPerMin: 10,
			LoginBurstSize:      3,
			APIRequestsPerMin:   60,
			APIBurstSize:        10,
		},
	}
}
