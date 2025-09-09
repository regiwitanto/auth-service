package testutil

import (
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/regiwitanto/auth-service/config"
)

func CreateTestConfig() (*config.Config, error) {
	return &config.Config{
		Server: config.ServerConfig{
			Port: 8080,
		},
		Database: config.DatabaseConfig{
			Host:     "localhost",
			Port:     5432,
			DBName:   "auth_test_db",
			User:     "test_user",
			Password: "test_password",
			SSLMode:  "disable",
		},
		Redis: config.RedisConfig{
			Host:     "localhost",
			Port:     6379,
			Password: "",
			DB:       0,
		},
		JWT: config.JWTConfig{
			Secret:         "test_secret_key",
			AccessTokenExp: 60 * time.Minute,
		},
	}, nil
}

func CreateTestToken(userID, username, role string, expiration time.Duration) (string, error) {
	cfg, err := CreateTestConfig()
	if err != nil {
		return "", err
	}

	// Create the Claims
	claims := jwt.MapClaims{
		"sub":  userID,
		"name": username,
		"role": role,
		"exp":  time.Now().Add(expiration).Unix(),
	}

	// Create token with claims
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Generate encoded token
	tokenString, err := token.SignedString([]byte(cfg.JWT.Secret))
	if err != nil {
		return "", err
	}

	return tokenString, nil
}
