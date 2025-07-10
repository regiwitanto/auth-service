package config

import (
	"os"
	"strconv"
	"time"
)

// NewTestConfig loads configuration for test environment
func NewTestConfig() (Config, error) {
	// Default test configuration
	config := Config{
		Server: ServerConfig{
			Port: 3007,
		},
		Database: DatabaseConfig{
			Host:     getTestEnv("TEST_DB_HOST", "localhost"),
			Port:     getTestEnvAsInt("TEST_DB_PORT", 5432),
			User:     getTestEnv("TEST_DB_USER", "postgres"),
			Password: getTestEnv("TEST_DB_PASSWORD", "postgres"),
			DBName:   getTestEnv("TEST_DB_NAME", "auth_service_test"),
			SSLMode:  getTestEnv("TEST_DB_SSLMODE", "disable"),
		},
		Redis: RedisConfig{
			Host:     getTestEnv("TEST_REDIS_HOST", "localhost"),
			Port:     getTestEnvAsInt("TEST_REDIS_PORT", 6379),
			Password: getTestEnv("TEST_REDIS_PASSWORD", ""),
			DB:       getTestEnvAsInt("TEST_REDIS_DB", 1),
		},
		JWT: JWTConfig{
			Secret:          getTestEnv("TEST_JWT_SECRET", "test_secret_key"),
			AccessTokenExp:  getTestEnvAsDuration("TEST_JWT_ACCESS_EXP", 15*time.Minute),
			RefreshTokenExp: getTestEnvAsDuration("TEST_JWT_REFRESH_EXP", 24*time.Hour),
		},
	}

	return config, nil
}

// Helper functions for test configuration

// getTestEnv gets the environment variable or returns a default value
func getTestEnv(key, defaultValue string) string {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	return value
}

// getTestEnvAsInt gets the environment variable as an integer or returns a default value
func getTestEnvAsInt(key string, defaultValue int) int {
	valueStr := getTestEnv(key, "")
	if valueStr == "" {
		return defaultValue
	}
	value, err := strconv.Atoi(valueStr)
	if err != nil {
		return defaultValue
	}
	return value
}

// getTestEnvAsDuration gets the environment variable as a duration or returns a default value
func getTestEnvAsDuration(key string, defaultValue time.Duration) time.Duration {
	valueStr := getTestEnv(key, "")
	if valueStr == "" {
		return defaultValue
	}
	value, err := time.ParseDuration(valueStr)
	if err != nil {
		return defaultValue
	}
	return value
}
