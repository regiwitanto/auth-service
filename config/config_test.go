package config

import (
	"os"
	"strconv"
	"time"
)

// LoadTestConfig loads configuration for test environment
func LoadTestConfig() (Config, error) {
	// Default test configuration
	config := Config{
		Server: ServerConfig{
			Port: 3007,
		},
		Database: DatabaseConfig{
			Host:     getEnv("TEST_DB_HOST", "localhost"),
			Port:     getEnvAsInt("TEST_DB_PORT", 5432),
			User:     getEnv("TEST_DB_USER", "postgres"),
			Password: getEnv("TEST_DB_PASSWORD", "postgres"),
			DBName:   getEnv("TEST_DB_NAME", "auth_service_test"),
			SSLMode:  getEnv("TEST_DB_SSLMODE", "disable"),
		},
		Redis: RedisConfig{
			Host:     getEnv("TEST_REDIS_HOST", "localhost"),
			Port:     getEnvAsInt("TEST_REDIS_PORT", 6379),
			Password: getEnv("TEST_REDIS_PASSWORD", ""),
			DB:       getEnvAsInt("TEST_REDIS_DB", 1),
		},
		JWT: JWTConfig{
			Secret:          getEnv("TEST_JWT_SECRET", "test_secret_key"),
			AccessTokenExp:  getEnvAsDuration("TEST_JWT_ACCESS_EXP", 15*time.Minute),
			RefreshTokenExp: getEnvAsDuration("TEST_JWT_REFRESH_EXP", 24*time.Hour),
		},
	}

	return config, nil
}

// Helper functions

// getEnv gets the environment variable or returns a default value
func getEnv(key, defaultValue string) string {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	return value
}

// getEnvAsInt gets the environment variable as an integer or returns a default value
func getEnvAsInt(key string, defaultValue int) int {
	valueStr := getEnv(key, "")
	if valueStr == "" {
		return defaultValue
	}
	value, err := strconv.Atoi(valueStr)
	if err != nil {
		return defaultValue
	}
	return value
}

// getEnvAsDuration gets the environment variable as a duration or returns a default value
func getEnvAsDuration(key string, defaultValue time.Duration) time.Duration {
	valueStr := getEnv(key, "")
	if valueStr == "" {
		return defaultValue
	}
	value, err := time.ParseDuration(valueStr)
	if err != nil {
		return defaultValue
	}
	return value
}
