package config

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/joho/godotenv"
	"github.com/redis/go-redis/v9"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

type Config struct {
	Server      ServerConfig
	Database    DatabaseConfig
	Redis       RedisConfig
	JWT         JWTConfig
	Environment string
	RateLimit   RateLimitConfig
}

type ServerConfig struct {
	Port    int
	BaseURL string
}

type DatabaseConfig struct {
	Host     string
	Port     int
	User     string
	Password string
	DBName   string
	SSLMode  string
}

type RedisConfig struct {
	Host     string
	Port     int
	Password string
	DB       int
}

type JWTConfig struct {
	Secret          string
	AccessTokenExp  time.Duration
	RefreshTokenExp time.Duration
}

type RateLimitConfig struct {
	Enabled             bool
	LoginRequestsPerMin int
	LoginBurstSize      int
	APIRequestsPerMin   int
	APIBurstSize        int
}

func LoadConfig() (config Config, err error) {
	// Load .env file if it exists
	err = godotenv.Load()
	if err != nil && !os.IsNotExist(err) {
		// Only report error if file exists but couldn't be loaded
		// Not finding .env is ok
		fmt.Printf("Warning: error loading .env file: %v\n", err)
	}

	// Using os.Getenv directly with fallback values
	// Server configuration
	serverPort, err := strconv.Atoi(getEnvWithDefault("SERVER_PORT", "8080"))
	if err != nil {
		serverPort = 8080
	}

	// Database defaults
	dbPort, err := strconv.Atoi(getEnvWithDefault("DB_PORT", "5432"))
	if err != nil {
		dbPort = 5432
	}

	// Redis defaults
	redisPort, err := strconv.Atoi(getEnvWithDefault("REDIS_PORT", "6379"))
	if err != nil {
		redisPort = 6379
	}

	redisDB, err := strconv.Atoi(getEnvWithDefault("REDIS_DB", "0"))
	if err != nil {
		redisDB = 0
	}

	// Server configuration
	// Server configuration is already set above

	// Set config values from environment variables
	config.Server.Port = serverPort
	config.Server.BaseURL = getEnvWithDefault("SERVER_BASE_URL", "http://localhost:8080")

	// Database configuration
	config.Database.Host = getEnvWithDefault("DB_HOST", "localhost")
	config.Database.Port = dbPort
	config.Database.User = getEnvWithDefault("DB_USER", "postgres")
	config.Database.Password = getEnvWithDefault("DB_PASSWORD", "postgres")
	config.Database.DBName = getEnvWithDefault("DB_NAME", "auth_service")
	config.Database.SSLMode = getEnvWithDefault("DB_SSLMODE", "disable")

	// Redis configuration
	config.Redis.Host = getEnvWithDefault("REDIS_HOST", "localhost")
	config.Redis.Port = redisPort
	config.Redis.Password = getEnvWithDefault("REDIS_PASSWORD", "")
	config.Redis.DB = redisDB

	// JWT configuration
	config.JWT.Secret = getEnvWithDefault("JWT_SECRET", "super_secret_key")

	accessExp, err := time.ParseDuration(getEnvWithDefault("JWT_ACCESS_EXP", "15m"))
	if err != nil {
		accessExp = 15 * time.Minute
	}
	config.JWT.AccessTokenExp = accessExp

	refreshExp, err := time.ParseDuration(getEnvWithDefault("JWT_REFRESH_EXP", "7d"))
	if err != nil {
		refreshExp = 7 * 24 * time.Hour // 7 days
	}
	config.JWT.RefreshTokenExp = refreshExp

	// Environment configuration
	config.Environment = getEnvWithDefault("APP_ENV", "development")

	// Rate limit configuration
	config.RateLimit.Enabled = getEnvWithDefault("RATE_LIMIT_ENABLED", "true") == "true"

	loginReqPerMin, err := strconv.Atoi(getEnvWithDefault("RATE_LIMIT_LOGIN_REQUESTS", "10"))
	if err != nil {
		loginReqPerMin = 10
	}
	config.RateLimit.LoginRequestsPerMin = loginReqPerMin

	loginBurst, err := strconv.Atoi(getEnvWithDefault("RATE_LIMIT_LOGIN_BURST", "3"))
	if err != nil {
		loginBurst = 3
	}
	config.RateLimit.LoginBurstSize = loginBurst

	apiReqPerMin, err := strconv.Atoi(getEnvWithDefault("RATE_LIMIT_API_REQUESTS", "60"))
	if err != nil {
		apiReqPerMin = 60
	}
	config.RateLimit.APIRequestsPerMin = apiReqPerMin

	apiBurst, err := strconv.Atoi(getEnvWithDefault("RATE_LIMIT_API_BURST", "10"))
	if err != nil {
		apiBurst = 10
	}
	config.RateLimit.APIBurstSize = apiBurst

	return config, nil
}

func InitDB(config Config) (*gorm.DB, error) {
	dsn := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		config.Database.Host,
		config.Database.Port,
		config.Database.User,
		config.Database.Password,
		config.Database.DBName,
		config.Database.SSLMode,
	)

	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		return nil, err
	}

	return db, nil
}

func InitRedis(config Config) (*redis.Client, error) {
	client := redis.NewClient(&redis.Options{
		Addr:     fmt.Sprintf("%s:%d", config.Redis.Host, config.Redis.Port),
		Password: config.Redis.Password,
		DB:       config.Redis.DB,
	})

	// Test the connection
	_, err := client.Ping(context.Background()).Result()
	return client, err
}

// getEnvWithDefault returns environment variable value or default if not set
func getEnvWithDefault(key, defaultValue string) string {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	return value
}

// LoadTestConfig loads configuration for testing environments
func LoadTestConfig() (Config, error) {
	// Set test environment variables if not already set
	if os.Getenv("TEST_DB_NAME") == "" {
		os.Setenv("DB_HOST", getEnvWithDefault("TEST_DB_HOST", "localhost"))
		os.Setenv("DB_PORT", getEnvWithDefault("TEST_DB_PORT", "5432"))
		os.Setenv("DB_USER", getEnvWithDefault("TEST_DB_USER", "postgres"))
		os.Setenv("DB_PASSWORD", getEnvWithDefault("TEST_DB_PASSWORD", "postgres"))
		os.Setenv("DB_NAME", getEnvWithDefault("TEST_DB_NAME", "auth_service_test"))
		os.Setenv("DB_SSLMODE", getEnvWithDefault("TEST_DB_SSLMODE", "disable"))

		os.Setenv("REDIS_HOST", getEnvWithDefault("TEST_REDIS_HOST", "localhost"))
		os.Setenv("REDIS_PORT", getEnvWithDefault("TEST_REDIS_PORT", "6379"))
		os.Setenv("REDIS_PASSWORD", getEnvWithDefault("TEST_REDIS_PASSWORD", ""))
		os.Setenv("REDIS_DB", getEnvWithDefault("TEST_REDIS_DB", "1"))

		os.Setenv("JWT_SECRET", getEnvWithDefault("TEST_JWT_SECRET", "test_secret_key"))
		os.Setenv("JWT_ACCESS_EXP", getEnvWithDefault("TEST_JWT_ACCESS_EXP", "5m"))
		os.Setenv("JWT_REFRESH_EXP", getEnvWithDefault("TEST_JWT_REFRESH_EXP", "1h"))
	}

	// Use the standard LoadConfig to load the config with the test values
	return LoadConfig()
}
