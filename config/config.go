package config

import (
	"context"
	"fmt"
	"time"

	"github.com/joho/godotenv"
	"github.com/redis/go-redis/v9"
	"github.com/spf13/viper"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// Config stores all configuration of the application.
// The values are read by viper from a config file or environment variable.
type Config struct {
	Server   ServerConfig
	Database DatabaseConfig
	Redis    RedisConfig
	JWT      JWTConfig
}

// ServerConfig stores server related configuration
type ServerConfig struct {
	Port int
}

// DatabaseConfig stores database connection related configuration
type DatabaseConfig struct {
	Host     string
	Port     int
	User     string
	Password string
	DBName   string
	SSLMode  string
}

// RedisConfig stores Redis connection related configuration
type RedisConfig struct {
	Host     string
	Port     int
	Password string
	DB       int
}

// JWTConfig stores JWT related configuration
type JWTConfig struct {
	Secret          string
	AccessTokenExp  time.Duration
	RefreshTokenExp time.Duration
}

// LoadConfig reads configuration from file or environment variables.
func LoadConfig() (config Config, err error) {
	// Load .env file if it exists
	godotenv.Load()

	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath("./config")
	viper.AddConfigPath(".")
	viper.AutomaticEnv()

	// Set default values
	// Server defaults
	viper.SetDefault("SERVER_PORT", 3007)

	// Database defaults
	viper.SetDefault("DB_HOST", "localhost")
	viper.SetDefault("DB_PORT", 5432)
	viper.SetDefault("DB_USER", "postgres")
	viper.SetDefault("DB_PASSWORD", "postgres")
	viper.SetDefault("DB_NAME", "auth_service")
	viper.SetDefault("DB_SSLMODE", "disable")

	// Redis defaults
	viper.SetDefault("REDIS_HOST", "localhost")
	viper.SetDefault("REDIS_PORT", 6379)
	viper.SetDefault("REDIS_PASSWORD", "")
	viper.SetDefault("REDIS_DB", 0)

	// JWT defaults
	viper.SetDefault("JWT_SECRET", "super_secret_key")
	viper.SetDefault("JWT_ACCESS_EXP", "15m")
	viper.SetDefault("JWT_REFRESH_EXP", "7d")

	// Read configuration
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return config, err
		}
		// Config file not found, will use env vars and defaults
	}

	// Server configuration
	config.Server.Port = viper.GetInt("SERVER_PORT")

	// Database configuration
	config.Database.Host = viper.GetString("DB_HOST")
	config.Database.Port = viper.GetInt("DB_PORT")
	config.Database.User = viper.GetString("DB_USER")
	config.Database.Password = viper.GetString("DB_PASSWORD")
	config.Database.DBName = viper.GetString("DB_NAME")
	config.Database.SSLMode = viper.GetString("DB_SSLMODE")

	// Redis configuration
	config.Redis.Host = viper.GetString("REDIS_HOST")
	config.Redis.Port = viper.GetInt("REDIS_PORT")
	config.Redis.Password = viper.GetString("REDIS_PASSWORD")
	config.Redis.DB = viper.GetInt("REDIS_DB")

	// JWT configuration
	config.JWT.Secret = viper.GetString("JWT_SECRET")

	accessExp, err := time.ParseDuration(viper.GetString("JWT_ACCESS_EXP"))
	if err != nil {
		accessExp = 15 * time.Minute
	}
	config.JWT.AccessTokenExp = accessExp

	refreshExp, err := time.ParseDuration(viper.GetString("JWT_REFRESH_EXP"))
	if err != nil {
		refreshExp = 7 * 24 * time.Hour // 7 days
	}
	config.JWT.RefreshTokenExp = refreshExp

	return config, nil
}

// InitDB initializes the database connection
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

	// You could add auto-migration here if needed
	// db.AutoMigrate(&model.User{})

	return db, nil
}

// InitRedis initializes the Redis client
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
