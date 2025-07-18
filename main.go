package main

import (
	"fmt"
	"net/http"
	"time"

	echojwt "github.com/labstack/echo-jwt/v4"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/regiwitanto/auth-service/config"
	"github.com/regiwitanto/auth-service/internal/delivery/http/handler"
	customMiddleware "github.com/regiwitanto/auth-service/internal/delivery/http/middleware"
	"github.com/regiwitanto/auth-service/internal/repository"
	"github.com/regiwitanto/auth-service/internal/usecase"
)

func main() {
	cfg, err := config.LoadConfig()
	if err != nil {
		panic(fmt.Sprintf("Failed to load configuration: %v", err))
	}

	e := echo.New()

	e.Use(middleware.Logger())
	e.Use(middleware.Recover())
	e.Use(middleware.CORS())

	db, err := config.InitDB(cfg)
	if err != nil {
		panic(fmt.Sprintf("Failed to connect to database: %v", err))
	}

	redisClient, err := config.InitRedis(cfg)
	if err != nil {
		panic(fmt.Sprintf("Failed to connect to Redis: %v", err))
	}

	userRepo := repository.NewUserRepository(db)
	tokenRepo := repository.NewTokenRepository(redisClient)

	authUseCase := usecase.NewAuthUseCase(userRepo, tokenRepo, cfg)

	authHandler := handler.NewAuthHandler(authUseCase)
	adminHandler := handler.NewAdminHandler(authUseCase)

	rbacMiddleware := customMiddleware.NewRBACMiddleware()

	var authRateLimiter, loginRateLimiter *customMiddleware.RateLimiter

	// Configure rate limiters based on environment
	if !cfg.RateLimit.Enabled || cfg.Environment == "development" {
		// In development mode or when rate limiting is disabled, use very permissive settings
		authRateLimiter = customMiddleware.NewRateLimiterWithConfig(customMiddleware.RateLimiterConfig{
			Requests:  1000,
			Window:    time.Minute,
			BurstSize: 50,
			Strategy:  "ip",
		})

		loginRateLimiter = customMiddleware.NewRateLimiterWithConfig(customMiddleware.RateLimiterConfig{
			Requests:  1000,
			Window:    time.Minute,
			BurstSize: 50,
			Strategy:  "ip",
		})

		fmt.Println("Rate limiting is set to development mode (1000 req/min)")
	} else {
		// In production, use the configured settings
		authRateLimiter = customMiddleware.NewRateLimiterWithConfig(customMiddleware.RateLimiterConfig{
			Requests:  cfg.RateLimit.APIRequestsPerMin,
			Window:    time.Minute,
			BurstSize: cfg.RateLimit.APIBurstSize,
			Strategy:  "ip",
		})

		loginRateLimiter = customMiddleware.NewRateLimiterWithConfig(customMiddleware.RateLimiterConfig{
			Requests:  cfg.RateLimit.LoginRequestsPerMin,
			Window:    time.Minute,
			BurstSize: cfg.RateLimit.LoginBurstSize,
			Strategy:  "ip",
		})

		fmt.Printf("Rate limiting is set to production mode (Login: %d req/min, API: %d req/min)\n",
			cfg.RateLimit.LoginRequestsPerMin,
			cfg.RateLimit.APIRequestsPerMin)
	}

	// Health check endpoint
	e.GET("/health", func(c echo.Context) error {
		return c.JSON(http.StatusOK, map[string]string{
			"status":  "OK",
			"message": "Auth service is healthy",
		})
	})

	api := e.Group("/api/v1")

	auth := api.Group("/auth")

	if cfg.RateLimit.Enabled {
		auth.POST("/register", authHandler.Register, authRateLimiter.Limit())
		auth.POST("/login", authHandler.Login, loginRateLimiter.Limit())
		auth.POST("/refresh", authHandler.RefreshToken, authRateLimiter.Limit())
		auth.POST("/logout", authHandler.Logout, authRateLimiter.Limit())
	} else {
		auth.POST("/register", authHandler.Register)
		auth.POST("/login", authHandler.Login)
		auth.POST("/refresh", authHandler.RefreshToken)
		auth.POST("/logout", authHandler.Logout)
		fmt.Println("Rate limiting is disabled")
	}
	// JWT middleware for protected routes
	jwtConfig := echojwt.Config{
		SigningKey:  []byte(cfg.JWT.Secret),
		TokenLookup: "header:Authorization,query:token",
		ErrorHandler: func(c echo.Context, err error) error {
			return echo.NewHTTPError(http.StatusUnauthorized,
				fmt.Sprintf("JWT authentication failed: %v", err))
		},
	}
	jwtMiddleware := echojwt.WithConfig(jwtConfig)

	user := api.Group("/user")
	user.Use(jwtMiddleware)
	user.Use(rbacMiddleware.IsUser())
	user.GET("/me", authHandler.GetUserProfile)

	admin := api.Group("/admin")
	admin.Use(jwtMiddleware)
	admin.Use(rbacMiddleware.IsAdmin())
	admin.GET("/users", adminHandler.GetAllUsers)
	admin.GET("/stats", adminHandler.GetSystemStats)

	e.Logger.Fatal(e.Start(fmt.Sprintf(":%d", cfg.Server.Port)))
}
