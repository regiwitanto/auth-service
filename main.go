package main

import (
	"fmt"
	"net/http"
	"time"

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

	authRateLimiter := customMiddleware.NewRateLimiterWithConfig(customMiddleware.RateLimiterConfig{
		Requests:  60,
		Window:    time.Minute,
		BurstSize: 10,
		Strategy:  "ip",
	})

	loginRateLimiter := customMiddleware.NewRateLimiterWithConfig(customMiddleware.RateLimiterConfig{
		Requests:  10,
		Window:    time.Minute,
		BurstSize: 3,
		Strategy:  "ip",
	})

	e.GET("/health", func(c echo.Context) error {
		return c.JSON(http.StatusOK, map[string]string{
			"status":  "OK",
			"message": "Auth service is healthy",
		})
	})

	api := e.Group("/api/v1")

	auth := api.Group("/auth")
	auth.POST("/register", authHandler.Register, authRateLimiter.Limit())
	auth.POST("/login", authHandler.Login, loginRateLimiter.Limit())
	auth.POST("/refresh", authHandler.RefreshToken, authRateLimiter.Limit())
	auth.POST("/logout", authHandler.Logout, authRateLimiter.Limit())

	// JWT middleware for protected routes
	jwtMiddleware := middleware.JWTWithConfig(middleware.JWTConfig{
		SigningKey: []byte(cfg.JWT.Secret),
	})

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
