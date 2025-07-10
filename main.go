package main

import (
	"fmt"
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/regiwitanto/auth-service/config"
	"github.com/regiwitanto/auth-service/internal/delivery/http/handler"
	customMiddleware "github.com/regiwitanto/auth-service/internal/delivery/http/middleware"
	"github.com/regiwitanto/auth-service/internal/repository"
	"github.com/regiwitanto/auth-service/internal/usecase"
)

func main() {
	// Load configuration
	cfg, err := config.LoadConfig()
	if err != nil {
		panic(fmt.Sprintf("Failed to load configuration: %v", err))
	}

	// Initialize Echo
	e := echo.New()

	// Middleware
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())
	e.Use(middleware.CORS())

	// Initialize database
	db, err := config.InitDB(cfg)
	if err != nil {
		panic(fmt.Sprintf("Failed to connect to database: %v", err))
	}

	// Initialize Redis
	redisClient, err := config.InitRedis(cfg)
	if err != nil {
		panic(fmt.Sprintf("Failed to connect to Redis: %v", err))
	}

	// Initialize repositories
	userRepo := repository.NewUserRepository(db)
	tokenRepo := repository.NewTokenRepository(redisClient)

	// Initialize usecases
	authUseCase := usecase.NewAuthUseCase(userRepo, tokenRepo, cfg)

	// Initialize handlers
	authHandler := handler.NewAuthHandler(authUseCase)
	adminHandler := handler.NewAdminHandler(authUseCase)

	// Initialize middleware
	rbacMiddleware := customMiddleware.NewRBACMiddleware()

	// Routes
	// Health check
	e.GET("/health", func(c echo.Context) error {
		return c.JSON(http.StatusOK, map[string]string{
			"status":  "OK",
			"message": "Auth service is healthy",
		})
	})

	// API routes
	api := e.Group("/api/v1")

	// Auth routes (public)
	auth := api.Group("/auth")
	auth.POST("/register", authHandler.Register)
	auth.POST("/login", authHandler.Login)
	auth.POST("/refresh", authHandler.RefreshToken)
	auth.POST("/logout", authHandler.Logout)

	// JWT middleware for protected routes
	jwtMiddleware := middleware.JWTWithConfig(middleware.JWTConfig{
		SigningKey: []byte(cfg.JWT.Secret),
	})

	// User routes (authenticated users only)
	user := api.Group("/user")
	user.Use(jwtMiddleware)
	user.Use(rbacMiddleware.IsUser())
	user.GET("/me", authHandler.GetUserProfile)

	// Admin routes (admin only)
	admin := api.Group("/admin")
	admin.Use(jwtMiddleware)
	admin.Use(rbacMiddleware.IsAdmin())
	admin.GET("/users", adminHandler.GetAllUsers)
	admin.GET("/stats", adminHandler.GetSystemStats)

	// Start server
	e.Logger.Fatal(e.Start(fmt.Sprintf(":%d", cfg.Server.Port)))
}
