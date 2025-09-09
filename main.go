package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/regiwitanto/auth-service/config"
	"github.com/regiwitanto/auth-service/internal/delivery/http/handler"
	"github.com/regiwitanto/auth-service/internal/repository"
	"github.com/regiwitanto/auth-service/internal/usecase"
)

func initLogger() *log.Logger {
	return log.New(os.Stdout, "[AUTH-SERVICE] ", log.LstdFlags|log.Lshortfile)
}

func main() {
	logger := initLogger()

	cfg, err := config.LoadConfig()
	if err != nil {
		logger.Fatalf("Failed to load configuration: %v", err)
	}

	e := echo.New()

	e.Use(middleware.Logger())
	e.Use(middleware.Recover())

	e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOrigins:     []string{"https://*.example.com", "http://localhost:*"},
		AllowMethods:     []string{echo.GET, echo.PUT, echo.POST, echo.DELETE, echo.OPTIONS},
		AllowHeaders:     []string{echo.HeaderOrigin, echo.HeaderContentType, echo.HeaderAccept, echo.HeaderAuthorization},
		AllowCredentials: true,
		MaxAge:           300,
	}))

	// Add security headers
	e.Use(func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			c.Response().Header().Set("X-Content-Type-Options", "nosniff")
			c.Response().Header().Set("X-Frame-Options", "DENY")
			c.Response().Header().Set("X-XSS-Protection", "1; mode=block")
			c.Response().Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
			c.Response().Header().Set("Content-Security-Policy", "default-src 'self'")
			c.Response().Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
			c.Response().Header().Set("Cache-Control", "no-store")
			c.Response().Header().Set("Pragma", "no-cache")
			return next(c)
		}
	})

	db, err := config.InitDB(cfg)
	if err != nil {
		logger.Fatalf("Failed to connect to database: %v", err)
	}

	redisClient, err := config.InitRedis(cfg)
	if err != nil {
		logger.Fatalf("Failed to connect to Redis: %v", err)
	}

	userRepo := repository.NewUserRepository(db)
	tokenRepo := repository.NewTokenRepository(redisClient)

	authUseCase := usecase.NewAuthUseCase(userRepo, tokenRepo, cfg)

	healthHandler := handler.NewHealthHandler()
	authHandler := handler.NewAuthHandler(authUseCase, &cfg)
	adminHandler := handler.NewAdminHandler(authUseCase, &cfg)

	healthHandler.RegisterRoutes(e)
	authHandler.RegisterRoutes(e)
	adminHandler.RegisterRoutes(e)
	go func() {
		if err := e.Start(fmt.Sprintf(":%d", cfg.Server.Port)); err != nil {
			logger.Printf("Shutting down the server: %v", err)
		}
	}()

	// Set up graceful shutdown with context
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)
	<-quit

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := e.Shutdown(ctx); err != nil {
		logger.Fatalf("Server forced to shutdown: %v", err)
	}

	logger.Println("Server gracefully stopped")
}
