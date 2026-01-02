package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/regiwitanto/auth-service/config"
	"github.com/regiwitanto/auth-service/internal/delivery/http/handler"
	customMiddleware "github.com/regiwitanto/auth-service/internal/delivery/http/middleware"
	"github.com/regiwitanto/auth-service/internal/pkg/logger"
	"github.com/regiwitanto/auth-service/internal/pkg/metrics"
	"github.com/regiwitanto/auth-service/internal/repository"
	"github.com/regiwitanto/auth-service/internal/usecase"
)

func main() {

	cfg, err := config.LoadConfig()
	if err != nil {
		// Initialize logger with default environment before config is available
		logger.Init("development")
		logger.Fatal("Failed to load configuration", logger.Err(err))
	}

	// Initialize logger with proper environment from config
	logger.Init(cfg.Environment)

	logger.Info("Starting auth service",
		logger.String("environment", cfg.Environment),
		logger.Int("port", cfg.Server.Port),
		logger.String("version", "1.0.0"))

	e := echo.New()

	// Configure Echo to use our structured logger
	e.Logger.SetOutput(logger.NewEchoLogger())

	// Use our custom Zap logger middleware instead of the default Echo logger
	e.Use(customMiddleware.ZapLoggerMiddleware())

	// Add Prometheus metrics middleware for all requests
	e.Use(customMiddleware.PrometheusMiddleware())

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
		logger.Fatal("Failed to connect to database", logger.Err(err))
	}

	redisClient, err := config.InitRedis(cfg)
	if err != nil {
		logger.Fatal("Failed to connect to Redis", logger.Err(err))
	}

	// Initialize repositories with monitoring
	userRepo := repository.NewUserRepository(db)
	tokenRepo := repository.NewTokenRepository(redisClient)

	// Set initial system metrics
	metrics.SystemGauges.WithLabelValues("goroutines").Set(float64(runtime.NumGoroutine()))
	metrics.SystemGauges.WithLabelValues("cpu_cores").Set(float64(runtime.NumCPU()))

	// Schedule periodic collection of token metrics
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				count, err := tokenRepo.GetTokenCount(context.Background())
				if err != nil {
					logger.Error("Failed to get token count", logger.Err(err))
				} else {
					metrics.ActiveTokensGauge.Set(float64(count))
				}

				// Update system metrics
				metrics.SystemGauges.WithLabelValues("goroutines").Set(float64(runtime.NumGoroutine()))

				var m runtime.MemStats
				runtime.ReadMemStats(&m)
				metrics.SystemGauges.WithLabelValues("memory_alloc_bytes").Set(float64(m.Alloc))
				metrics.SystemGauges.WithLabelValues("memory_sys_bytes").Set(float64(m.Sys))
			}
		}
	}()

	authUseCase := usecase.NewAuthUseCase(userRepo, tokenRepo, cfg)

	// Initialize handlers
	healthHandler := handler.NewHealthHandler(userRepo, redisClient, &cfg)
	authHandler := handler.NewAuthHandler(authUseCase, &cfg)
	adminHandler := handler.NewAdminHandler(authUseCase, &cfg)
	metricsHandler := handler.NewMetricsHandler()

	healthHandler.RegisterRoutes(e)
	authHandler.RegisterRoutes(e)
	adminHandler.RegisterRoutes(e)
	metricsHandler.RegisterRoutes(e) // Register metrics endpoint
	go func() {
		if err := e.Start(fmt.Sprintf(":%d", cfg.Server.Port)); err != nil {
			logger.Info("Shutting down the server", logger.Err(err))
		}
	}()

	// Set up graceful shutdown with context
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)
	<-quit

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := e.Shutdown(ctx); err != nil {
		logger.Fatal("Server forced to shutdown", logger.Err(err))
	}

	logger.Info("Server gracefully stopped")
}
