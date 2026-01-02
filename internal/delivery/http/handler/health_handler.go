package handler

import (
	"context"
	"net/http"
	"runtime"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/regiwitanto/auth-service/config"
	"github.com/regiwitanto/auth-service/internal/pkg/logger"
	"github.com/regiwitanto/auth-service/internal/pkg/metrics"
	"github.com/regiwitanto/auth-service/internal/repository"
)

type HealthHandler struct {
	userRepo    repository.UserRepository
	redisClient repository.RedisClient
	config      *config.Config
	startTime   time.Time
}

func NewHealthHandler(userRepo repository.UserRepository, redis repository.RedisClient, cfg *config.Config) *HealthHandler {
	// Record system info metrics
	metrics.SystemGauges.WithLabelValues("goroutines").Set(float64(runtime.NumGoroutine()))
	metrics.SystemGauges.WithLabelValues("cpu_cores").Set(float64(runtime.NumCPU()))

	return &HealthHandler{
		userRepo:    userRepo,
		redisClient: redis,
		config:      cfg,
		startTime:   time.Now(),
	}
}

func (h *HealthHandler) RegisterRoutes(e *echo.Echo) {
	e.GET("/health", h.HealthCheck)
	e.GET("/health/detailed", h.DetailedHealthCheck)
}

func (h *HealthHandler) HealthCheck(c echo.Context) error {
	return c.JSON(http.StatusOK, map[string]string{
		"status":  "OK",
		"message": "Auth service is healthy",
	})
}

func (h *HealthHandler) DetailedHealthCheck(c echo.Context) error {
	// Use short timeout for health checks
	ctx, cancel := context.WithTimeout(c.Request().Context(), 3*time.Second)
	defer cancel()

	// Check database connectivity
	dbStatus := "UP"
	var dbError string

	if h.userRepo != nil {
		if err := h.userRepo.Ping(ctx); err != nil {
			dbStatus = "DOWN"
			dbError = err.Error()
			logger.Error("Health check: Database connectivity issue", logger.Err(err))
		}
	} else {
		dbStatus = "UNKNOWN"
		dbError = "Database connection not initialized"
	}

	// Check Redis connectivity
	redisStatus := "UP"
	var redisError string

	if h.redisClient != nil {
		if err := h.redisClient.Ping(ctx).Err(); err != nil {
			redisStatus = "DOWN"
			redisError = err.Error()
			logger.Error("Health check: Redis connectivity issue", logger.Err(err))
		}
	} else {
		redisStatus = "UNKNOWN"
		redisError = "Redis connection not initialized"
	}

	// Calculate uptime
	uptime := time.Since(h.startTime).String()

	// Update system metrics
	metrics.SystemGauges.WithLabelValues("goroutines").Set(float64(runtime.NumGoroutine()))

	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	metrics.SystemGauges.WithLabelValues("memory_alloc_bytes").Set(float64(m.Alloc))
	metrics.SystemGauges.WithLabelValues("memory_sys_bytes").Set(float64(m.Sys))

	response := map[string]interface{}{
		"status":      "OK",
		"message":     "Auth service detailed health status",
		"timestamp":   time.Now().Format(time.RFC3339),
		"uptime":      uptime,
		"version":     "1.0.0",
		"environment": h.config.Environment,
		"components": map[string]interface{}{
			"database": map[string]interface{}{
				"status": dbStatus,
				"error":  dbError,
			},
			"redis": map[string]interface{}{
				"status": redisStatus,
				"error":  redisError,
			},
		},
		"system": map[string]interface{}{
			"go_version":    runtime.Version(),
			"goroutines":    runtime.NumGoroutine(),
			"cpu_cores":     runtime.NumCPU(),
			"memory_alloc":  m.Alloc / 1024 / 1024, // MB
			"memory_system": m.Sys / 1024 / 1024,   // MB
		},
	}

	return c.JSON(http.StatusOK, response)
}
