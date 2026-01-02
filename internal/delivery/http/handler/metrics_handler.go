package handler

import (
	"github.com/labstack/echo/v4"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/regiwitanto/auth-service/internal/pkg/logger"
)

type MetricsHandler struct{}

func NewMetricsHandler() *MetricsHandler {
	return &MetricsHandler{}
}

func (h *MetricsHandler) RegisterRoutes(e *echo.Echo) {
	// Create a separate route group for metrics
	metrics := e.Group("/metrics")

	// Expose Prometheus metrics endpoint
	metrics.GET("", func(c echo.Context) error {
		logger.Debug("Metrics endpoint accessed",
			logger.String("remote_ip", c.RealIP()))
		promhttp.Handler().ServeHTTP(c.Response(), c.Request())
		return nil
	})
}
