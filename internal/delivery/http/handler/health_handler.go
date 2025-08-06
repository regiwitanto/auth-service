package handler

import (
	"net/http"

	"github.com/labstack/echo/v4"
)

type HealthHandler struct{}

func NewHealthHandler() *HealthHandler {
	return &HealthHandler{}
}

// RegisterRoutes registers all health check routes
func (h *HealthHandler) RegisterRoutes(e *echo.Echo) {
	// Health check endpoint
	e.GET("/health", h.HealthCheck)
}

// HealthCheck returns the health status of the service
func (h *HealthHandler) HealthCheck(c echo.Context) error {
	return c.JSON(http.StatusOK, map[string]string{
		"status":  "OK",
		"message": "Auth service is healthy",
	})
}
