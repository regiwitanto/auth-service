package middleware

import (
	"strconv"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/regiwitanto/auth-service/internal/pkg/metrics"
)

// PrometheusMiddleware is a middleware that collects metrics for Prometheus
func PrometheusMiddleware() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			req := c.Request()
			res := c.Response()
			path := req.URL.Path
			start := time.Now()

			err := next(c)

			duration := time.Since(start).Seconds()
			status := strconv.Itoa(res.Status)
			method := req.Method

			// Count the request
			metrics.RequestCounter.WithLabelValues(path, method, status).Inc()

			// Record the request duration
			metrics.RequestDuration.WithLabelValues(path, method, status).Observe(duration)

			return err
		}
	}
}
