package middleware

import (
	"github.com/labstack/echo/v4"
	"github.com/regiwitanto/auth-service/internal/pkg/logger"
	"time"
)

// ZapLoggerMiddleware is a middleware that logs HTTP requests using zap
func ZapLoggerMiddleware() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			req := c.Request()
			res := c.Response()
			start := time.Now()
			
			err := next(c)
			
			stop := time.Now()
			latency := stop.Sub(start)
			
			status := res.Status
			method := req.Method
			path := req.URL.Path
			if path == "" {
				path = "/"
			}
			
			fields := []logger.Field{
				logger.String("remote_ip", c.RealIP()),
				logger.String("method", method),
				logger.String("path", path),
				logger.Int("status", status),
				logger.String("latency", latency.String()),
				logger.String("user_agent", req.UserAgent()),
				logger.Int64("bytes_out", res.Size),
			}
			
			id := req.Header.Get(echo.HeaderXRequestID)
			if id != "" {
				fields = append(fields, logger.String("request_id", id))
			}
			
			// Log the request with appropriate level based on status code
			msg := "Request completed"
			if err != nil {
				fields = append(fields, logger.Err(err))
				msg = "Request error"
			}
			
			switch {
			case status >= 500:
				logger.Error(msg, fields...)
			case status >= 400:
				logger.Warn(msg, fields...)
			default:
				logger.Info(msg, fields...)
			}
			
			return err
		}
	}
}
