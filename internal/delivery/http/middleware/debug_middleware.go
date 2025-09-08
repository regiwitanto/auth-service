package middleware

import (
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/labstack/echo/v4"
)

// DebugMiddleware logs debug information for requests
type DebugMiddleware struct {
	logger *log.Logger
}

// NewDebugMiddleware creates a new debug middleware
func NewDebugMiddleware() *DebugMiddleware {
	return &DebugMiddleware{
		logger: log.New(os.Stdout, "[DEBUG] ", log.LstdFlags),
	}
}

// LogAuthHeader logs the authorization header for debugging
func (m *DebugMiddleware) LogAuthHeader() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			authHeader := c.Request().Header.Get("Authorization")
			if authHeader != "" {
				m.logger.Printf("Original Auth Header: %s", authHeader)

				// Parse the header
				if strings.HasPrefix(authHeader, "Bearer ") {
					tokenStr := authHeader[7:]
					m.logger.Printf("Token length: %d", len(tokenStr))

					// Check if there are any problematic characters
					m.logger.Printf("First 20 chars: %q", tokenStr[:min(20, len(tokenStr))])

					// Check if we can decode the header part
					parts := strings.Split(tokenStr, ".")
					if len(parts) == 3 {
						m.logger.Printf("Header part: %s", parts[0])

						// Try to decode base64
						_, err := base64.RawURLEncoding.DecodeString(parts[0])
						if err != nil {
							m.logger.Printf("Base64 decoding error: %v", err)

							// Try standard base64 too
							_, err = base64.StdEncoding.DecodeString(parts[0])
							if err != nil {
								m.logger.Printf("Standard base64 decoding error: %v", err)
							}
						}
					} else {
						m.logger.Printf("Token doesn't have 3 parts: %d parts", len(parts))
					}

					// Set clean token
					cleanToken := strings.TrimSpace(tokenStr)
					c.Request().Header.Set("Authorization", fmt.Sprintf("Bearer %s", cleanToken))
					m.logger.Printf("Cleaned Token: Bearer %s", cleanToken)
				}
			} else {
				m.logger.Printf("No Authorization header found")
			}

			return next(c)
		}
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
