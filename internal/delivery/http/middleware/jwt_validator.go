package middleware

import (
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt"
	"github.com/labstack/echo/v4"
	"github.com/regiwitanto/auth-service/config"
)

// JWTValidatorMiddleware is a custom middleware for validating JWT tokens
type JWTValidatorMiddleware struct {
	config *config.Config
}

// NewJWTValidatorMiddleware creates a new JWT validator middleware
func NewJWTValidatorMiddleware(config *config.Config) *JWTValidatorMiddleware {
	return &JWTValidatorMiddleware{
		config: config,
	}
}

// ValidateToken manually processes the JWT token with more careful handling
func (m *JWTValidatorMiddleware) ValidateToken() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			// First check if this route should be protected
			if shouldSkip(c) {
				return next(c)
			}

			// Get the Authorization header
			authHeader := c.Request().Header.Get("Authorization")

			// If empty, check query param
			if authHeader == "" {
				tokenParam := c.QueryParam("token")
				if tokenParam == "" {
					return echo.NewHTTPError(http.StatusUnauthorized, "Missing authorization token")
				}
				authHeader = "Bearer " + tokenParam
			}

			// Clean up the header
			authHeader = strings.TrimSpace(authHeader)

			// Check format
			if !strings.HasPrefix(authHeader, "Bearer ") {
				return echo.NewHTTPError(http.StatusUnauthorized, "Invalid authorization format")
			}

			// Extract the token
			tokenString := strings.TrimSpace(authHeader[7:])

			// Parse and validate the token
			token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
				// Don't forget to validate the alg is what you expect
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, echo.NewHTTPError(http.StatusUnauthorized, "Invalid token signing method")
				}

				return []byte(m.config.JWT.Secret), nil
			})

			if err != nil {
				return echo.NewHTTPError(http.StatusUnauthorized, "Invalid token: "+err.Error())
			}

			if !token.Valid {
				return echo.NewHTTPError(http.StatusUnauthorized, "Token validation failed")
			}

			// Get the claims
			claims, ok := token.Claims.(jwt.MapClaims)
			if !ok {
				return echo.NewHTTPError(http.StatusUnauthorized, "Failed to extract token claims")
			}

			// Store the user ID and token in context
			userID, ok := claims["sub"].(string)
			if !ok {
				return echo.NewHTTPError(http.StatusUnauthorized, "Invalid user ID in token")
			}

			// Store token and user ID in context for later use
			c.Set("user", token)
			c.Set("userID", userID)

			return next(c)
		}
	}
}

// shouldSkip determines if the current route should skip authentication
func shouldSkip(c echo.Context) bool {
	// Skip auth for public routes
	path := c.Path()

	// List of paths that don't require authentication
	publicPaths := []string{
		"/api/v1/auth/login",
		"/api/v1/auth/register",
		"/api/v1/auth/forgot-password",
		"/api/v1/auth/reset-password",
		"/api/v1/health",
	}

	for _, p := range publicPaths {
		if path == p {
			return true
		}
	}

	return false
}
