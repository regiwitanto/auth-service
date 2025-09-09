package middleware

import (
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt"
	"github.com/labstack/echo/v4"
	"github.com/regiwitanto/auth-service/config"
)

type JWTValidatorMiddleware struct {
	config *config.Config
}

func NewJWTValidatorMiddleware(config *config.Config) *JWTValidatorMiddleware {
	return &JWTValidatorMiddleware{
		config: config,
	}
}

func (m *JWTValidatorMiddleware) ValidateToken() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			if shouldSkip(c) {
				return next(c)
			}

			authHeader := c.Request().Header.Get("Authorization")

			if authHeader == "" {
				tokenParam := c.QueryParam("token")
				if tokenParam == "" {
					return echo.NewHTTPError(http.StatusUnauthorized, "Missing authorization token")
				}
				authHeader = "Bearer " + tokenParam
			}

			authHeader = strings.TrimSpace(authHeader)

			if !strings.HasPrefix(authHeader, "Bearer ") {
				return echo.NewHTTPError(http.StatusUnauthorized, "Invalid authorization format")
			}

			tokenString := strings.TrimSpace(authHeader[7:])
			token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
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

			claims, ok := token.Claims.(jwt.MapClaims)
			if !ok {
				return echo.NewHTTPError(http.StatusUnauthorized, "Failed to extract token claims")
			}

			userID, ok := claims["sub"].(string)
			if !ok {
				return echo.NewHTTPError(http.StatusUnauthorized, "Invalid user ID in token")
			}
			c.Set("user", token)
			c.Set("userID", userID)

			return next(c)
		}
	}
}

// shouldSkip determines if the current route should skip authentication
func shouldSkip(c echo.Context) bool {
	path := c.Path()

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
