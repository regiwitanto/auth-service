package middleware

import (
	"net/http"

	"github.com/golang-jwt/jwt"
	"github.com/labstack/echo/v4"
)

const (
	RoleUser  = "user"
	RoleAdmin = "admin"
)

type RBACMiddleware struct{}

func NewRBACMiddleware() *RBACMiddleware {
	return &RBACMiddleware{}
}

func (m *RBACMiddleware) RequireRole(roles ...string) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			user := c.Get("user")
			if user == nil {
				return echo.NewHTTPError(http.StatusUnauthorized, "Missing or invalid token")
			}

			token, ok := user.(*jwt.Token)
			if !ok {
				return echo.NewHTTPError(http.StatusUnauthorized, "Invalid token format")
			}

			claims, ok := token.Claims.(jwt.MapClaims)
			if !ok {
				return echo.NewHTTPError(http.StatusUnauthorized, "Invalid token claims")
			}

			role, ok := claims["role"].(string)
			if !ok {
				return echo.NewHTTPError(http.StatusForbidden, "Role information missing")
			}
			hasRequiredRole := false
			for _, requiredRole := range roles {
				if role == requiredRole {
					hasRequiredRole = true
					break
				}
			}

			if !hasRequiredRole {
				return echo.NewHTTPError(http.StatusForbidden, "Insufficient permissions")
			}

			return next(c)
		}
	}
}

func (m *RBACMiddleware) IsAdmin() echo.MiddlewareFunc {
	return m.RequireRole(RoleAdmin)
}
func (m *RBACMiddleware) IsUser() echo.MiddlewareFunc {
	return m.RequireRole(RoleUser, RoleAdmin)
}
