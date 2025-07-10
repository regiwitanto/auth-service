package middleware

import (
	"net/http"

	"github.com/golang-jwt/jwt"
	"github.com/labstack/echo/v4"
)

// Role constants
const (
	RoleUser  = "user"
	RoleAdmin = "admin"
)

// RBACMiddleware provides role-based access control
type RBACMiddleware struct {
	// Add any dependencies here if needed
}

// NewRBACMiddleware creates a new RBAC middleware instance
func NewRBACMiddleware() *RBACMiddleware {
	return &RBACMiddleware{}
}

// RequireRole creates a middleware that restricts access to users with the specified roles
func (m *RBACMiddleware) RequireRole(roles ...string) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			// The JWT middleware should have already validated the token
			// and put it in the context
			user := c.Get("user")
			if user == nil {
				return echo.NewHTTPError(http.StatusUnauthorized, "Missing or invalid token")
			}

			// Extract token
			token, ok := user.(*jwt.Token)
			if !ok {
				return echo.NewHTTPError(http.StatusUnauthorized, "Invalid token format")
			}

			// Extract claims
			claims, ok := token.Claims.(jwt.MapClaims)
			if !ok {
				return echo.NewHTTPError(http.StatusUnauthorized, "Invalid token claims")
			}

			// Extract user role
			role, ok := claims["role"].(string)
			if !ok {
				return echo.NewHTTPError(http.StatusForbidden, "Role information missing")
			}

			// Check if user has any of the required roles
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

			// User has required role, proceed to the handler
			return next(c)
		}
	}
}

// IsAdmin is a shorthand middleware to restrict access to admin users only
func (m *RBACMiddleware) IsAdmin() echo.MiddlewareFunc {
	return m.RequireRole(RoleAdmin)
}

// IsUser is a shorthand middleware to restrict access to authenticated users (any role)
func (m *RBACMiddleware) IsUser() echo.MiddlewareFunc {
	return m.RequireRole(RoleUser, RoleAdmin)
}
