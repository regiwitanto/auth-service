package middleware_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/labstack/echo/v4"
	"github.com/regiwitanto/auth-service/internal/delivery/http/middleware"
	"github.com/stretchr/testify/assert"
)

func TestRequireRole(t *testing.T) {
	// Setup
	e := echo.New()
	rbac := middleware.NewRBACMiddleware()

	// Create test handler
	handler := func(c echo.Context) error {
		return c.String(http.StatusOK, "success")
	}

	tests := []struct {
		name          string
		roles         []string
		tokenRole     string
		expectedCode  int
		expectedError string
	}{
		{
			name:         "Allow admin access to admin resource",
			roles:        []string{"admin"},
			tokenRole:    "admin",
			expectedCode: http.StatusOK,
		},
		{
			name:          "Deny user access to admin resource",
			roles:         []string{"admin"},
			tokenRole:     "user",
			expectedCode:  http.StatusForbidden,
			expectedError: "Insufficient permissions",
		},
		{
			name:         "Allow admin access to user resource",
			roles:        []string{"user", "admin"},
			tokenRole:    "admin",
			expectedCode: http.StatusOK,
		},
		{
			name:         "Allow user access to user resource",
			roles:        []string{"user", "admin"},
			tokenRole:    "user",
			expectedCode: http.StatusOK,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Create middleware
			rbacMiddleware := rbac.RequireRole(tc.roles...)
			middlewareFunc := rbacMiddleware(handler)

			// Create request
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)

			// Set token with role claim
			token := jwt.New(jwt.SigningMethodHS256)
			claims := token.Claims.(jwt.MapClaims)
			claims["sub"] = "test-user-id"
			claims["name"] = "testuser"
			claims["role"] = tc.tokenRole
			claims["exp"] = time.Now().Add(time.Hour).Unix()
			c.Set("user", token)

			// Execute middleware
			err := middlewareFunc(c)

			// Assertions
			if tc.expectedError != "" {
				if he, ok := err.(*echo.HTTPError); ok {
					assert.Equal(t, tc.expectedCode, he.Code)
					assert.Contains(t, he.Message, tc.expectedError, "Error message should contain expected text")
				} else {
					t.Errorf("Expected HTTPError but got %T", err)
				}
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expectedCode, rec.Code)
				assert.Equal(t, "success", rec.Body.String())
			}
		})
	}
}

func TestIsAdmin(t *testing.T) {
	// Setup
	e := echo.New()
	rbac := middleware.NewRBACMiddleware()

	// Create test handler
	handler := func(c echo.Context) error {
		return c.String(http.StatusOK, "admin access")
	}

	// Create middleware
	adminMiddleware := rbac.IsAdmin()
	middlewareFunc := adminMiddleware(handler)

	t.Run("Allow admin access", func(t *testing.T) {
		// Create request
		req := httptest.NewRequest(http.MethodGet, "/admin", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		// Set token with admin role
		token := jwt.New(jwt.SigningMethodHS256)
		claims := token.Claims.(jwt.MapClaims)
		claims["sub"] = "admin-user-id"
		claims["name"] = "adminuser"
		claims["role"] = "admin"
		claims["exp"] = time.Now().Add(time.Hour).Unix()
		c.Set("user", token)

		// Execute middleware
		err := middlewareFunc(c)

		// Assert - admin should be allowed
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "admin access", rec.Body.String())
	})

	t.Run("Deny non-admin access", func(t *testing.T) {
		// Create request
		req := httptest.NewRequest(http.MethodGet, "/admin", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		// Set token with regular user role
		token := jwt.New(jwt.SigningMethodHS256)
		claims := token.Claims.(jwt.MapClaims)
		claims["sub"] = "regular-user-id"
		claims["name"] = "regularuser"
		claims["role"] = "user"
		claims["exp"] = time.Now().Add(time.Hour).Unix()
		c.Set("user", token)

		// Execute middleware
		err := middlewareFunc(c)

		// Assert - regular user should be denied
		httpError, ok := err.(*echo.HTTPError)
		assert.True(t, ok)
		assert.Equal(t, http.StatusForbidden, httpError.Code)
		assert.Contains(t, httpError.Message.(string), "Insufficient permissions")
	})

	t.Run("Deny when no token present", func(t *testing.T) {
		// Create request without token
		req := httptest.NewRequest(http.MethodGet, "/admin", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		// Execute middleware
		err := middlewareFunc(c)

		// Assert - should be denied
		httpError, ok := err.(*echo.HTTPError)
		assert.True(t, ok)
		assert.Equal(t, http.StatusUnauthorized, httpError.Code)
		assert.Equal(t, "Missing or invalid token", httpError.Message)
	})
}
