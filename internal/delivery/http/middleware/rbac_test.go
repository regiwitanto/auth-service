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
					assert.Equal(t, tc.expectedError, he.Message)
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
		claims["role"] = "admin"
		c.Set("user", token)

		// Execute middleware
		err := middlewareFunc(c)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "admin access", rec.Body.String())
	})

	t.Run("Deny user access", func(t *testing.T) {
		// Create request
		req := httptest.NewRequest(http.MethodGet, "/admin", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		// Set token with user role
		token := jwt.New(jwt.SigningMethodHS256)
		claims := token.Claims.(jwt.MapClaims)
		claims["role"] = "user"
		c.Set("user", token)

		// Execute middleware
		err := middlewareFunc(c)
		if he, ok := err.(*echo.HTTPError); ok {
			assert.Equal(t, http.StatusForbidden, he.Code)
			assert.Equal(t, "Insufficient permissions", he.Message)
		} else {
			t.Errorf("Expected HTTPError but got %T", err)
		}
	})
}

func TestIsUser(t *testing.T) {
	// Setup
	e := echo.New()
	rbac := middleware.NewRBACMiddleware()

	// Create test handler
	handler := func(c echo.Context) error {
		return c.String(http.StatusOK, "user access")
	}

	// Create middleware
	userMiddleware := rbac.IsUser()
	middlewareFunc := userMiddleware(handler)

	tests := []struct {
		name          string
		role          string
		expectSuccess bool
	}{
		{"Allow user access", "user", true},
		{"Allow admin access", "admin", true},
		{"Deny other role access", "guest", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Create request
			req := httptest.NewRequest(http.MethodGet, "/user", nil)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)

			// Set token with role
			token := jwt.New(jwt.SigningMethodHS256)
			claims := token.Claims.(jwt.MapClaims)
			claims["role"] = tc.role
			c.Set("user", token)

			// Execute middleware
			err := middlewareFunc(c)

			if tc.expectSuccess {
				assert.NoError(t, err)
				assert.Equal(t, http.StatusOK, rec.Code)
				assert.Equal(t, "user access", rec.Body.String())
			} else {
				if he, ok := err.(*echo.HTTPError); ok {
					assert.Equal(t, http.StatusForbidden, he.Code)
					assert.Equal(t, "Insufficient permissions", he.Message)
				} else {
					t.Errorf("Expected HTTPError but got %T", err)
				}
			}
		})
	}
}
