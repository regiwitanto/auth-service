package handler_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/regiwitanto/auth-service/internal/delivery/http/handler"
	"github.com/regiwitanto/auth-service/internal/testutil/mocks"
	"github.com/stretchr/testify/assert"
)

func TestGetAllUsers(t *testing.T) {
	// Setup
	e := echo.New()
	mockAuthUseCase := new(mocks.MockAuthUseCase)
	mockConfig := mocks.MockConfig()
	adminHandler := handler.NewAdminHandler(mockAuthUseCase, mockConfig)

	// Create JWT claims for admin user
	adminClaims := make(map[string]interface{})
	adminClaims["sub"] = "admin-123"
	adminClaims["role"] = "admin"

	tests := []struct {
		name           string
		setupContext   func(c echo.Context)
		expectedStatus int
		expectedError  bool
	}{
		{
			name: "Success - Admin Access",
			setupContext: func(c echo.Context) {
				c.Set("user", adminClaims)
			},
			expectedStatus: http.StatusOK,
			expectedError:  false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Reset mock
			mockAuthUseCase.ExpectedCalls = nil
			mockAuthUseCase.Calls = nil

			// Create request
			req := httptest.NewRequest(http.MethodGet, "/admin/users", nil)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)
			test.setupContext(c)

			// Perform request
			err := adminHandler.GetAllUsers(c)

			// Assertions
			assert.NoError(t, err)
			assert.Equal(t, test.expectedStatus, rec.Code)

			// Check response structure
			if !test.expectedError {
				assert.Contains(t, rec.Body.String(), "users")
				assert.Contains(t, rec.Body.String(), "message")
			}
		})
	}
}

func TestGetSystemStats(t *testing.T) {
	// Setup
	e := echo.New()
	mockAuthUseCase := new(mocks.MockAuthUseCase)
	mockConfig := mocks.MockConfig()
	adminHandler := handler.NewAdminHandler(mockAuthUseCase, mockConfig)

	// Create JWT claims for admin user
	adminClaims := make(map[string]interface{})
	adminClaims["sub"] = "admin-123"
	adminClaims["role"] = "admin"

	tests := []struct {
		name           string
		setupContext   func(c echo.Context)
		expectedStatus int
		expectedError  bool
	}{
		{
			name: "Success - Admin Access",
			setupContext: func(c echo.Context) {
				c.Set("user", adminClaims)
			},
			expectedStatus: http.StatusOK,
			expectedError:  false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Reset mock
			mockAuthUseCase.ExpectedCalls = nil
			mockAuthUseCase.Calls = nil

			// Create request
			req := httptest.NewRequest(http.MethodGet, "/admin/stats", nil)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)
			test.setupContext(c)

			// Perform request
			err := adminHandler.GetSystemStats(c)

			// Assertions
			assert.NoError(t, err)
			assert.Equal(t, test.expectedStatus, rec.Code)

			// Check response structure
			if !test.expectedError {
				assert.Contains(t, rec.Body.String(), "stats")
				assert.Contains(t, rec.Body.String(), "message")
			}
		})
	}
}
