package handler_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/regiwitanto/auth-service/internal/delivery/http/handler"
	"github.com/regiwitanto/auth-service/internal/domain"
	"github.com/regiwitanto/auth-service/internal/testutil/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestForgotPassword(t *testing.T) {
	// Setup
	e := echo.New()
	mockAuthUseCase := new(mocks.MockAuthUseCase)
	authHandler := handler.NewAuthHandler(mockAuthUseCase)

	tests := []struct {
		name           string
		requestBody    map[string]interface{}
		mockBehavior   func()
		expectedStatus int
	}{
		{
			name: "Success",
			requestBody: map[string]interface{}{
				"email": "test@example.com",
			},
			mockBehavior: func() {
				mockAuthUseCase.On("ForgotPassword", mock.Anything, mock.MatchedBy(func(req *domain.ForgotPasswordRequest) bool {
					return req.Email == "test@example.com"
				})).Return(nil)
			},
			expectedStatus: http.StatusOK,
		},
		{
			name: "Invalid Email Format",
			requestBody: map[string]interface{}{
				"email": "invalid-email",
			},
			mockBehavior:   func() {},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name: "Internal Error",
			requestBody: map[string]interface{}{
				"email": "test@example.com",
			},
			mockBehavior: func() {
				mockAuthUseCase.On("ForgotPassword", mock.Anything, mock.MatchedBy(func(req *domain.ForgotPasswordRequest) bool {
					return req.Email == "test@example.com"
				})).Return(errors.New("internal error"))
			},
			expectedStatus: http.StatusInternalServerError,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Reset mock
			mockAuthUseCase.ExpectedCalls = nil
			mockAuthUseCase.Calls = nil

			// Setup mock behavior
			test.mockBehavior()

			// Create request
			requestJSON, _ := json.Marshal(test.requestBody)
			req := httptest.NewRequest(http.MethodPost, "/auth/forgot-password", bytes.NewReader(requestJSON))
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)

			// Perform request
			err := authHandler.ForgotPassword(c)

			// Assertions
			assert.NoError(t, err)
			assert.Equal(t, test.expectedStatus, rec.Code)

			var response map[string]interface{}
			json.Unmarshal(rec.Body.Bytes(), &response)

			if test.expectedStatus == http.StatusOK {
				assert.Contains(t, response, "message")
			} else {
				assert.Contains(t, response, "error")
			}

			// Verify all expected mocks were called
			mockAuthUseCase.AssertExpectations(t)
		})
	}
}

func TestResetPassword(t *testing.T) {
	// Setup
	e := echo.New()
	mockAuthUseCase := new(mocks.MockAuthUseCase)
	authHandler := handler.NewAuthHandler(mockAuthUseCase)

	tests := []struct {
		name           string
		requestBody    map[string]interface{}
		mockBehavior   func()
		expectedStatus int
	}{
		{
			name: "Success",
			requestBody: map[string]interface{}{
				"token":    "valid-token",
				"password": "newpassword123",
			},
			mockBehavior: func() {
				mockAuthUseCase.On("ResetPassword", mock.Anything, mock.MatchedBy(func(req *domain.ResetPasswordRequest) bool {
					return req.Token == "valid-token" && req.Password == "newpassword123"
				})).Return(nil)
			},
			expectedStatus: http.StatusOK,
		},
		{
			name: "Invalid Token",
			requestBody: map[string]interface{}{
				"token":    "invalid-token",
				"password": "newpassword123",
			},
			mockBehavior: func() {
				mockAuthUseCase.On("ResetPassword", mock.Anything, mock.MatchedBy(func(req *domain.ResetPasswordRequest) bool {
					return req.Token == "invalid-token" && req.Password == "newpassword123"
				})).Return(errors.New("invalid or expired reset token"))
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name: "Password Too Short",
			requestBody: map[string]interface{}{
				"token":    "valid-token",
				"password": "short",
			},
			mockBehavior:   func() {},
			expectedStatus: http.StatusBadRequest,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Reset mock
			mockAuthUseCase.ExpectedCalls = nil
			mockAuthUseCase.Calls = nil

			// Setup mock behavior
			test.mockBehavior()

			// Create request
			requestJSON, _ := json.Marshal(test.requestBody)
			req := httptest.NewRequest(http.MethodPost, "/auth/reset-password", bytes.NewReader(requestJSON))
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)

			// Perform request
			err := authHandler.ResetPassword(c)

			// Assertions
			assert.NoError(t, err)
			assert.Equal(t, test.expectedStatus, rec.Code)

			var response map[string]interface{}
			json.Unmarshal(rec.Body.Bytes(), &response)

			if test.expectedStatus == http.StatusOK {
				assert.Contains(t, response, "message")
			} else {
				assert.Contains(t, response, "error")
			}

			// Verify all expected mocks were called
			mockAuthUseCase.AssertExpectations(t)
		})
	}
}
