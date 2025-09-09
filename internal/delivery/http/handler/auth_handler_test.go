package handler_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt"

	"github.com/labstack/echo/v4"
	"github.com/regiwitanto/auth-service/internal/delivery/http/handler"
	"github.com/regiwitanto/auth-service/internal/domain"
	"github.com/regiwitanto/auth-service/internal/testutil/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestRegister(t *testing.T) {
	e := echo.New()
	mockAuthUseCase := new(mocks.MockAuthUseCase)
	mockConfig := mocks.MockConfig()
	authHandler := handler.NewAuthHandler(mockAuthUseCase, mockConfig)

	tests := []struct {
		name           string
		requestBody    map[string]interface{}
		mockBehavior   func()
		expectedStatus int
		expectedError  bool
	}{
		{
			name: "Success",
			requestBody: map[string]interface{}{
				"username":   "testuser",
				"email":      "test@example.com",
				"password":   "password123",
				"first_name": "Test",
				"last_name":  "User",
			},
			mockBehavior: func() {
				mockAuthUseCase.On("Register", mock.Anything, mock.MatchedBy(func(req *domain.RegisterRequest) bool {
					return req.Username == "testuser" && req.Email == "test@example.com"
				})).Return(&domain.UserResponse{
					UUID:      "user-123",
					Username:  "testuser",
					Email:     "test@example.com",
					FirstName: "Test",
					LastName:  "User",
					Role:      "user",
				}, nil)
			},
			expectedStatus: http.StatusCreated,
			expectedError:  false,
		},
		{
			name: "User Already Exists",
			requestBody: map[string]interface{}{
				"username":   "existinguser",
				"email":      "existing@example.com",
				"password":   "password123",
				"first_name": "Existing",
				"last_name":  "User",
			},
			mockBehavior: func() {
				mockAuthUseCase.On("Register", mock.Anything, mock.MatchedBy(func(req *domain.RegisterRequest) bool {
					return req.Username == "existinguser" && req.Email == "existing@example.com"
				})).Return(nil, errors.New("user with this email already exists"))
			},
			expectedStatus: http.StatusBadRequest,
			expectedError:  true,
		},
		{
			name: "Invalid Request - Missing Required Fields",
			requestBody: map[string]interface{}{
				"username": "testuser",
				// Missing email and password
			},
			mockBehavior:   func() {},
			expectedStatus: http.StatusBadRequest,
			expectedError:  true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mockAuthUseCase.ExpectedCalls = nil
			mockAuthUseCase.Calls = nil

			test.mockBehavior()

			jsonBody, _ := json.Marshal(test.requestBody)
			req := httptest.NewRequest(http.MethodPost, "/auth/register", bytes.NewReader(jsonBody))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)

			err := authHandler.Register(c)

			assert.NoError(t, err)
			assert.Equal(t, test.expectedStatus, rec.Code)
			var response map[string]interface{}
			json.Unmarshal(rec.Body.Bytes(), &response)

			if test.expectedError {
				assert.Contains(t, response, "error")
			} else {
				// Handler returns UserResponse directly at top level
				assert.Equal(t, "testuser", response["username"])
				assert.Equal(t, "test@example.com", response["email"])
				assert.Equal(t, "user-123", response["uuid"])
				assert.Equal(t, "user", response["role"])
			}

			// Verify all expected mocks were called
			mockAuthUseCase.AssertExpectations(t)
		})
	}
}

func TestLogin(t *testing.T) {
	e := echo.New()
	mockAuthUseCase := new(mocks.MockAuthUseCase)
	mockConfig := mocks.MockConfig()
	authHandler := handler.NewAuthHandler(mockAuthUseCase, mockConfig)

	tests := []struct {
		name           string
		requestBody    map[string]interface{}
		mockBehavior   func()
		expectedStatus int
		expectedError  bool
	}{
		{
			name: "Success",
			requestBody: map[string]interface{}{
				"email":    "test@example.com",
				"password": "password123",
			},
			mockBehavior: func() {
				mockAuthUseCase.On("Login", mock.Anything, mock.MatchedBy(func(req *domain.LoginRequest) bool {
					return req.Email == "test@example.com" && req.Password == "password123"
				})).Return(&domain.TokenResponse{
					AccessToken:  "test-access-token",
					RefreshToken: "test-refresh-token",
					ExpiresIn:    3600,
				}, nil)
			},
			expectedStatus: http.StatusOK,
			expectedError:  false,
		},
		{
			name: "Invalid Credentials",
			requestBody: map[string]interface{}{
				"email":    "wrong@example.com",
				"password": "wrongpass",
			},
			mockBehavior: func() {
				mockAuthUseCase.On("Login", mock.Anything, mock.MatchedBy(func(req *domain.LoginRequest) bool {
					return req.Email == "wrong@example.com" && req.Password == "wrongpass"
				})).Return(nil, errors.New("invalid email or password"))
			},
			expectedStatus: http.StatusUnauthorized,
			expectedError:  true,
		},
		{
			name: "Invalid Request - Missing Required Fields",
			requestBody: map[string]interface{}{
				"email": "test@example.com",
				// Missing password
			},
			mockBehavior:   func() {},
			expectedStatus: http.StatusBadRequest,
			expectedError:  true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mockAuthUseCase.ExpectedCalls = nil
			mockAuthUseCase.Calls = nil

			test.mockBehavior()

			jsonBody, _ := json.Marshal(test.requestBody)
			req := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewReader(jsonBody))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)

			err := authHandler.Login(c)

			assert.NoError(t, err)
			assert.Equal(t, test.expectedStatus, rec.Code)
			var response map[string]interface{}
			json.Unmarshal(rec.Body.Bytes(), &response)

			if test.expectedError {
				assert.Contains(t, response, "error")
			} else {
				assert.Contains(t, response, "access_token")
				assert.Contains(t, response, "refresh_token")
				assert.Contains(t, response, "expires_in")
				assert.Equal(t, "test-access-token", response["access_token"])
			}

			// Verify all expected mocks were called
			mockAuthUseCase.AssertExpectations(t)
		})
	}
}

func TestRefreshToken(t *testing.T) {
	e := echo.New()
	mockAuthUseCase := new(mocks.MockAuthUseCase)
	mockConfig := mocks.MockConfig()
	authHandler := handler.NewAuthHandler(mockAuthUseCase, mockConfig)

	tests := []struct {
		name           string
		requestBody    map[string]interface{}
		mockBehavior   func()
		expectedStatus int
		expectedError  bool
	}{
		{
			name: "Success",
			requestBody: map[string]interface{}{
				"refresh_token": "valid-refresh-token",
			},
			mockBehavior: func() {
				mockAuthUseCase.On("RefreshToken", mock.Anything, mock.MatchedBy(func(req *domain.RefreshTokenRequest) bool {
					return req.RefreshToken == "valid-refresh-token"
				})).Return(&domain.TokenResponse{
					AccessToken:  "new-access-token",
					RefreshToken: "new-refresh-token",
					ExpiresIn:    3600,
				}, nil)
			},
			expectedStatus: http.StatusOK,
			expectedError:  false,
		},
		{
			name: "Invalid Refresh Token",
			requestBody: map[string]interface{}{
				"refresh_token": "invalid-refresh-token",
			},
			mockBehavior: func() {
				mockAuthUseCase.On("RefreshToken", mock.Anything, mock.MatchedBy(func(req *domain.RefreshTokenRequest) bool {
					return req.RefreshToken == "invalid-refresh-token"
				})).Return(nil, errors.New("invalid refresh token"))
			},
			expectedStatus: http.StatusUnauthorized,
			expectedError:  true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mockAuthUseCase.ExpectedCalls = nil
			mockAuthUseCase.Calls = nil

			test.mockBehavior()

			jsonBody, _ := json.Marshal(test.requestBody)
			req := httptest.NewRequest(http.MethodPost, "/auth/refresh", bytes.NewReader(jsonBody))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)

			err := authHandler.RefreshToken(c)

			assert.NoError(t, err)
			assert.Equal(t, test.expectedStatus, rec.Code)
			var response map[string]interface{}
			json.Unmarshal(rec.Body.Bytes(), &response)

			if test.expectedError {
				assert.Contains(t, response, "error")
			} else {
				assert.Contains(t, response, "access_token")
				assert.Contains(t, response, "refresh_token")
				assert.Equal(t, "new-access-token", response["access_token"])
			}

			// Verify all expected mocks were called
			mockAuthUseCase.AssertExpectations(t)
		})
	}
}

func TestLogout(t *testing.T) {
	e := echo.New()
	mockAuthUseCase := new(mocks.MockAuthUseCase)
	mockConfig := mocks.MockConfig()
	authHandler := handler.NewAuthHandler(mockAuthUseCase, mockConfig)

	tests := []struct {
		name           string
		requestBody    map[string]interface{}
		mockBehavior   func()
		expectedStatus int
		expectedError  bool
	}{
		{
			name: "Success",
			requestBody: map[string]interface{}{
				"refresh_token": "valid-refresh-token",
			},
			mockBehavior: func() {
				mockAuthUseCase.On("Logout", mock.Anything, "valid-refresh-token").Return(nil)
			},
			expectedStatus: http.StatusOK,
			expectedError:  false,
		},
		{
			name: "Invalid Token",
			requestBody: map[string]interface{}{
				"refresh_token": "invalid-token",
			},
			mockBehavior: func() {
				mockAuthUseCase.On("Logout", mock.Anything, "invalid-token").Return(errors.New("token not found"))
			},
			expectedStatus: http.StatusInternalServerError, // Handler returns 500 for token errors
			expectedError:  true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mockAuthUseCase.ExpectedCalls = nil
			mockAuthUseCase.Calls = nil

			test.mockBehavior()

			jsonBody, _ := json.Marshal(test.requestBody)
			req := httptest.NewRequest(http.MethodPost, "/auth/logout", bytes.NewReader(jsonBody))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)

			err := authHandler.Logout(c)

			assert.NoError(t, err)
			assert.Equal(t, test.expectedStatus, rec.Code)
			var response map[string]interface{}
			json.Unmarshal(rec.Body.Bytes(), &response)

			if test.expectedError {
				assert.Contains(t, response, "error")
			} else {
				assert.Contains(t, response, "message")
				assert.Equal(t, "Logged out successfully", response["message"])
			}

			// Verify all expected mocks were called
			mockAuthUseCase.AssertExpectations(t)
		})
	}
}

func TestGetProfile(t *testing.T) {
	e := echo.New()
	mockAuthUseCase := new(mocks.MockAuthUseCase)
	mockConfig := mocks.MockConfig()
	authHandler := handler.NewAuthHandler(mockAuthUseCase, mockConfig)

	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)
	claims["sub"] = "user-123"
	claims["role"] = "user"
	claims["name"] = "testuser"
	claims["email"] = "test@example.com"
	claims["exp"] = time.Now().Add(time.Hour).Unix()

	tests := []struct {
		name           string
		setupContext   func(c echo.Context)
		mockBehavior   func()
		expectedStatus int
		expectedError  bool
	}{
		{
			name: "Success",
			setupContext: func(c echo.Context) {
				c.Set("user", token)
			},
			mockBehavior: func() {
				mockAuthUseCase.On("GetUserProfile", mock.Anything, "user-123").Return(&domain.UserResponse{
					UUID:      "user-123",
					Username:  "testuser",
					Email:     "test@example.com",
					FirstName: "Test",
					LastName:  "User",
					Role:      "user",
				}, nil)
			},
			expectedStatus: http.StatusOK,
			expectedError:  false,
		},
		{
			name: "User Not Found",
			setupContext: func(c echo.Context) {
				c.Set("user", token)
			},
			mockBehavior: func() {
				mockAuthUseCase.On("GetUserProfile", mock.Anything, "user-123").Return(nil, errors.New("user not found"))
			},
			expectedStatus: http.StatusNotFound,
			expectedError:  true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mockAuthUseCase.ExpectedCalls = nil
			mockAuthUseCase.Calls = nil

			test.mockBehavior()

			req := httptest.NewRequest(http.MethodGet, "/auth/profile", nil)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)
			test.setupContext(c)

			err := authHandler.GetUserProfile(c)

			assert.NoError(t, err)
			assert.Equal(t, test.expectedStatus, rec.Code)
			var response map[string]interface{}
			json.Unmarshal(rec.Body.Bytes(), &response)

			if test.expectedError {
				assert.Contains(t, response, "error")
			} else {
				// Handler returns UserResponse directly at top level
				assert.Equal(t, "testuser", response["username"])
				assert.Equal(t, "test@example.com", response["email"])
				assert.Equal(t, "user-123", response["uuid"])
				assert.Equal(t, "user", response["role"])
			}

			// Verify all expected mocks were called
			mockAuthUseCase.AssertExpectations(t)
		})
	}
}
