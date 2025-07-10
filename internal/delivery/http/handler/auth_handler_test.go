package handler_test

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-playground/validator/v10"
	"github.com/golang-jwt/jwt"
	"github.com/labstack/echo/v4"
	"github.com/regiwitanto/auth-service/internal/delivery/http/handler"
	"github.com/regiwitanto/auth-service/internal/domain"
	"github.com/regiwitanto/auth-service/internal/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"
)

type AuthHandlerTestSuite struct {
	suite.Suite
	echo        *echo.Echo
	mockAuthUC  *mocks.MockAuthUseCase
	authHandler *handler.AuthHandler
}

func (suite *AuthHandlerTestSuite) SetupTest() {
	suite.echo = echo.New()
	suite.echo.Validator = &CustomValidator{validator: validator.New()}
	suite.mockAuthUC = new(mocks.MockAuthUseCase)
	suite.authHandler = handler.NewAuthHandler(suite.mockAuthUC)
}

func TestAuthHandlerSuite(t *testing.T) {
	suite.Run(t, new(AuthHandlerTestSuite))
}

// CustomValidator is a wrapper for the validator package
type CustomValidator struct {
	validator *validator.Validate
}

// Validate validates the request body
func (cv *CustomValidator) Validate(i interface{}) error {
	if err := cv.validator.Struct(i); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}
	return nil
}

func (suite *AuthHandlerTestSuite) TestRegister_Success() {
	// Arrange
	requestBody := `{
		"email": "test@example.com",
		"username": "testuser",
		"password": "password123",
		"first_name": "Test",
		"last_name": "User"
	}`

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/register", strings.NewReader(requestBody))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	c := suite.echo.NewContext(req, rec)

	// Mock expected response
	expectedResponse := &domain.UserResponse{
		UUID:      "test-uuid",
		Email:     "test@example.com",
		Username:  "testuser",
		FirstName: "Test",
		LastName:  "User",
		Role:      "user",
	}

	// Mock Register use case
	suite.mockAuthUC.On("Register", mock.Anything, mock.AnythingOfType("*domain.RegisterRequest")).
		Return(expectedResponse, nil)

	// Act
	err := suite.authHandler.Register(c)

	// Assert
	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), http.StatusCreated, rec.Code)

	// Check response body
	var response domain.UserResponse
	err = json.Unmarshal(rec.Body.Bytes(), &response)
	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), expectedResponse.UUID, response.UUID)
	assert.Equal(suite.T(), expectedResponse.Email, response.Email)
	assert.Equal(suite.T(), expectedResponse.Username, response.Username)

	// Verify mocks
	suite.mockAuthUC.AssertExpectations(suite.T())
}

func (suite *AuthHandlerTestSuite) TestRegister_InvalidRequest() {
	// Arrange - Missing required fields
	requestBody := `{
		"email": "test@example.com",
		"password": "password123"
	}`

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/register", strings.NewReader(requestBody))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	c := suite.echo.NewContext(req, rec)

	// Act
	err := suite.authHandler.Register(c)

	// Assert
	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), http.StatusBadRequest, rec.Code)

	// Response should contain error message
	var response map[string]string
	err = json.Unmarshal(rec.Body.Bytes(), &response)
	assert.NoError(suite.T(), err)
	assert.Contains(suite.T(), response["error"], "Validation failed")
}

func (suite *AuthHandlerTestSuite) TestRegister_UseCaseError() {
	// Arrange
	requestBody := `{
		"email": "existing@example.com",
		"username": "existinguser",
		"password": "password123",
		"first_name": "Test",
		"last_name": "User"
	}`

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/register", strings.NewReader(requestBody))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	c := suite.echo.NewContext(req, rec)

	// Mock Register use case - Return error
	suite.mockAuthUC.On("Register", mock.Anything, mock.AnythingOfType("*domain.RegisterRequest")).
		Return(nil, errors.New("user with this email already exists"))

	// Act
	err := suite.authHandler.Register(c)

	// Assert
	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), http.StatusBadRequest, rec.Code)

	// Response should contain error message
	var response map[string]string
	err = json.Unmarshal(rec.Body.Bytes(), &response)
	assert.NoError(suite.T(), err)
	assert.Contains(suite.T(), response["error"], "already exists")

	// Verify mocks
	suite.mockAuthUC.AssertExpectations(suite.T())
}

func (suite *AuthHandlerTestSuite) TestLogin_Success() {
	// Arrange
	requestBody := `{
		"email": "test@example.com",
		"password": "password123"
	}`

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", strings.NewReader(requestBody))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	c := suite.echo.NewContext(req, rec)

	// Mock expected response
	expectedResponse := &domain.TokenResponse{
		AccessToken:  "test-access-token",
		RefreshToken: "test-refresh-token",
		ExpiresIn:    900, // 15 minutes in seconds
		TokenType:    "Bearer",
	}

	// Mock Login use case
	suite.mockAuthUC.On("Login", mock.Anything, mock.AnythingOfType("*domain.LoginRequest")).
		Return(expectedResponse, nil)

	// Act
	err := suite.authHandler.Login(c)

	// Assert
	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), http.StatusOK, rec.Code)

	// Check response body
	var response domain.TokenResponse
	err = json.Unmarshal(rec.Body.Bytes(), &response)
	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), expectedResponse.AccessToken, response.AccessToken)
	assert.Equal(suite.T(), expectedResponse.RefreshToken, response.RefreshToken)
	assert.Equal(suite.T(), expectedResponse.ExpiresIn, response.ExpiresIn)
	assert.Equal(suite.T(), expectedResponse.TokenType, response.TokenType)

	// Verify mocks
	suite.mockAuthUC.AssertExpectations(suite.T())
}

func (suite *AuthHandlerTestSuite) TestLogin_InvalidCredentials() {
	// Arrange
	requestBody := `{
		"email": "wrong@example.com",
		"password": "wrongpassword"
	}`

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", strings.NewReader(requestBody))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	c := suite.echo.NewContext(req, rec)

	// Mock Login use case - Return error
	suite.mockAuthUC.On("Login", mock.Anything, mock.AnythingOfType("*domain.LoginRequest")).
		Return(nil, errors.New("invalid email or password"))

	// Act
	err := suite.authHandler.Login(c)

	// Assert
	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), http.StatusUnauthorized, rec.Code)

	// Response should contain error message
	var response map[string]string
	err = json.Unmarshal(rec.Body.Bytes(), &response)
	assert.NoError(suite.T(), err)
	assert.Contains(suite.T(), response["error"], "invalid email or password")

	// Verify mocks
	suite.mockAuthUC.AssertExpectations(suite.T())
}

func (suite *AuthHandlerTestSuite) TestRefreshToken_Success() {
	// Arrange
	requestBody := `{
		"refresh_token": "valid-refresh-token"
	}`

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", strings.NewReader(requestBody))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	c := suite.echo.NewContext(req, rec)

	// Mock expected response
	expectedResponse := &domain.TokenResponse{
		AccessToken:  "new-access-token",
		RefreshToken: "new-refresh-token",
		ExpiresIn:    900, // 15 minutes in seconds
		TokenType:    "Bearer",
	}

	// Mock RefreshToken use case
	suite.mockAuthUC.On("RefreshToken", mock.Anything, mock.AnythingOfType("*domain.RefreshTokenRequest")).
		Return(expectedResponse, nil)

	// Act
	err := suite.authHandler.RefreshToken(c)

	// Assert
	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), http.StatusOK, rec.Code)

	// Check response body
	var response domain.TokenResponse
	err = json.Unmarshal(rec.Body.Bytes(), &response)
	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), expectedResponse.AccessToken, response.AccessToken)
	assert.Equal(suite.T(), expectedResponse.RefreshToken, response.RefreshToken)

	// Verify mocks
	suite.mockAuthUC.AssertExpectations(suite.T())
}

func (suite *AuthHandlerTestSuite) TestRefreshToken_InvalidToken() {
	// Arrange
	requestBody := `{
		"refresh_token": "invalid-refresh-token"
	}`

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", strings.NewReader(requestBody))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	c := suite.echo.NewContext(req, rec)

	// Mock RefreshToken use case - Return error
	suite.mockAuthUC.On("RefreshToken", mock.Anything, mock.AnythingOfType("*domain.RefreshTokenRequest")).
		Return(nil, errors.New("invalid or expired refresh token"))

	// Act
	err := suite.authHandler.RefreshToken(c)

	// Assert
	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), http.StatusUnauthorized, rec.Code)

	// Response should contain error message
	var response map[string]string
	err = json.Unmarshal(rec.Body.Bytes(), &response)
	assert.NoError(suite.T(), err)
	assert.Contains(suite.T(), response["error"], "invalid or expired refresh token")

	// Verify mocks
	suite.mockAuthUC.AssertExpectations(suite.T())
}

func (suite *AuthHandlerTestSuite) TestLogout_Success() {
	// Arrange
	requestBody := `{
		"refresh_token": "valid-refresh-token"
	}`

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/logout", strings.NewReader(requestBody))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	c := suite.echo.NewContext(req, rec)

	// Mock Logout use case
	suite.mockAuthUC.On("Logout", mock.Anything, "valid-refresh-token").
		Return(nil)

	// Act
	err := suite.authHandler.Logout(c)

	// Assert
	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), http.StatusOK, rec.Code)

	// Response should contain success message
	var response map[string]string
	err = json.Unmarshal(rec.Body.Bytes(), &response)
	assert.NoError(suite.T(), err)
	assert.Contains(suite.T(), response["message"], "Logged out successfully")

	// Verify mocks
	suite.mockAuthUC.AssertExpectations(suite.T())
}

func (suite *AuthHandlerTestSuite) TestGetUserProfile_Success() {
	// Arrange
	userID := "test-uuid"

	// Create a request
	req := httptest.NewRequest(http.MethodGet, "/api/v1/user/me", nil)
	rec := httptest.NewRecorder()
	c := suite.echo.NewContext(req, rec)

	// Set JWT token claims in context
	claims := jwt.MapClaims{
		"sub": userID,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	c.Set("user", token)

	// Mock expected response
	expectedResponse := &domain.UserResponse{
		UUID:      userID,
		Email:     "test@example.com",
		Username:  "testuser",
		FirstName: "Test",
		LastName:  "User",
		Role:      "user",
	}

	// Mock GetUserProfile use case
	suite.mockAuthUC.On("GetUserProfile", mock.Anything, userID).
		Return(expectedResponse, nil)

	// Act
	err := suite.authHandler.GetUserProfile(c)

	// Assert
	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), http.StatusOK, rec.Code)

	// Check response body
	var response domain.UserResponse
	err = json.Unmarshal(rec.Body.Bytes(), &response)
	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), expectedResponse.UUID, response.UUID)
	assert.Equal(suite.T(), expectedResponse.Email, response.Email)
	assert.Equal(suite.T(), expectedResponse.Username, response.Username)

	// Verify mocks
	suite.mockAuthUC.AssertExpectations(suite.T())
}

func (suite *AuthHandlerTestSuite) TestGetUserProfile_UserNotFound() {
	// Arrange
	userID := "nonexistent-uuid"

	// Create a request
	req := httptest.NewRequest(http.MethodGet, "/api/v1/user/me", nil)
	rec := httptest.NewRecorder()
	c := suite.echo.NewContext(req, rec)

	// Set JWT token claims in context
	claims := jwt.MapClaims{
		"sub": userID,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	c.Set("user", token)

	// Mock GetUserProfile use case - Return error
	suite.mockAuthUC.On("GetUserProfile", mock.Anything, userID).
		Return(nil, errors.New("user not found"))

	// Act
	err := suite.authHandler.GetUserProfile(c)

	// Assert
	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), http.StatusNotFound, rec.Code)

	// Response should contain error message
	var response map[string]string
	err = json.Unmarshal(rec.Body.Bytes(), &response)
	assert.NoError(suite.T(), err)
	assert.Contains(suite.T(), response["error"], "user not found")

	// Verify mocks
	suite.mockAuthUC.AssertExpectations(suite.T())
}

func (suite *AuthHandlerTestSuite) TestGetUserProfile_InvalidToken() {
	// Arrange
	// Create a request with no token
	req := httptest.NewRequest(http.MethodGet, "/api/v1/user/me", nil)
	rec := httptest.NewRecorder()
	c := suite.echo.NewContext(req, rec)

	// Act
	err := suite.authHandler.GetUserProfile(c)

	// Assert
	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), http.StatusUnauthorized, rec.Code)

	// Response should contain error message
	var response map[string]string
	err = json.Unmarshal(rec.Body.Bytes(), &response)
	assert.NoError(suite.T(), err)
	assert.Contains(suite.T(), response["error"], "Invalid or missing token")
}
