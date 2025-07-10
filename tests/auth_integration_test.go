package tests

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/regiwitanto/auth-service/config"
	"github.com/regiwitanto/auth-service/internal/delivery/http/handler"
	"github.com/regiwitanto/auth-service/internal/domain"
	"github.com/regiwitanto/auth-service/internal/repository"
	"github.com/regiwitanto/auth-service/internal/usecase"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

type AuthIntegrationTestSuite struct {
	suite.Suite
	db          *gorm.DB
	e           *echo.Echo
	authHandler *handler.AuthHandler
	userRepo    repository.UserRepository
	tokenRepo   repository.TokenRepository
	authUseCase usecase.AuthUseCase
	cfg         config.Config

	// Test data
	testUser     *domain.User
	accessToken  string
	refreshToken string
}

func (suite *AuthIntegrationTestSuite) SetupSuite() {
	// Load test configuration
	var err error
	suite.cfg, err = config.LoadTestConfig()
	if err != nil {
		suite.T().Fatalf("Failed to load test configuration: %v", err)
	}

	// Initialize test database
	dsn := fmt.Sprintf(
		"host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		suite.cfg.Database.Host,
		suite.cfg.Database.Port,
		suite.cfg.Database.User,
		suite.cfg.Database.Password,
		suite.cfg.Database.DBName,
		suite.cfg.Database.SSLMode,
	)

	suite.db, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		suite.T().Fatalf("Failed to connect to database: %v", err)
	}

	// Run migrations for testing
	err = suite.runMigrations()
	if err != nil {
		suite.T().Fatalf("Failed to run migrations: %v", err)
	}

	// Initialize Redis
	redisClient, err := config.InitRedis(suite.cfg)
	if err != nil {
		suite.T().Fatalf("Failed to connect to Redis: %v", err)
	}

	// Initialize repositories
	suite.userRepo = repository.NewUserRepository(suite.db)
	suite.tokenRepo = repository.NewTokenRepository(redisClient)

	// Initialize use cases
	suite.authUseCase = usecase.NewAuthUseCase(
		suite.userRepo,
		suite.tokenRepo,
		suite.cfg,
	)

	// Initialize handler
	suite.authHandler = handler.NewAuthHandler(suite.authUseCase)

	// Initialize Echo
	suite.e = echo.New()
}

func (suite *AuthIntegrationTestSuite) TearDownSuite() {
	// Clean up the database
	sqlDB, err := suite.db.DB()
	if err != nil {
		suite.T().Fatalf("Failed to get DB instance: %v", err)
	}
	sqlDB.Close()
}

func (suite *AuthIntegrationTestSuite) SetupTest() {
	// Clean up tables before each test
	suite.db.Exec("TRUNCATE TABLE users CASCADE")
}

func (suite *AuthIntegrationTestSuite) runMigrations() error {
	// Define migrations
	return suite.db.AutoMigrate(&domain.User{})
}

// LoadTestConfig is a utility function to load the test configuration
func LoadTestConfig() (config.Config, error) {
	// This could be loaded from a test.env file or set with environment variables
	return config.Config{
		Database: config.DatabaseConfig{
			Host:     os.Getenv("TEST_DB_HOST"),
			Port:     3306,
			User:     os.Getenv("TEST_DB_USER"),
			Password: os.Getenv("TEST_DB_PASSWORD"),
			DBName:   os.Getenv("TEST_DB_NAME"),
			SSLMode:  "disable",
		},
		JWT: config.JWTConfig{
			Secret:          "test_secret",
			AccessTokenExp:  15,
			RefreshTokenExp: 60,
		},
	}, nil
}

func TestAuthIntegrationSuite(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration tests in short mode")
	}
	suite.Run(t, new(AuthIntegrationTestSuite))
}

func (suite *AuthIntegrationTestSuite) TestAuthFlow() {
	// Step 1: Register a new user
	registerReq := domain.RegisterRequest{
		Email:     "test@example.com",
		Username:  "testuser",
		Password:  "password123",
		FirstName: "Test",
		LastName:  "User",
	}

	requestBody, _ := json.Marshal(registerReq)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/register", bytes.NewBuffer(requestBody))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	c := suite.e.NewContext(req, rec)

	// Execute the handler
	err := suite.authHandler.Register(c)
	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), http.StatusCreated, rec.Code)

	// Parse the response
	var userResponse domain.UserResponse
	err = json.Unmarshal(rec.Body.Bytes(), &userResponse)
	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), registerReq.Email, userResponse.Email)
	assert.Equal(suite.T(), registerReq.Username, userResponse.Username)

	// Step 2: Login with the new user
	loginReq := domain.LoginRequest{
		Email:    registerReq.Email,
		Password: registerReq.Password,
	}

	requestBody, _ = json.Marshal(loginReq)

	req = httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewBuffer(requestBody))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec = httptest.NewRecorder()
	c = suite.e.NewContext(req, rec)

	// Execute the handler
	err = suite.authHandler.Login(c)
	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), http.StatusOK, rec.Code)

	// Parse the response
	var tokenResponse domain.TokenResponse
	err = json.Unmarshal(rec.Body.Bytes(), &tokenResponse)
	assert.NoError(suite.T(), err)
	assert.NotEmpty(suite.T(), tokenResponse.AccessToken)
	assert.NotEmpty(suite.T(), tokenResponse.RefreshToken)

	// Save tokens for later use
	suite.accessToken = tokenResponse.AccessToken
	suite.refreshToken = tokenResponse.RefreshToken

	// Step 3: Access protected route with the token
	req = httptest.NewRequest(http.MethodGet, "/api/v1/user/me", nil)
	req.Header.Set(echo.HeaderAuthorization, "Bearer "+suite.accessToken)
	rec = httptest.NewRecorder()
	c = suite.e.NewContext(req, rec)

	// Mock JWT middleware by setting the token in context
	token, _ := suite.authUseCase.VerifyToken(suite.accessToken)
	c.Set("user", token)

	// Execute the handler
	err = suite.authHandler.GetUserProfile(c)
	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), http.StatusOK, rec.Code)

	// Parse the response
	var profileResponse domain.UserResponse
	err = json.Unmarshal(rec.Body.Bytes(), &profileResponse)
	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), registerReq.Email, profileResponse.Email)
	assert.Equal(suite.T(), registerReq.Username, profileResponse.Username)

	// Step 4: Refresh the token
	refreshReq := domain.RefreshTokenRequest{
		RefreshToken: suite.refreshToken,
	}

	requestBody, _ = json.Marshal(refreshReq)

	req = httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", bytes.NewBuffer(requestBody))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec = httptest.NewRecorder()
	c = suite.e.NewContext(req, rec)

	// Execute the handler
	err = suite.authHandler.RefreshToken(c)
	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), http.StatusOK, rec.Code)

	// Parse the response
	var newTokenResponse domain.TokenResponse
	err = json.Unmarshal(rec.Body.Bytes(), &newTokenResponse)
	assert.NoError(suite.T(), err)
	assert.NotEmpty(suite.T(), newTokenResponse.AccessToken)
	assert.NotEmpty(suite.T(), newTokenResponse.RefreshToken)
	assert.NotEqual(suite.T(), suite.accessToken, newTokenResponse.AccessToken)
	assert.NotEqual(suite.T(), suite.refreshToken, newTokenResponse.RefreshToken)

	// Update tokens
	suite.accessToken = newTokenResponse.AccessToken
	suite.refreshToken = newTokenResponse.RefreshToken

	// Step 5: Logout
	logoutReq := domain.RefreshTokenRequest{
		RefreshToken: suite.refreshToken,
	}

	requestBody, _ = json.Marshal(logoutReq)

	req = httptest.NewRequest(http.MethodPost, "/api/v1/auth/logout", bytes.NewBuffer(requestBody))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec = httptest.NewRecorder()
	c = suite.e.NewContext(req, rec)

	// Execute the handler
	err = suite.authHandler.Logout(c)
	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), http.StatusOK, rec.Code)

	// Step 6: Verify that refresh token is no longer valid
	refreshReq = domain.RefreshTokenRequest{
		RefreshToken: suite.refreshToken,
	}

	requestBody, _ = json.Marshal(refreshReq)

	req = httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", bytes.NewBuffer(requestBody))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec = httptest.NewRecorder()
	c = suite.e.NewContext(req, rec)

	// Execute the handler
	err = suite.authHandler.RefreshToken(c)
	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), http.StatusUnauthorized, rec.Code) // Should fail as token is invalidated
}
