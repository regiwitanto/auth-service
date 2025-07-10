package usecase_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/regiwitanto/auth-service/config"
	"github.com/regiwitanto/auth-service/internal/domain"
	"github.com/regiwitanto/auth-service/internal/mocks"
	"github.com/regiwitanto/auth-service/internal/usecase"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"
	"golang.org/x/crypto/bcrypt"
)

type AuthUseCaseTestSuite struct {
	suite.Suite
	mockUserRepo  *mocks.MockUserRepository
	mockTokenRepo *mocks.MockTokenRepository
	cfg           config.Config
	authUseCase   usecase.AuthUseCase
	ctx           context.Context
}

func (suite *AuthUseCaseTestSuite) SetupTest() {
	suite.mockUserRepo = new(mocks.MockUserRepository)
	suite.mockTokenRepo = new(mocks.MockTokenRepository)

	// Setup default config for testing
	suite.cfg = config.Config{
		JWT: config.JWTConfig{
			Secret:          "test_secret",
			AccessTokenExp:  15 * time.Minute,
			RefreshTokenExp: 24 * time.Hour,
		},
	}

	suite.authUseCase = usecase.NewAuthUseCase(
		suite.mockUserRepo,
		suite.mockTokenRepo,
		suite.cfg,
	)
	suite.ctx = context.Background()
}

func TestAuthUseCaseSuite(t *testing.T) {
	suite.Run(t, new(AuthUseCaseTestSuite))
}

func (suite *AuthUseCaseTestSuite) TestRegister_Success() {
	// Arrange
	registerReq := &domain.RegisterRequest{
		Email:     "test@example.com",
		Username:  "testuser",
		Password:  "password123",
		FirstName: "Test",
		LastName:  "User",
	}

	// Mock FindByEmail - No existing user
	suite.mockUserRepo.On("FindByEmail", suite.ctx, registerReq.Email).
		Return(nil, errors.New("user not found"))

	// Mock FindByUsername - No existing user
	suite.mockUserRepo.On("FindByUsername", suite.ctx, registerReq.Username).
		Return(nil, errors.New("user not found"))

	// Mock Create
	suite.mockUserRepo.On("Create", suite.ctx, mock.AnythingOfType("*domain.User")).
		Return(nil)

	// Act
	result, err := suite.authUseCase.Register(suite.ctx, registerReq)

	// Assert
	assert.NoError(suite.T(), err)
	assert.NotNil(suite.T(), result)
	assert.Equal(suite.T(), registerReq.Email, result.Email)
	assert.Equal(suite.T(), registerReq.Username, result.Username)
	assert.Equal(suite.T(), registerReq.FirstName, result.FirstName)
	assert.Equal(suite.T(), registerReq.LastName, result.LastName)

	// Verify mocks
	suite.mockUserRepo.AssertExpectations(suite.T())
}

func (suite *AuthUseCaseTestSuite) TestRegister_EmailExists() {
	// Arrange
	registerReq := &domain.RegisterRequest{
		Email:     "existing@example.com",
		Username:  "testuser",
		Password:  "password123",
		FirstName: "Test",
		LastName:  "User",
	}

	// Mock FindByEmail - Existing user with same email
	existingUser := &domain.User{
		Email:    registerReq.Email,
		Username: "differentuser",
	}
	suite.mockUserRepo.On("FindByEmail", suite.ctx, registerReq.Email).
		Return(existingUser, nil)

	// Act
	result, err := suite.authUseCase.Register(suite.ctx, registerReq)

	// Assert
	assert.Error(suite.T(), err)
	assert.Nil(suite.T(), result)
	assert.Contains(suite.T(), err.Error(), "email already exists")

	// Verify mocks
	suite.mockUserRepo.AssertExpectations(suite.T())
}

func (suite *AuthUseCaseTestSuite) TestRegister_UsernameExists() {
	// Arrange
	registerReq := &domain.RegisterRequest{
		Email:     "test@example.com",
		Username:  "existinguser",
		Password:  "password123",
		FirstName: "Test",
		LastName:  "User",
	}

	// Mock FindByEmail - No existing user with same email
	suite.mockUserRepo.On("FindByEmail", suite.ctx, registerReq.Email).
		Return(nil, errors.New("user not found"))

	// Mock FindByUsername - Existing user with same username
	existingUser := &domain.User{
		Email:    "different@example.com",
		Username: registerReq.Username,
	}
	suite.mockUserRepo.On("FindByUsername", suite.ctx, registerReq.Username).
		Return(existingUser, nil)

	// Act
	result, err := suite.authUseCase.Register(suite.ctx, registerReq)

	// Assert
	assert.Error(suite.T(), err)
	assert.Nil(suite.T(), result)
	assert.Contains(suite.T(), err.Error(), "username already exists")

	// Verify mocks
	suite.mockUserRepo.AssertExpectations(suite.T())
}

func (suite *AuthUseCaseTestSuite) TestLogin_Success() {
	// Arrange
	loginReq := &domain.LoginRequest{
		Email:    "test@example.com",
		Password: "password123",
	}

	// Create a hashed password
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(loginReq.Password), bcrypt.DefaultCost)

	// Mock user
	user := &domain.User{
		ID:        1,
		UUID:      "test-uuid",
		Email:     loginReq.Email,
		Username:  "testuser",
		Password:  string(hashedPassword),
		FirstName: "Test",
		LastName:  "User",
		Role:      "user",
		Active:    true,
	}

	// Mock FindByEmail - Return the user
	suite.mockUserRepo.On("FindByEmail", suite.ctx, loginReq.Email).
		Return(user, nil)

	// Mock StoreRefreshToken - Store the token in Redis
	suite.mockTokenRepo.On("StoreRefreshToken",
		suite.ctx,
		user.UUID,
		mock.AnythingOfType("string"),
		suite.cfg.JWT.RefreshTokenExp).
		Return(nil)

	// Act
	result, err := suite.authUseCase.Login(suite.ctx, loginReq)

	// Assert
	assert.NoError(suite.T(), err)
	assert.NotNil(suite.T(), result)
	assert.NotEmpty(suite.T(), result.AccessToken)
	assert.NotEmpty(suite.T(), result.RefreshToken)
	assert.Equal(suite.T(), "Bearer", result.TokenType)
	assert.Greater(suite.T(), result.ExpiresIn, int64(0))

	// Verify access token
	token, err := jwt.Parse(result.AccessToken, func(token *jwt.Token) (interface{}, error) {
		return []byte(suite.cfg.JWT.Secret), nil
	})
	assert.NoError(suite.T(), err)
	assert.True(suite.T(), token.Valid)

	claims, ok := token.Claims.(jwt.MapClaims)
	assert.True(suite.T(), ok)
	assert.Equal(suite.T(), user.UUID, claims["sub"])
	assert.Equal(suite.T(), user.Username, claims["name"])
	assert.Equal(suite.T(), user.Email, claims["email"])
	assert.Equal(suite.T(), user.Role, claims["role"])

	// Verify mocks
	suite.mockUserRepo.AssertExpectations(suite.T())
	suite.mockTokenRepo.AssertExpectations(suite.T())
}

func (suite *AuthUseCaseTestSuite) TestLogin_UserNotFound() {
	// Arrange
	loginReq := &domain.LoginRequest{
		Email:    "nonexistent@example.com",
		Password: "password123",
	}

	// Mock FindByEmail - User not found
	suite.mockUserRepo.On("FindByEmail", suite.ctx, loginReq.Email).
		Return(nil, errors.New("user not found"))

	// Act
	result, err := suite.authUseCase.Login(suite.ctx, loginReq)

	// Assert
	assert.Error(suite.T(), err)
	assert.Nil(suite.T(), result)
	assert.Contains(suite.T(), err.Error(), "invalid email or password")

	// Verify mocks
	suite.mockUserRepo.AssertExpectations(suite.T())
}

func (suite *AuthUseCaseTestSuite) TestLogin_InvalidPassword() {
	// Arrange
	loginReq := &domain.LoginRequest{
		Email:    "test@example.com",
		Password: "wrongpassword",
	}

	// Create a hashed password for a different password
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("correctpassword"), bcrypt.DefaultCost)

	// Mock user
	user := &domain.User{
		Email:    loginReq.Email,
		Password: string(hashedPassword),
		Active:   true,
	}

	// Mock FindByEmail - Return the user
	suite.mockUserRepo.On("FindByEmail", suite.ctx, loginReq.Email).
		Return(user, nil)

	// Act
	result, err := suite.authUseCase.Login(suite.ctx, loginReq)

	// Assert
	assert.Error(suite.T(), err)
	assert.Nil(suite.T(), result)
	assert.Contains(suite.T(), err.Error(), "invalid email or password")

	// Verify mocks
	suite.mockUserRepo.AssertExpectations(suite.T())
}

func (suite *AuthUseCaseTestSuite) TestRefreshToken_Success() {
	// Arrange
	refreshReq := &domain.RefreshTokenRequest{
		RefreshToken: "valid-refresh-token",
	}

	// Mock user
	user := &domain.User{
		ID:        1,
		UUID:      "test-uuid",
		Email:     "test@example.com",
		Username:  "testuser",
		FirstName: "Test",
		LastName:  "User",
		Role:      "user",
		Active:    true,
	}

	// Mock GetUserIDByRefreshToken - Return the user ID
	suite.mockTokenRepo.On("GetUserIDByRefreshToken", suite.ctx, refreshReq.RefreshToken).
		Return(user.UUID, nil)

	// Mock FindByUUID - Return the user
	suite.mockUserRepo.On("FindByUUID", suite.ctx, user.UUID).
		Return(user, nil)

	// Mock DeleteRefreshToken - Delete the old refresh token
	suite.mockTokenRepo.On("DeleteRefreshToken", suite.ctx, refreshReq.RefreshToken).
		Return(nil)

	// Mock StoreRefreshToken - Store the new refresh token
	suite.mockTokenRepo.On("StoreRefreshToken",
		suite.ctx,
		user.UUID,
		mock.AnythingOfType("string"),
		suite.cfg.JWT.RefreshTokenExp).
		Return(nil)

	// Act
	result, err := suite.authUseCase.RefreshToken(suite.ctx, refreshReq)

	// Assert
	assert.NoError(suite.T(), err)
	assert.NotNil(suite.T(), result)
	assert.NotEmpty(suite.T(), result.AccessToken)
	assert.NotEmpty(suite.T(), result.RefreshToken)
	assert.Equal(suite.T(), "Bearer", result.TokenType)
	assert.Greater(suite.T(), result.ExpiresIn, int64(0))

	// Verify access token
	token, err := jwt.Parse(result.AccessToken, func(token *jwt.Token) (interface{}, error) {
		return []byte(suite.cfg.JWT.Secret), nil
	})
	assert.NoError(suite.T(), err)
	assert.True(suite.T(), token.Valid)

	// Verify mocks
	suite.mockTokenRepo.AssertExpectations(suite.T())
	suite.mockUserRepo.AssertExpectations(suite.T())
}

func (suite *AuthUseCaseTestSuite) TestRefreshToken_InvalidToken() {
	// Arrange
	refreshReq := &domain.RefreshTokenRequest{
		RefreshToken: "invalid-refresh-token",
	}

	// Mock GetUserIDByRefreshToken - Token not found
	suite.mockTokenRepo.On("GetUserIDByRefreshToken", suite.ctx, refreshReq.RefreshToken).
		Return("", errors.New("token not found"))

	// Act
	result, err := suite.authUseCase.RefreshToken(suite.ctx, refreshReq)

	// Assert
	assert.Error(suite.T(), err)
	assert.Nil(suite.T(), result)
	assert.Contains(suite.T(), err.Error(), "invalid or expired refresh token")

	// Verify mocks
	suite.mockTokenRepo.AssertExpectations(suite.T())
}

func (suite *AuthUseCaseTestSuite) TestLogout_Success() {
	// Arrange
	token := "valid-refresh-token"

	// Mock DeleteRefreshToken - Success
	suite.mockTokenRepo.On("DeleteRefreshToken", suite.ctx, token).
		Return(nil)

	// Act
	err := suite.authUseCase.Logout(suite.ctx, token)

	// Assert
	assert.NoError(suite.T(), err)

	// Verify mocks
	suite.mockTokenRepo.AssertExpectations(suite.T())
}

func (suite *AuthUseCaseTestSuite) TestGetUserProfile_Success() {
	// Arrange
	userID := "test-uuid"

	// Mock user
	user := &domain.User{
		ID:        1,
		UUID:      userID,
		Email:     "test@example.com",
		Username:  "testuser",
		FirstName: "Test",
		LastName:  "User",
		Role:      "user",
	}

	// Mock FindByUUID - Return the user
	suite.mockUserRepo.On("FindByUUID", suite.ctx, userID).
		Return(user, nil)

	// Act
	result, err := suite.authUseCase.GetUserProfile(suite.ctx, userID)

	// Assert
	assert.NoError(suite.T(), err)
	assert.NotNil(suite.T(), result)
	assert.Equal(suite.T(), user.UUID, result.UUID)
	assert.Equal(suite.T(), user.Email, result.Email)
	assert.Equal(suite.T(), user.Username, result.Username)
	assert.Equal(suite.T(), user.FirstName, result.FirstName)
	assert.Equal(suite.T(), user.LastName, result.LastName)
	assert.Equal(suite.T(), user.Role, result.Role)

	// Verify mocks
	suite.mockUserRepo.AssertExpectations(suite.T())
}

func (suite *AuthUseCaseTestSuite) TestGetUserProfile_UserNotFound() {
	// Arrange
	userID := "nonexistent-uuid"

	// Mock FindByUUID - User not found
	suite.mockUserRepo.On("FindByUUID", suite.ctx, userID).
		Return(nil, errors.New("user not found"))

	// Act
	result, err := suite.authUseCase.GetUserProfile(suite.ctx, userID)

	// Assert
	assert.Error(suite.T(), err)
	assert.Nil(suite.T(), result)
	assert.Contains(suite.T(), err.Error(), "user not found")

	// Verify mocks
	suite.mockUserRepo.AssertExpectations(suite.T())
}

func (suite *AuthUseCaseTestSuite) TestVerifyToken_ValidToken() {
	// Arrange - Create a valid JWT token
	claims := jwt.MapClaims{
		"sub":  "test-uuid",
		"name": "testuser",
		"exp":  time.Now().Add(time.Hour).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, _ := token.SignedString([]byte(suite.cfg.JWT.Secret))

	// Act
	resultClaims, err := suite.authUseCase.VerifyToken(tokenString)

	// Assert
	assert.NoError(suite.T(), err)
	assert.NotNil(suite.T(), resultClaims)
	assert.Equal(suite.T(), claims["sub"], resultClaims["sub"])
	assert.Equal(suite.T(), claims["name"], resultClaims["name"])
}

func (suite *AuthUseCaseTestSuite) TestVerifyToken_InvalidToken() {
	// Arrange - Create an invalid token (wrong signature)
	claims := jwt.MapClaims{
		"sub":  "test-uuid",
		"name": "testuser",
		"exp":  time.Now().Add(time.Hour).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, _ := token.SignedString([]byte("wrong-secret"))

	// Act
	resultClaims, err := suite.authUseCase.VerifyToken(tokenString)

	// Assert
	assert.Error(suite.T(), err)
	assert.Nil(suite.T(), resultClaims)
}

func (suite *AuthUseCaseTestSuite) TestVerifyToken_ExpiredToken() {
	// Arrange - Create an expired token
	claims := jwt.MapClaims{
		"sub":  "test-uuid",
		"name": "testuser",
		"exp":  time.Now().Add(-time.Hour).Unix(), // Expired 1 hour ago
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, _ := token.SignedString([]byte(suite.cfg.JWT.Secret))

	// Act
	resultClaims, err := suite.authUseCase.VerifyToken(tokenString)

	// Assert
	assert.Error(suite.T(), err)
	assert.Nil(suite.T(), resultClaims)
	// The actual error message is "Token is expired" with capital T
	assert.Contains(suite.T(), strings.ToLower(err.Error()), "token is expired")
}
