package usecase_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/regiwitanto/auth-service/config"
	"github.com/regiwitanto/auth-service/internal/domain"
	"github.com/regiwitanto/auth-service/internal/testutil/mocks"
	"github.com/regiwitanto/auth-service/internal/usecase"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

func setupAuthUseCase() (usecase.AuthUseCase, *mocks.MockUserRepository, *mocks.MockTokenRepository) {
	mockUserRepo := new(mocks.MockUserRepository)
	mockTokenRepo := new(mocks.MockTokenRepository)

	cfg := config.Config{
		JWT: config.JWTConfig{
			Secret:         "test-secret-key-for-jwt-token-that-is-long-enough",
			AccessTokenExp: 1 * time.Hour,
		},
		Server: config.ServerConfig{
			Port: 8080,
		},
	}

	authUseCase := usecase.NewAuthUseCase(mockUserRepo, mockTokenRepo, cfg)
	return authUseCase, mockUserRepo, mockTokenRepo
}

func TestRegister(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		// Create fresh mocks for this test
		mockUserRepo := new(mocks.MockUserRepository)
		mockTokenRepo := new(mocks.MockTokenRepository)

		// Setup request
		registerReq := &domain.RegisterRequest{
			Email:     "new@example.com",
			Username:  "newuser",
			Password:  "password123",
			FirstName: "New",
			LastName:  "User",
		}

		// Setup mock behavior
		// In FindByEmail and FindByUsername:
		// - Return nil for user (first return value) since user doesn't exist
		// - Return error for "not found" condition (second return value)

		// First check if email exists (should return nil user and error for "not found")
		mockUserRepo.On("FindByEmail", mock.Anything, registerReq.Email).
			Return(nil, errors.New("user not found"))

		// Then check if username exists (should return nil user and error for "not found")
		mockUserRepo.On("FindByUsername", mock.Anything, registerReq.Username).
			Return(nil, errors.New("user not found"))

		// Then create the user
		mockUserRepo.On("Create", mock.Anything, mock.MatchedBy(func(u *domain.User) bool {
			// Password should be hashed
			err := bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(registerReq.Password))
			return u.Email == registerReq.Email &&
				u.Username == registerReq.Username &&
				u.FirstName == registerReq.FirstName &&
				u.LastName == registerReq.LastName &&
				u.Role == "user" &&
				err == nil // Password was correctly hashed
		})).Return(nil)

		// Create the use case with our mocks
		cfg := config.Config{
			JWT: config.JWTConfig{
				Secret:         "test-secret-key-for-jwt-token-that-is-long-enough",
				AccessTokenExp: 1 * time.Hour,
			},
		}
		authUseCase := usecase.NewAuthUseCase(mockUserRepo, mockTokenRepo, cfg)

		// Call the use case
		response, err := authUseCase.Register(context.Background(), registerReq)

		// Assertions
		require.NoError(t, err)
		require.NotNil(t, response)
		assert.Equal(t, registerReq.Email, response.Email)
		assert.Equal(t, registerReq.Username, response.Username)
		assert.Equal(t, registerReq.FirstName, response.FirstName)
		assert.Equal(t, registerReq.LastName, response.LastName)
		assert.Equal(t, "user", response.Role)
		assert.NotEmpty(t, response.UUID)

		// Verify mock expectations
		mockUserRepo.AssertExpectations(t)
	})

	t.Run("Email Already Exists", func(t *testing.T) {
		// Create fresh mocks for this test
		mockUserRepo := new(mocks.MockUserRepository)
		mockTokenRepo := new(mocks.MockTokenRepository)

		// Setup request
		registerReq := &domain.RegisterRequest{
			Email:     "existing@example.com",
			Username:  "newuser",
			Password:  "password123",
			FirstName: "New",
			LastName:  "User",
		}

		// Setup mock behavior - Email exists
		existingUser := &domain.User{
			ID:       1,
			UUID:     "existing-uuid",
			Email:    registerReq.Email,
			Username: "existinguser",
		}
		mockUserRepo.On("FindByEmail", mock.Anything, registerReq.Email).
			Return(existingUser, nil)

		// Create the use case with our mocks
		cfg := config.Config{
			JWT: config.JWTConfig{
				Secret:         "test-secret-key-for-jwt-token-that-is-long-enough",
				AccessTokenExp: 1 * time.Hour,
			},
		}
		authUseCase := usecase.NewAuthUseCase(mockUserRepo, mockTokenRepo, cfg)

		// Call the use case
		response, err := authUseCase.Register(context.Background(), registerReq)

		// Assertions
		require.Error(t, err)
		assert.Contains(t, err.Error(), "already exists")
		assert.Nil(t, response)

		// Verify mock expectations
		mockUserRepo.AssertExpectations(t)
	})

	t.Run("Username Already Exists", func(t *testing.T) {
		// Create fresh mocks for this test
		mockUserRepo := new(mocks.MockUserRepository)
		mockTokenRepo := new(mocks.MockTokenRepository)

		// Setup request
		registerReq := &domain.RegisterRequest{
			Email:     "new@example.com",
			Username:  "existinguser",
			Password:  "password123",
			FirstName: "New",
			LastName:  "User",
		}

		// Setup mock behavior
		// Email doesn't exist
		mockUserRepo.On("FindByEmail", mock.Anything, registerReq.Email).
			Return(nil, errors.New("user not found"))

		// But username exists
		existingUser := &domain.User{
			ID:       1,
			UUID:     "existing-uuid",
			Email:    "other@example.com",
			Username: registerReq.Username,
		}
		mockUserRepo.On("FindByUsername", mock.Anything, registerReq.Username).
			Return(existingUser, nil)

		// Create the use case with our mocks
		cfg := config.Config{
			JWT: config.JWTConfig{
				Secret:         "test-secret-key-for-jwt-token-that-is-long-enough",
				AccessTokenExp: 1 * time.Hour,
			},
		}
		authUseCase := usecase.NewAuthUseCase(mockUserRepo, mockTokenRepo, cfg)

		// Call the use case
		response, err := authUseCase.Register(context.Background(), registerReq)

		// Assertions
		require.Error(t, err)
		assert.Contains(t, err.Error(), "already exists")
		assert.Nil(t, response)

		// Verify mock expectations
		mockUserRepo.AssertExpectations(t)
	})

	t.Run("Database Error", func(t *testing.T) {
		// Create fresh mocks for this test
		mockUserRepo := new(mocks.MockUserRepository)
		mockTokenRepo := new(mocks.MockTokenRepository)

		// Setup request
		registerReq := &domain.RegisterRequest{
			Email:     "new@example.com",
			Username:  "newuser",
			Password:  "password123",
			FirstName: "New",
			LastName:  "User",
		}

		// Setup mock behavior
		mockUserRepo.On("FindByEmail", mock.Anything, registerReq.Email).
			Return(nil, errors.New("user not found"))
		mockUserRepo.On("FindByUsername", mock.Anything, registerReq.Username).
			Return(nil, errors.New("user not found"))
		mockUserRepo.On("Create", mock.Anything, mock.AnythingOfType("*domain.User")).
			Return(errors.New("database error"))

		// Create the use case with our mocks
		cfg := config.Config{
			JWT: config.JWTConfig{
				Secret:         "test-secret-key-for-jwt-token-that-is-long-enough",
				AccessTokenExp: 1 * time.Hour,
			},
		}
		authUseCase := usecase.NewAuthUseCase(mockUserRepo, mockTokenRepo, cfg)

		// Call the use case
		response, err := authUseCase.Register(context.Background(), registerReq)

		// Assertions
		require.Error(t, err)
		assert.Nil(t, response)

		// Verify mock expectations
		mockUserRepo.AssertExpectations(t)
	})
}

func TestLogin(t *testing.T) {
	_, mockUserRepo, mockTokenRepo := setupAuthUseCase()

	// Mock user with hashed password
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.DefaultCost)
	mockUser := &domain.User{
		ID:        1,
		UUID:      "test-uuid",
		Email:     "test@example.com",
		Username:  "testuser",
		Password:  string(hashedPassword),
		FirstName: "Test",
		LastName:  "User",
		Role:      "user",
	}

	t.Run("Success with Email", func(t *testing.T) {
		// Reset mocks
		mockUserRepo.ExpectedCalls = nil
		mockTokenRepo.ExpectedCalls = nil

		// Setup request
		loginReq := &domain.LoginRequest{
			Email:    "test@example.com",
			Password: "password123",
		}

		// Setup mock behavior
		mockUserRepo.On("FindByEmail", mock.Anything, loginReq.Email).
			Return(mockUser, nil)

		// Should store refresh token
		mockTokenRepo.On("StoreRefreshToken", mock.Anything, mockUser.UUID, mock.AnythingOfType("string"), mock.AnythingOfType("time.Duration")).
			Return(nil)

		// Call the use case
		authUseCase, _, _ := setupAuthUseCase()
		response, err := authUseCase.Login(context.Background(), loginReq)

		// Assertions
		require.NoError(t, err)
		require.NotNil(t, response)
		assert.NotEmpty(t, response.AccessToken)
		assert.NotEmpty(t, response.RefreshToken)
		assert.Equal(t, "Bearer", response.TokenType)
		assert.True(t, response.ExpiresIn > 0)

		// Verify token validity
		token, err := jwt.Parse(response.AccessToken, func(token *jwt.Token) (interface{}, error) {
			return []byte("test-secret-key-for-jwt-token-that-is-long-enough"), nil
		})
		require.NoError(t, err)
		require.True(t, token.Valid)

		// Check claims
		claims := token.Claims.(jwt.MapClaims)
		assert.Equal(t, mockUser.UUID, claims["sub"])
		assert.Equal(t, mockUser.Role, claims["role"])

		// Verify mock expectations
		mockUserRepo.AssertExpectations(t)
		mockTokenRepo.AssertExpectations(t)
	})

	t.Run("Invalid Password", func(t *testing.T) {
		// Reset mocks
		mockUserRepo.ExpectedCalls = nil
		mockTokenRepo.ExpectedCalls = nil

		// Setup request with wrong password
		loginReq := &domain.LoginRequest{
			Email:    "test@example.com",
			Password: "wrongpassword",
		}

		// Setup mock behavior
		mockUserRepo.On("FindByEmail", mock.Anything, loginReq.Email).
			Return(mockUser, nil)

		// Call the use case
		authUseCase, _, _ := setupAuthUseCase()
		response, err := authUseCase.Login(context.Background(), loginReq)

		// Assertions
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid")
		assert.Nil(t, response)

		// Verify mock expectations
		mockUserRepo.AssertExpectations(t)
		mockTokenRepo.AssertExpectations(t)
	})

	t.Run("User Not Found", func(t *testing.T) {
		// Reset mocks
		mockUserRepo.ExpectedCalls = nil

		// Setup request
		loginReq := &domain.LoginRequest{
			Email:    "nonexistent@example.com",
			Password: "password123",
		}

		// Setup mock behavior
		mockUserRepo.On("FindByEmail", mock.Anything, loginReq.Email).
			Return(nil, errors.New("user not found"))

		// Call the use case
		authUseCase, _, _ := setupAuthUseCase()
		response, err := authUseCase.Login(context.Background(), loginReq)

		// Assertions
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not found")
		assert.Nil(t, response)

		// Verify mock expectations
		mockUserRepo.AssertExpectations(t)
	})
}

func TestRefreshToken(t *testing.T) {
	_, mockUserRepo, mockTokenRepo := setupAuthUseCase()

	t.Run("Success", func(t *testing.T) {
		// Reset mocks
		mockUserRepo.ExpectedCalls = nil
		mockTokenRepo.ExpectedCalls = nil

		// Setup
		userID := "test-uuid"
		refreshToken := "valid-refresh-token"

		mockUser := &domain.User{
			ID:        1,
			UUID:      userID,
			Email:     "test@example.com",
			Username:  "testuser",
			FirstName: "Test",
			LastName:  "User",
			Role:      "user",
		}

		// Setup mock behavior
		mockTokenRepo.On("GetUserIDByRefreshToken", mock.Anything, refreshToken).
			Return(userID, nil)

		mockUserRepo.On("FindByUUID", mock.Anything, userID).
			Return(mockUser, nil)

		// Should store a new refresh token
		mockTokenRepo.On("StoreRefreshToken", mock.Anything, userID, mock.AnythingOfType("string"), mock.AnythingOfType("time.Duration")).
			Return(nil)

		// Should delete the old refresh token
		mockTokenRepo.On("DeleteRefreshToken", mock.Anything, refreshToken).
			Return(nil)

		// Call the use case
		authUseCase, _, _ := setupAuthUseCase()
		response, err := authUseCase.RefreshToken(context.Background(), &domain.RefreshTokenRequest{
			RefreshToken: refreshToken,
		})

		// Assertions
		require.NoError(t, err)
		require.NotNil(t, response)
		assert.NotEmpty(t, response.AccessToken)
		assert.NotEmpty(t, response.RefreshToken)
		assert.NotEqual(t, refreshToken, response.RefreshToken) // New refresh token should be different
		assert.Equal(t, "Bearer", response.TokenType)
		assert.True(t, response.ExpiresIn > 0)

		// Verify mock expectations
		mockUserRepo.AssertExpectations(t)
		mockTokenRepo.AssertExpectations(t)
	})

	t.Run("Invalid Refresh Token", func(t *testing.T) {
		// Reset mocks
		mockTokenRepo.ExpectedCalls = nil

		// Setup
		refreshToken := "invalid-refresh-token"

		// Setup mock behavior
		mockTokenRepo.On("GetUserIDByRefreshToken", mock.Anything, refreshToken).
			Return("", errors.New("token not found or expired"))

		// Call the use case
		authUseCase, _, _ := setupAuthUseCase()
		response, err := authUseCase.RefreshToken(context.Background(), &domain.RefreshTokenRequest{
			RefreshToken: refreshToken,
		})

		// Assertions
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid refresh token")
		assert.Nil(t, response)

		// Verify mock expectations
		mockTokenRepo.AssertExpectations(t)
	})
}

func TestLogout(t *testing.T) {
	_, _, mockTokenRepo := setupAuthUseCase()

	t.Run("Success", func(t *testing.T) {
		// Reset mocks
		mockTokenRepo.ExpectedCalls = nil

		// Setup
		refreshToken := "valid-refresh-token"

		// Setup mock behavior
		mockTokenRepo.On("DeleteRefreshToken", mock.Anything, refreshToken).
			Return(nil)

		// Call the use case
		authUseCase, _, _ := setupAuthUseCase()
		err := authUseCase.Logout(context.Background(), refreshToken)

		// Assertions
		require.NoError(t, err)

		// Verify mock expectations
		mockTokenRepo.AssertExpectations(t)
	})

	t.Run("Token Not Found", func(t *testing.T) {
		// Reset mocks
		mockTokenRepo.ExpectedCalls = nil

		// Setup
		refreshToken := "invalid-refresh-token"

		// Setup mock behavior
		mockTokenRepo.On("DeleteRefreshToken", mock.Anything, refreshToken).
			Return(errors.New("token not found"))

		// Call the use case
		authUseCase, _, _ := setupAuthUseCase()
		err := authUseCase.Logout(context.Background(), refreshToken)

		// Assertions
		require.Error(t, err)
		assert.Contains(t, err.Error(), "token not found")

		// Verify mock expectations
		mockTokenRepo.AssertExpectations(t)
	})
}

func TestVerifyToken(t *testing.T) {
	t.Run("Valid Token", func(t *testing.T) {
		// Setup
		authUseCase, _, _ := setupAuthUseCase()

		// Create a valid token
		claims := jwt.MapClaims{
			"sub":  "test-uuid",
			"role": "user",
			"iat":  time.Now().Unix(),
			"exp":  time.Now().Add(time.Hour).Unix(),
			"iss":  "auth-service-test",
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		signedToken, err := token.SignedString([]byte("test-secret-key-for-jwt-token-that-is-long-enough"))
		require.NoError(t, err)

		// Call the use case
		verifiedClaims, err := authUseCase.VerifyToken(signedToken)

		// Assertions
		require.NoError(t, err)
		assert.Equal(t, claims["sub"], verifiedClaims["sub"])
		assert.Equal(t, claims["role"], verifiedClaims["role"])
	})

	t.Run("Invalid Token Format", func(t *testing.T) {
		// Setup
		authUseCase, _, _ := setupAuthUseCase()

		// Call with invalid token
		verifiedClaims, err := authUseCase.VerifyToken("invalid-token-format")

		// Assertions
		require.Error(t, err)
		assert.Nil(t, verifiedClaims)
	})

	t.Run("Expired Token", func(t *testing.T) {
		// Setup
		authUseCase, _, _ := setupAuthUseCase()

		// Create an expired token
		claims := jwt.MapClaims{
			"sub":  "test-uuid",
			"role": "user",
			"iat":  time.Now().Add(-2 * time.Hour).Unix(),
			"exp":  time.Now().Add(-1 * time.Hour).Unix(), // Expired 1 hour ago
			"iss":  "auth-service-test",
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		signedToken, err := token.SignedString([]byte("test-secret-key-for-jwt-token-that-is-long-enough"))
		require.NoError(t, err)

		// Call the use case
		verifiedClaims, err := authUseCase.VerifyToken(signedToken)

		// Assertions
		require.Error(t, err)
		assert.Nil(t, verifiedClaims)
		assert.Contains(t, err.Error(), "expired")
	})
}
