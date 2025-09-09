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
		mockUserRepo := new(mocks.MockUserRepository)
		mockTokenRepo := new(mocks.MockTokenRepository)

		registerReq := &domain.RegisterRequest{
			Email:     "new@example.com",
			Username:  "newuser",
			Password:  "password123",
			FirstName: "New",
			LastName:  "User",
		}

		mockUserRepo.On("FindByEmail", mock.Anything, registerReq.Email).
			Return(nil, errors.New("user not found"))

		mockUserRepo.On("FindByUsername", mock.Anything, registerReq.Username).
			Return(nil, errors.New("user not found"))

		mockUserRepo.On("Create", mock.Anything, mock.MatchedBy(func(u *domain.User) bool {
			err := bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(registerReq.Password))
			u.UUID = "test-uuid-12345"
			return u.Email == registerReq.Email &&
				u.Username == registerReq.Username &&
				u.FirstName == registerReq.FirstName &&
				u.LastName == registerReq.LastName &&
				u.Role == "user" &&
				err == nil
		})).Return(nil)

		cfg := config.Config{
			JWT: config.JWTConfig{
				Secret:         "test-secret-key-for-jwt-token-that-is-long-enough",
				AccessTokenExp: 1 * time.Hour,
			},
		}
		authUseCase := usecase.NewAuthUseCase(mockUserRepo, mockTokenRepo, cfg)

		response, err := authUseCase.Register(context.Background(), registerReq)

		require.NoError(t, err)
		require.NotNil(t, response)
		assert.Equal(t, registerReq.Email, response.Email)
		assert.Equal(t, registerReq.Username, response.Username)
		assert.Equal(t, registerReq.FirstName, response.FirstName)
		assert.Equal(t, registerReq.LastName, response.LastName)
		assert.Equal(t, "user", response.Role)
		assert.NotEmpty(t, response.UUID)

		mockUserRepo.AssertExpectations(t)
	})

	t.Run("Email Already Exists", func(t *testing.T) {
		mockUserRepo := new(mocks.MockUserRepository)
		mockTokenRepo := new(mocks.MockTokenRepository)

		registerReq := &domain.RegisterRequest{
			Email:     "existing@example.com",
			Username:  "newuser",
			Password:  "password123",
			FirstName: "New",
			LastName:  "User",
		}

		existingUser := &domain.User{
			ID:       1,
			UUID:     "existing-uuid",
			Email:    registerReq.Email,
			Username: "existinguser",
		}
		mockUserRepo.On("FindByEmail", mock.Anything, registerReq.Email).
			Return(existingUser, nil)

		cfg := config.Config{
			JWT: config.JWTConfig{
				Secret:         "test-secret-key-for-jwt-token-that-is-long-enough",
				AccessTokenExp: 1 * time.Hour,
			},
		}
		authUseCase := usecase.NewAuthUseCase(mockUserRepo, mockTokenRepo, cfg)

		response, err := authUseCase.Register(context.Background(), registerReq)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "already exists")
		assert.Nil(t, response)

		// Verify mock expectations
		mockUserRepo.AssertExpectations(t)
	})

	t.Run("Username Already Exists", func(t *testing.T) {
		mockUserRepo := new(mocks.MockUserRepository)
		mockTokenRepo := new(mocks.MockTokenRepository)

		registerReq := &domain.RegisterRequest{
			Email:     "new@example.com",
			Username:  "existinguser",
			Password:  "password123",
			FirstName: "New",
			LastName:  "User",
		}

		mockUserRepo.On("FindByEmail", mock.Anything, registerReq.Email).
			Return(nil, errors.New("user not found"))
		existingUser := &domain.User{
			ID:       1,
			UUID:     "existing-uuid",
			Email:    "other@example.com",
			Username: registerReq.Username,
		}
		mockUserRepo.On("FindByUsername", mock.Anything, registerReq.Username).
			Return(existingUser, nil)

		cfg := config.Config{
			JWT: config.JWTConfig{
				Secret:         "test-secret-key-for-jwt-token-that-is-long-enough",
				AccessTokenExp: 1 * time.Hour,
			},
		}
		authUseCase := usecase.NewAuthUseCase(mockUserRepo, mockTokenRepo, cfg)

		// Call the use case
		response, err := authUseCase.Register(context.Background(), registerReq)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "already exists")
		assert.Nil(t, response)

		// Verify mock expectations
		mockUserRepo.AssertExpectations(t)
	})

	t.Run("Database Error", func(t *testing.T) {
		mockUserRepo := new(mocks.MockUserRepository)
		mockTokenRepo := new(mocks.MockTokenRepository)

		registerReq := &domain.RegisterRequest{
			Email:     "new@example.com",
			Username:  "newuser",
			Password:  "password123",
			FirstName: "New",
			LastName:  "User",
		}
		mockUserRepo.On("FindByEmail", mock.Anything, registerReq.Email).
			Return(nil, errors.New("user not found"))
		mockUserRepo.On("FindByUsername", mock.Anything, registerReq.Username).
			Return(nil, errors.New("user not found"))
		mockUserRepo.On("Create", mock.Anything, mock.AnythingOfType("*domain.User")).
			Return(errors.New("database error"))

		cfg := config.Config{
			JWT: config.JWTConfig{
				Secret:         "test-secret-key-for-jwt-token-that-is-long-enough",
				AccessTokenExp: 1 * time.Hour,
			},
		}
		authUseCase := usecase.NewAuthUseCase(mockUserRepo, mockTokenRepo, cfg)

		response, err := authUseCase.Register(context.Background(), registerReq)

		// Assertions
		require.Error(t, err)
		assert.Nil(t, response)

		// Verify mock expectations
		mockUserRepo.AssertExpectations(t)
	})
}

func TestLogin(t *testing.T) {
	t.Run("Success with Email", func(t *testing.T) {
		mockUserRepo := new(mocks.MockUserRepository)
		mockTokenRepo := new(mocks.MockTokenRepository)

		cfg := config.Config{
			JWT: config.JWTConfig{
				Secret:         "test-secret-key-for-jwt-token-that-is-long-enough",
				AccessTokenExp: 1 * time.Hour,
			},
		}

		authUseCase := usecase.NewAuthUseCase(mockUserRepo, mockTokenRepo, cfg)
		loginReq := &domain.LoginRequest{
			Email:    "test@example.com",
			Password: "password123",
		}
		hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.DefaultCost)
		mockUser := &domain.User{
			ID:        1,
			UUID:      "user-123",
			Email:     "test@example.com",
			Username:  "testuser",
			Password:  string(hashedPassword),
			FirstName: "Test",
			LastName:  "User",
			Role:      "user",
			Active:    true,
		}

		mockUserRepo.On("FindByEmail", mock.Anything, loginReq.Email).
			Return(mockUser, nil)
		mockTokenRepo.On("StoreRefreshToken", mock.Anything, mockUser.UUID, mock.AnythingOfType("string"), mock.AnythingOfType("time.Duration")).
			Return(nil)

		response, err := authUseCase.Login(context.Background(), loginReq)
		require.NoError(t, err)
		require.NotNil(t, response)
		assert.NotEmpty(t, response.AccessToken)
		assert.NotEmpty(t, response.RefreshToken)
		assert.Equal(t, "Bearer", response.TokenType)
		assert.True(t, response.ExpiresIn > 0)

		token, err := jwt.Parse(response.AccessToken, func(token *jwt.Token) (interface{}, error) {
			return []byte("test-secret-key-for-jwt-token-that-is-long-enough"), nil
		})
		require.NoError(t, err)
		require.True(t, token.Valid)
		claims := token.Claims.(jwt.MapClaims)
		assert.Equal(t, mockUser.UUID, claims["sub"])
		assert.Equal(t, mockUser.Role, claims["role"])

		mockUserRepo.AssertExpectations(t)
		mockTokenRepo.AssertExpectations(t)
	})

	t.Run("Invalid Password", func(t *testing.T) {
		mockUserRepo := new(mocks.MockUserRepository)
		mockTokenRepo := new(mocks.MockTokenRepository)

		cfg := config.Config{
			JWT: config.JWTConfig{
				Secret:         "test-secret-key-for-jwt-token-that-is-long-enough",
				AccessTokenExp: 1 * time.Hour,
			},
		}

		authUseCase := usecase.NewAuthUseCase(mockUserRepo, mockTokenRepo, cfg)
		loginReq := &domain.LoginRequest{
			Email:    "test@example.com",
			Password: "wrongpassword",
		}
		hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.DefaultCost)
		mockUser := &domain.User{
			ID:        1,
			UUID:      "user-123",
			Email:     "test@example.com",
			Username:  "testuser",
			Password:  string(hashedPassword),
			FirstName: "Test",
			LastName:  "User",
			Role:      "user",
			Active:    true,
		}
		mockUserRepo.On("FindByEmail", mock.Anything, loginReq.Email).
			Return(mockUser, nil)

		response, err := authUseCase.Login(context.Background(), loginReq)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid email or password")
		assert.Nil(t, response)

		// Verify mock expectations
		mockUserRepo.AssertExpectations(t)
		mockTokenRepo.AssertExpectations(t)
	})

	t.Run("User Not Found", func(t *testing.T) {
		mockUserRepo := new(mocks.MockUserRepository)
		mockTokenRepo := new(mocks.MockTokenRepository)

		cfg := config.Config{
			JWT: config.JWTConfig{
				Secret:         "test-secret-key-for-jwt-token-that-is-long-enough",
				AccessTokenExp: 1 * time.Hour,
			},
		}

		authUseCase := usecase.NewAuthUseCase(mockUserRepo, mockTokenRepo, cfg)
		loginReq := &domain.LoginRequest{
			Email:    "nonexistent@example.com",
			Password: "password123",
		}
		mockUserRepo.On("FindByEmail", mock.Anything, loginReq.Email).
			Return(nil, errors.New("user not found"))

		response, err := authUseCase.Login(context.Background(), loginReq)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid email or password")
		assert.Nil(t, response)

		// Verify mock expectations
		mockUserRepo.AssertExpectations(t)
		mockTokenRepo.AssertExpectations(t)
	})
}

func TestRefreshToken(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		mockUserRepo := new(mocks.MockUserRepository)
		mockTokenRepo := new(mocks.MockTokenRepository)

		cfg := config.Config{
			JWT: config.JWTConfig{
				Secret:          "test-secret-key-for-jwt-token-that-is-long-enough",
				AccessTokenExp:  1 * time.Hour,
				RefreshTokenExp: 24 * time.Hour,
			},
		}

		authUseCase := usecase.NewAuthUseCase(mockUserRepo, mockTokenRepo, cfg)

		refreshReq := &domain.RefreshTokenRequest{
			RefreshToken: "valid-refresh-token",
		}
		mockTokenRepo.On("GetUserIDByRefreshToken", mock.Anything, "valid-refresh-token").
			Return("user-123", nil)

		mockUser := &domain.User{
			ID:        1,
			UUID:      "user-123",
			Email:     "test@example.com",
			Username:  "testuser",
			FirstName: "Test",
			LastName:  "User",
			Role:      "user",
			Active:    true,
		}

		mockUserRepo.On("FindByUUID", mock.Anything, "user-123").
			Return(mockUser, nil)
		mockTokenRepo.On("DeleteRefreshToken", mock.Anything, "valid-refresh-token").
			Return(nil)
		mockTokenRepo.On("StoreRefreshToken", mock.Anything, "user-123", mock.AnythingOfType("string"), mock.AnythingOfType("time.Duration")).
			Return(nil)

		response, err := authUseCase.RefreshToken(context.Background(), refreshReq)
		require.NoError(t, err)
		require.NotNil(t, response)
		assert.NotEmpty(t, response.AccessToken)
		assert.NotEmpty(t, response.RefreshToken)
		assert.Equal(t, "Bearer", response.TokenType)
		assert.True(t, response.ExpiresIn > 0)

		// Verify mock expectations
		mockUserRepo.AssertExpectations(t)
		mockTokenRepo.AssertExpectations(t)
	})

	t.Run("Invalid Refresh Token", func(t *testing.T) {
		mockUserRepo := new(mocks.MockUserRepository)
		mockTokenRepo := new(mocks.MockTokenRepository)

		cfg := config.Config{
			JWT: config.JWTConfig{
				Secret:         "test-secret-key-for-jwt-token-that-is-long-enough",
				AccessTokenExp: 1 * time.Hour,
			},
		}

		authUseCase := usecase.NewAuthUseCase(mockUserRepo, mockTokenRepo, cfg)

		refreshReq := &domain.RefreshTokenRequest{
			RefreshToken: "invalid-refresh-token",
		}
		mockTokenRepo.On("GetUserIDByRefreshToken", mock.Anything, "invalid-refresh-token").
			Return("", errors.New("token not found"))

		response, err := authUseCase.RefreshToken(context.Background(), refreshReq)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid or expired refresh token")
		assert.Nil(t, response)

		mockUserRepo.AssertExpectations(t)
		mockTokenRepo.AssertExpectations(t)
	})
}

func TestLogout(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		mockUserRepo := new(mocks.MockUserRepository)
		mockTokenRepo := new(mocks.MockTokenRepository)
		cfg := config.Config{
			JWT: config.JWTConfig{
				Secret:         "test-secret-key-for-jwt-token-that-is-long-enough",
				AccessTokenExp: 1 * time.Hour,
			},
		}

		refreshToken := "valid-refresh-token"
		mockTokenRepo.On("DeleteRefreshToken", mock.Anything, refreshToken).
			Return(nil)

		authUseCase := usecase.NewAuthUseCase(mockUserRepo, mockTokenRepo, cfg)

		err := authUseCase.Logout(context.Background(), refreshToken)
		require.NoError(t, err)

		mockTokenRepo.AssertExpectations(t)
	})

	t.Run("Token Not Found", func(t *testing.T) {
		mockUserRepo := new(mocks.MockUserRepository)
		mockTokenRepo := new(mocks.MockTokenRepository)
		cfg := config.Config{
			JWT: config.JWTConfig{
				Secret:         "test-secret-key-for-jwt-token-that-is-long-enough",
				AccessTokenExp: 1 * time.Hour,
			},
		}

		refreshToken := "invalid-refresh-token"
		mockTokenRepo.On("DeleteRefreshToken", mock.Anything, refreshToken).
			Return(errors.New("token not found"))

		authUseCase := usecase.NewAuthUseCase(mockUserRepo, mockTokenRepo, cfg)

		err := authUseCase.Logout(context.Background(), refreshToken)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "token not found")

		mockTokenRepo.AssertExpectations(t)
	})
}

func TestVerifyToken(t *testing.T) {
	t.Run("Valid Token", func(t *testing.T) {
		authUseCase, _, _ := setupAuthUseCase()
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

		verifiedClaims, err := authUseCase.VerifyToken(signedToken)

		require.NoError(t, err)
		assert.Equal(t, claims["sub"], verifiedClaims["sub"])
		assert.Equal(t, claims["role"], verifiedClaims["role"])
	})

	t.Run("Invalid Token Format", func(t *testing.T) {
		authUseCase, _, _ := setupAuthUseCase()

		verifiedClaims, err := authUseCase.VerifyToken("invalid-token-format")
		require.Error(t, err)
		assert.Nil(t, verifiedClaims)
	})

	t.Run("Expired Token", func(t *testing.T) {
		authUseCase, _, _ := setupAuthUseCase()
		claims := jwt.MapClaims{
			"sub":  "test-uuid",
			"role": "user",
			"iat":  time.Now().Add(-2 * time.Hour).Unix(),
			"exp":  time.Now().Add(-1 * time.Hour).Unix(),
			"iss":  "auth-service-test",
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		signedToken, err := token.SignedString([]byte("test-secret-key-for-jwt-token-that-is-long-enough"))
		require.NoError(t, err)

		verifiedClaims, err := authUseCase.VerifyToken(signedToken)

		require.Error(t, err)
		assert.Nil(t, verifiedClaims)
		assert.Contains(t, err.Error(), "expired")
	})
}
