package usecase_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/regiwitanto/auth-service/config"
	"github.com/regiwitanto/auth-service/internal/domain"
	"github.com/regiwitanto/auth-service/internal/testutil/mocks"
	"github.com/regiwitanto/auth-service/internal/usecase"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestForgotPassword(t *testing.T) {
	// Setup mocks
	mockUserRepo := new(mocks.MockUserRepository)
	mockTokenRepo := new(mocks.MockTokenRepository)

	// Setup config
	cfg := config.Config{
		Server: config.ServerConfig{
			BaseURL: "http://localhost:8080",
		},
	}

	// Create use case
	authUseCase := usecase.NewAuthUseCase(mockUserRepo, mockTokenRepo, cfg)

	// Setup test cases
	tests := []struct {
		name          string
		email         string
		setupMocks    func()
		expectedError bool
	}{
		{
			name:  "Success",
			email: "test@example.com",
			setupMocks: func() {
				// User exists
				mockUserRepo.On("FindByEmail", mock.Anything, "test@example.com").Return(&domain.User{
					ID:    1,
					Email: "test@example.com",
				}, nil)

				// Token should be stored (any string token will work)
				mockTokenRepo.On("StorePasswordResetToken",
					mock.Anything,
					"test@example.com",
					mock.AnythingOfType("string"),
					15*time.Minute,
				).Return(nil)
			},
			expectedError: false,
		},
		{
			name:  "User Not Found",
			email: "nonexistent@example.com",
			setupMocks: func() {
				// User doesn't exist - but we don't reveal this for security
				mockUserRepo.On("FindByEmail", mock.Anything, "nonexistent@example.com").
					Return(nil, errors.New("user not found"))

				// Should not call token repo
			},
			expectedError: false, // still returns success for security
		},
		{
			name:  "Token Storage Error",
			email: "test@example.com",
			setupMocks: func() {
				// User exists
				mockUserRepo.On("FindByEmail", mock.Anything, "test@example.com").Return(&domain.User{
					ID:    1,
					Email: "test@example.com",
				}, nil)

				// Error storing token
				mockTokenRepo.On("StorePasswordResetToken",
					mock.Anything,
					"test@example.com",
					mock.AnythingOfType("string"),
					15*time.Minute,
				).Return(errors.New("redis error"))
			},
			expectedError: true,
		},
	}

	// Run tests
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Reset mocks
			mockUserRepo.ExpectedCalls = nil
			mockTokenRepo.ExpectedCalls = nil
			mockUserRepo.Calls = nil
			mockTokenRepo.Calls = nil

			// Setup mocks
			test.setupMocks()

			// Execute
			err := authUseCase.ForgotPassword(context.Background(), &domain.ForgotPasswordRequest{
				Email: test.email,
			})

			// Assert
			if test.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			// Verify mocks
			mockUserRepo.AssertExpectations(t)
			mockTokenRepo.AssertExpectations(t)
		})
	}
}

func TestResetPassword(t *testing.T) {
	// Setup mocks
	mockUserRepo := new(mocks.MockUserRepository)
	mockTokenRepo := new(mocks.MockTokenRepository)

	// Setup config
	cfg := config.Config{}

	// Create use case
	authUseCase := usecase.NewAuthUseCase(mockUserRepo, mockTokenRepo, cfg)

	// Setup test cases
	tests := []struct {
		name          string
		token         string
		password      string
		setupMocks    func()
		expectedError bool
	}{
		{
			name:     "Success",
			token:    "valid-token",
			password: "newPassword123",
			setupMocks: func() {
				// Token is valid
				mockTokenRepo.On("GetEmailByResetToken", mock.Anything, "valid-token").
					Return("test@example.com", nil)

				// Password update
				mockUserRepo.On("UpdatePassword", mock.Anything, "test@example.com", mock.AnythingOfType("string")).
					Return(nil)

				// Token deletion
				mockTokenRepo.On("DeletePasswordResetToken", mock.Anything, "valid-token").
					Return(nil)
			},
			expectedError: false,
		},
		{
			name:     "Invalid Token",
			token:    "invalid-token",
			password: "newPassword123",
			setupMocks: func() {
				// Token is invalid
				mockTokenRepo.On("GetEmailByResetToken", mock.Anything, "invalid-token").
					Return("", errors.New("token not found"))

				// Should not call other methods
			},
			expectedError: true,
		},
		{
			name:     "Password Update Error",
			token:    "valid-token",
			password: "newPassword123",
			setupMocks: func() {
				// Token is valid
				mockTokenRepo.On("GetEmailByResetToken", mock.Anything, "valid-token").
					Return("test@example.com", nil)

				// Password update fails
				mockUserRepo.On("UpdatePassword", mock.Anything, "test@example.com", mock.AnythingOfType("string")).
					Return(errors.New("database error"))

				// Should not call token deletion
			},
			expectedError: true,
		},
	}

	// Run tests
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Reset mocks
			mockUserRepo.ExpectedCalls = nil
			mockTokenRepo.ExpectedCalls = nil
			mockUserRepo.Calls = nil
			mockTokenRepo.Calls = nil

			// Setup mocks
			test.setupMocks()

			// Execute
			err := authUseCase.ResetPassword(context.Background(), &domain.ResetPasswordRequest{
				Token:    test.token,
				Password: test.password,
			})

			// Assert
			if test.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			// Verify mocks
			mockUserRepo.AssertExpectations(t)
			mockTokenRepo.AssertExpectations(t)
		})
	}
}
