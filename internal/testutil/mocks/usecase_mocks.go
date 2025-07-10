package mocks

import (
	"context"

	"github.com/regiwitanto/auth-service/internal/domain"
	"github.com/stretchr/testify/mock"
)

// MockAuthUseCase is a mock implementation of the AuthUseCase interface
type MockAuthUseCase struct {
	mock.Mock
}

// Register mocks the Register method
func (m *MockAuthUseCase) Register(ctx context.Context, request *domain.RegisterRequest) (*domain.UserResponse, error) {
	args := m.Called(ctx, request)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.UserResponse), args.Error(1)
}

// Login mocks the Login method
func (m *MockAuthUseCase) Login(ctx context.Context, request *domain.LoginRequest) (*domain.TokenResponse, error) {
	args := m.Called(ctx, request)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.TokenResponse), args.Error(1)
}

// RefreshToken mocks the RefreshToken method
func (m *MockAuthUseCase) RefreshToken(ctx context.Context, request *domain.RefreshTokenRequest) (*domain.TokenResponse, error) {
	args := m.Called(ctx, request)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.TokenResponse), args.Error(1)
}

// Logout mocks the Logout method
func (m *MockAuthUseCase) Logout(ctx context.Context, token string) error {
	args := m.Called(ctx, token)
	return args.Error(0)
}

// GetUserProfile mocks the GetUserProfile method
func (m *MockAuthUseCase) GetUserProfile(ctx context.Context, userID string) (*domain.UserResponse, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.UserResponse), args.Error(1)
}

// VerifyToken mocks the VerifyToken method
func (m *MockAuthUseCase) VerifyToken(tokenString string) (map[string]interface{}, error) {
	args := m.Called(tokenString)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(map[string]interface{}), args.Error(1)
}
