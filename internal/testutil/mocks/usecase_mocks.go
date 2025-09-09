package mocks

import (
	"context"

	"github.com/regiwitanto/auth-service/internal/domain"
	"github.com/stretchr/testify/mock"
)

type MockAuthUseCase struct {
	mock.Mock
}

func (m *MockAuthUseCase) Register(ctx context.Context, request *domain.RegisterRequest) (*domain.UserResponse, error) {
	args := m.Called(ctx, request)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.UserResponse), args.Error(1)
}

func (m *MockAuthUseCase) Login(ctx context.Context, request *domain.LoginRequest) (*domain.TokenResponse, error) {
	args := m.Called(ctx, request)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.TokenResponse), args.Error(1)
}

func (m *MockAuthUseCase) RefreshToken(ctx context.Context, request *domain.RefreshTokenRequest) (*domain.TokenResponse, error) {
	args := m.Called(ctx, request)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.TokenResponse), args.Error(1)
}

func (m *MockAuthUseCase) Logout(ctx context.Context, token string) error {
	args := m.Called(ctx, token)
	return args.Error(0)
}

func (m *MockAuthUseCase) GetUserProfile(ctx context.Context, userID string) (*domain.UserResponse, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.UserResponse), args.Error(1)
}

func (m *MockAuthUseCase) VerifyToken(tokenString string) (map[string]interface{}, error) {
	args := m.Called(tokenString)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(map[string]interface{}), args.Error(1)
}

func (m *MockAuthUseCase) ForgotPassword(ctx context.Context, request *domain.ForgotPasswordRequest) error {
	args := m.Called(ctx, request)
	return args.Error(0)
}

func (m *MockAuthUseCase) ResetPassword(ctx context.Context, request *domain.ResetPasswordRequest) error {
	args := m.Called(ctx, request)
	return args.Error(0)
}
