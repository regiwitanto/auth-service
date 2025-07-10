package usecase

import (
	"context"

	"github.com/regiwitanto/auth-service/internal/domain"
)

type AuthUseCase interface {
	Register(ctx context.Context, request *domain.RegisterRequest) (*domain.UserResponse, error)
	Login(ctx context.Context, request *domain.LoginRequest) (*domain.TokenResponse, error)
	RefreshToken(ctx context.Context, request *domain.RefreshTokenRequest) (*domain.TokenResponse, error)
	Logout(ctx context.Context, token string) error
	GetUserProfile(ctx context.Context, userID string) (*domain.UserResponse, error)
	VerifyToken(tokenString string) (map[string]interface{}, error)
}
