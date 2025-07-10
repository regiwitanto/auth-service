package usecase

import (
	"context"

	"github.com/regiwitanto/auth-service/internal/domain"
)

// AuthUseCase defines the interface for authentication-related operations
type AuthUseCase interface {
	// Register creates a new user account
	Register(ctx context.Context, request *domain.RegisterRequest) (*domain.UserResponse, error)

	// Login authenticates a user and returns JWT tokens
	Login(ctx context.Context, request *domain.LoginRequest) (*domain.TokenResponse, error)

	// RefreshToken refreshes an access token using a valid refresh token
	RefreshToken(ctx context.Context, request *domain.RefreshTokenRequest) (*domain.TokenResponse, error)

	// Logout invalidates the user's refresh token
	Logout(ctx context.Context, token string) error

	// GetUserProfile gets the user profile from a JWT token
	GetUserProfile(ctx context.Context, userID string) (*domain.UserResponse, error)

	// VerifyToken verifies if a JWT token is valid and returns the claims
	VerifyToken(tokenString string) (map[string]interface{}, error)
}
