package repository

import (
	"context"
	"time"
)

// TokenRepository defines the interface for token-related operations
type TokenRepository interface {
	// StoreRefreshToken stores a refresh token with expiry
	StoreRefreshToken(ctx context.Context, userID string, token string, expiry time.Duration) error

	// GetUserIDByRefreshToken retrieves the user ID associated with a refresh token
	GetUserIDByRefreshToken(ctx context.Context, token string) (string, error)

	// DeleteRefreshToken deletes a refresh token
	DeleteRefreshToken(ctx context.Context, token string) error

	// DeleteAllUserTokens deletes all tokens for a specific user
	DeleteAllUserTokens(ctx context.Context, userID string) error
}
