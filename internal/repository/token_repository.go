package repository

import (
	"context"
	"time"
)

type TokenRepository interface {
	StoreRefreshToken(ctx context.Context, userID string, token string, expiry time.Duration) error
	GetUserIDByRefreshToken(ctx context.Context, token string) (string, error)
	DeleteRefreshToken(ctx context.Context, token string) error
	DeleteAllUserTokens(ctx context.Context, userID string) error
}
