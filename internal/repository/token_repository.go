package repository

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
)

type RedisClient interface {
	Set(ctx context.Context, key string, value interface{}, expiration time.Duration) *redis.StatusCmd
	Get(ctx context.Context, key string) *redis.StringCmd
	Del(ctx context.Context, keys ...string) *redis.IntCmd
	SAdd(ctx context.Context, key string, members ...interface{}) *redis.IntCmd
	SRem(ctx context.Context, key string, members ...interface{}) *redis.IntCmd
	SMembers(ctx context.Context, key string) *redis.StringSliceCmd
	Pipeline() redis.Pipeliner
}

type TokenRepository interface {
	StoreRefreshToken(ctx context.Context, userID string, token string, expiry time.Duration) error
	GetUserIDByRefreshToken(ctx context.Context, token string) (string, error)
	DeleteRefreshToken(ctx context.Context, token string) error
	DeleteAllUserTokens(ctx context.Context, userID string) error
	StorePasswordResetToken(ctx context.Context, email string, token string, expiry time.Duration) error
	GetEmailByResetToken(ctx context.Context, token string) (string, error)
	DeletePasswordResetToken(ctx context.Context, token string) error
}
