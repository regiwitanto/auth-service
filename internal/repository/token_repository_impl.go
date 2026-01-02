package repository

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/regiwitanto/auth-service/internal/pkg/logger"
	"github.com/regiwitanto/auth-service/internal/pkg/metrics"
)

type tokenRepository struct {
	redis RedisClient
}

func NewTokenRepository(redis RedisClient) TokenRepository {
	return &tokenRepository{
		redis: redis,
	}
}

func (r *tokenRepository) StoreRefreshToken(ctx context.Context, userID string, token string, expiry time.Duration) error {
	if ctx.Err() != nil {
		logger.Warn("Context error when storing refresh token",
			logger.String("user_id", userID),
			logger.Err(ctx.Err()))
		return ctx.Err()
	}
	pipe := r.redis.Pipeline()

	key := fmt.Sprintf("refresh_token:%s", token)
	pipe.Set(ctx, key, userID, expiry)

	userTokensKey := fmt.Sprintf("user_tokens:%s", userID)
	pipe.SAdd(ctx, userTokensKey, token)

	// This helps with Redis memory management
	maxExpiry := 30 * 24 * time.Hour // 30 days
	pipe.Expire(ctx, userTokensKey, maxExpiry)
	_, err := pipe.Exec(ctx)
	if err != nil {
		logger.Error("Failed to store refresh token",
			logger.String("user_id", userID),
			logger.Err(err))
		return fmt.Errorf("failed to store refresh token: %w", err)
	}

	logger.Debug("Refresh token stored successfully",
		logger.String("user_id", userID),
		logger.String("expiry", expiry.String()))
	return nil
}

func (r *tokenRepository) GetUserIDByRefreshToken(ctx context.Context, token string) (string, error) {
	key := fmt.Sprintf("refresh_token:%s", token)
	userID, err := r.redis.Get(ctx, key).Result()
	if err != nil {
		if err == redis.Nil {
			logger.Info("Refresh token not found or expired",
				logger.String("token_key", key))
			return "", errors.New("token not found or expired")
		}
		logger.Error("Failed to get user ID by refresh token",
			logger.String("token_key", key),
			logger.Err(err))
		return "", err
	}
	logger.Debug("User ID retrieved by refresh token",
		logger.String("user_id", userID))
	return userID, nil
}

func (r *tokenRepository) DeleteRefreshToken(ctx context.Context, token string) error {
	key := fmt.Sprintf("refresh_token:%s", token)
	userID, err := r.redis.Get(ctx, key).Result()
	if err != nil {
		if err == redis.Nil {
			logger.Debug("Refresh token already deleted or expired",
				logger.String("token_key", key))
			return nil // Token already gone, nothing to do
		}
		logger.Error("Failed to get user ID when deleting refresh token",
			logger.String("token_key", key),
			logger.Err(err))
		return err
	}

	userTokensKey := fmt.Sprintf("user_tokens:%s", userID)
	err = r.redis.SRem(ctx, userTokensKey, token).Err()
	if err != nil && err != redis.Nil {
		logger.Error("Failed to remove token from user tokens set",
			logger.String("user_id", userID),
			logger.Err(err))
		return err
	}

	err = r.redis.Del(ctx, key).Err()
	if err != nil {
		logger.Error("Failed to delete refresh token key",
			logger.String("token_key", key),
			logger.Err(err))
		return err
	}

	logger.Debug("Refresh token deleted successfully",
		logger.String("user_id", userID))
	return nil
}

func (r *tokenRepository) DeleteAllUserTokens(ctx context.Context, userID string) error {
	userTokensKey := fmt.Sprintf("user_tokens:%s", userID)
	tokens, err := r.redis.SMembers(ctx, userTokensKey).Result()
	if err != nil {
		if err == redis.Nil {
			logger.Debug("No tokens found for user",
				logger.String("user_id", userID))
			return nil // No tokens to delete
		}
		logger.Error("Failed to get user tokens",
			logger.String("user_id", userID),
			logger.Err(err))
		return err
	}

	logger.Info("Deleting all refresh tokens for user",
		logger.String("user_id", userID),
		logger.Int("token_count", len(tokens)))

	pipe := r.redis.Pipeline()
	for _, token := range tokens {
		tokenKey := fmt.Sprintf("refresh_token:%s", token)
		pipe.Del(ctx, tokenKey)
	}
	pipe.Del(ctx, userTokensKey)

	_, err = pipe.Exec(ctx)
	return err
}

func (r *tokenRepository) StorePasswordResetToken(ctx context.Context, email string, token string, expiry time.Duration) error {
	key := fmt.Sprintf("password_reset:%s", token)
	return r.redis.Set(ctx, key, email, expiry).Err()
}

func (r *tokenRepository) GetEmailByResetToken(ctx context.Context, token string) (string, error) {
	key := fmt.Sprintf("password_reset:%s", token)
	email, err := r.redis.Get(ctx, key).Result()
	if err != nil {
		if err == redis.Nil {
			return "", errors.New("password reset token not found or expired")
		}
		return "", err
	}
	return email, nil
}

func (r *tokenRepository) DeletePasswordResetToken(ctx context.Context, token string) error {
	key := fmt.Sprintf("password_reset:%s", token)
	return r.redis.Del(ctx, key).Err()
}

func (r *tokenRepository) GetTokenCount(ctx context.Context) (int64, error) {
	// Count tokens by getting Redis keys for refresh tokens
	// This is for metrics/monitoring purposes

	// In production, consider using more efficient ways to count tokens
	// like keeping a separate counter in Redis that's updated when tokens are added/removed

	keys, err := r.redis.Keys(ctx, "refresh_token:*").Result()
	if err != nil {
		logger.Error("Failed to get Redis token count", logger.Err(err))
		return 0, err
	}

	// Update metrics
	metrics.ActiveTokensGauge.Set(float64(len(keys)))

	return int64(len(keys)), nil
}

func (r *tokenRepository) Ping(ctx context.Context) error {
	status := r.redis.Ping(ctx)
	if status.Err() != nil {
		logger.Error("Redis ping failed", logger.Err(status.Err()))
		return status.Err()
	}
	return nil
}
