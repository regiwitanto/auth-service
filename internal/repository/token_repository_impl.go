package repository

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
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
		return fmt.Errorf("failed to store refresh token: %w", err)
	}

	return nil
}

func (r *tokenRepository) GetUserIDByRefreshToken(ctx context.Context, token string) (string, error) {
	key := fmt.Sprintf("refresh_token:%s", token)
	userID, err := r.redis.Get(ctx, key).Result()
	if err != nil {
		if err == redis.Nil {
			return "", errors.New("token not found or expired")
		}
		return "", err
	}
	return userID, nil
}

func (r *tokenRepository) DeleteRefreshToken(ctx context.Context, token string) error {
	key := fmt.Sprintf("refresh_token:%s", token)
	userID, err := r.redis.Get(ctx, key).Result()
	if err != nil {
		if err == redis.Nil {
			return nil // Token already gone, nothing to do
		}
		return err
	}

	userTokensKey := fmt.Sprintf("user_tokens:%s", userID)
	err = r.redis.SRem(ctx, userTokensKey, token).Err()
	if err != nil && err != redis.Nil {
		return err
	}
	return r.redis.Del(ctx, key).Err()
}

func (r *tokenRepository) DeleteAllUserTokens(ctx context.Context, userID string) error {
	userTokensKey := fmt.Sprintf("user_tokens:%s", userID)
	tokens, err := r.redis.SMembers(ctx, userTokensKey).Result()
	if err != nil {
		if err == redis.Nil {
			return nil // No tokens to delete
		}
		return err
	}

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
