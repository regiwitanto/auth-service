package repository

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// tokenRepository implements the TokenRepository interface
type tokenRepository struct {
	redis RedisClient
}

// NewTokenRepository creates a new token repository
func NewTokenRepository(redis RedisClient) TokenRepository {
	return &tokenRepository{
		redis: redis,
	}
}

// StoreRefreshToken stores a refresh token with expiry
func (r *tokenRepository) StoreRefreshToken(ctx context.Context, userID string, token string, expiry time.Duration) error {
	// Store the token with the user ID as value
	key := fmt.Sprintf("refresh_token:%s", token)
	err := r.redis.Set(ctx, key, userID, expiry).Err()
	if err != nil {
		return err
	}

	// Also store a reference in a set of tokens for this user (for logout all functionality)
	userTokensKey := fmt.Sprintf("user_tokens:%s", userID)
	err = r.redis.SAdd(ctx, userTokensKey, token).Err()
	if err != nil {
		return err
	}

	// We don't set expiry on the set itself as it will be cleaned up when all tokens expire
	return nil
}

// GetUserIDByRefreshToken retrieves the user ID associated with a refresh token
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

// DeleteRefreshToken deletes a refresh token
func (r *tokenRepository) DeleteRefreshToken(ctx context.Context, token string) error {
	// First get the user ID to remove from the user's token set
	key := fmt.Sprintf("refresh_token:%s", token)
	userID, err := r.redis.Get(ctx, key).Result()
	if err != nil {
		if err == redis.Nil {
			return nil // Token already gone, nothing to do
		}
		return err
	}

	// Remove token from user's tokens set
	userTokensKey := fmt.Sprintf("user_tokens:%s", userID)
	err = r.redis.SRem(ctx, userTokensKey, token).Err()
	if err != nil && err != redis.Nil {
		return err
	}

	// Delete the token itself
	return r.redis.Del(ctx, key).Err()
}

// DeleteAllUserTokens deletes all tokens for a specific user
func (r *tokenRepository) DeleteAllUserTokens(ctx context.Context, userID string) error {
	// Get all tokens for this user
	userTokensKey := fmt.Sprintf("user_tokens:%s", userID)
	tokens, err := r.redis.SMembers(ctx, userTokensKey).Result()
	if err != nil {
		if err == redis.Nil {
			return nil // No tokens to delete
		}
		return err
	}

	// Delete each individual token
	pipe := r.redis.Pipeline()
	for _, token := range tokens {
		tokenKey := fmt.Sprintf("refresh_token:%s", token)
		pipe.Del(ctx, tokenKey)
	}

	// Delete the set itself
	pipe.Del(ctx, userTokensKey)

	_, err = pipe.Exec(ctx)
	return err
}

// StorePasswordResetToken stores a password reset token with expiry
func (r *tokenRepository) StorePasswordResetToken(ctx context.Context, email string, token string, expiry time.Duration) error {
	// Store the token with the email as value
	key := fmt.Sprintf("password_reset:%s", token)
	return r.redis.Set(ctx, key, email, expiry).Err()
}

// GetEmailByResetToken retrieves the email associated with a password reset token
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

// DeletePasswordResetToken deletes a password reset token
func (r *tokenRepository) DeletePasswordResetToken(ctx context.Context, token string) error {
	key := fmt.Sprintf("password_reset:%s", token)
	return r.redis.Del(ctx, key).Err()
}
