package repository_test

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/regiwitanto/auth-service/internal/repository"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupRedisTest() (*miniredis.Miniredis, *redis.Client) {
	mr, err := miniredis.Run()
	if err != nil {
		panic(err)
	}

	client := redis.NewClient(&redis.Options{
		Addr: mr.Addr(),
	})

	return mr, client
}

func TestTokenRepository_StoreRefreshToken(t *testing.T) {
	mr, client := setupRedisTest()
	defer mr.Close()

	repo := repository.NewTokenRepository(client)
	ctx := context.Background()

	userID := "user-123"
	token := "test-refresh-token"
	expiry := 15 * time.Minute
	err := repo.StoreRefreshToken(ctx, userID, token, expiry)
	require.NoError(t, err)

	key := "refresh_token:" + token
	val, err := client.Get(ctx, key).Result()
	require.NoError(t, err)
	assert.Equal(t, userID, val)
	ttl := mr.TTL(key)
	assert.True(t, ttl > 0, "Token should have a positive TTL")
	assert.Greater(t, float64(ttl), 0.0, "Token TTL should be greater than 0")
	userTokensKey := "user_tokens:" + userID
	members, err := client.SMembers(ctx, userTokensKey).Result()
	require.NoError(t, err)
	assert.Contains(t, members, token)
}

func TestTokenRepository_GetUserIDByRefreshToken(t *testing.T) {
	mr, client := setupRedisTest()
	defer mr.Close()

	repo := repository.NewTokenRepository(client)
	ctx := context.Background()

	userID := "user-123"
	validToken := "valid-refresh-token"
	expiry := 15 * time.Minute
	err := repo.StoreRefreshToken(ctx, userID, validToken, expiry)
	require.NoError(t, err)

	t.Run("Valid Token", func(t *testing.T) {
		retrievedID, err := repo.GetUserIDByRefreshToken(ctx, validToken)
		require.NoError(t, err)
		assert.Equal(t, userID, retrievedID)
	})

	t.Run("Invalid Token", func(t *testing.T) {
		retrievedID, err := repo.GetUserIDByRefreshToken(ctx, "invalid-token")
		require.Error(t, err)
		assert.Empty(t, retrievedID)
		assert.Contains(t, err.Error(), "token not found or expired")
	})

	t.Run("Expired Token", func(t *testing.T) {
		expiredToken := "expired-token"
		shortExpiry := 1 * time.Second
		err := repo.StoreRefreshToken(ctx, userID, expiredToken, shortExpiry)
		require.NoError(t, err)
		key := "refresh_token:" + expiredToken
		exists := mr.Exists(key)
		assert.True(t, exists, "Token should exist immediately after creation")

		mr.FastForward(shortExpiry + time.Millisecond)
		exists = mr.Exists(key)
		assert.False(t, exists, "Token should be removed after expiration")

		retrievedID, err := repo.GetUserIDByRefreshToken(ctx, expiredToken)
		require.Error(t, err, "Getting an expired token should return an error")
		assert.Empty(t, retrievedID, "No user ID should be returned for expired token")
		assert.Contains(t, err.Error(), "token not found or expired")
	})
}

func TestTokenRepository_DeleteRefreshToken(t *testing.T) {
	mr, client := setupRedisTest()
	defer mr.Close()

	repo := repository.NewTokenRepository(client)
	ctx := context.Background()

	userID := "user-123"
	token := "test-refresh-token"
	expiry := 15 * time.Minute
	err := repo.StoreRefreshToken(ctx, userID, token, expiry)
	require.NoError(t, err)

	key := "refresh_token:" + token
	exists := mr.Exists(key)
	assert.True(t, exists)
	err = repo.DeleteRefreshToken(ctx, token)
	require.NoError(t, err)

	exists = mr.Exists(key)
	assert.False(t, exists)
}

func TestTokenRepository_DeleteAllUserTokens(t *testing.T) {
	mr, client := setupRedisTest()
	defer mr.Close()

	repo := repository.NewTokenRepository(client)
	ctx := context.Background()

	userID := "user-123"
	tokens := []string{"token1", "token2", "token3"}
	expiry := 15 * time.Minute
	for _, token := range tokens {
		err := repo.StoreRefreshToken(ctx, userID, token, expiry)
		require.NoError(t, err)
	}

	for _, token := range tokens {
		key := "refresh_token:" + token
		exists := mr.Exists(key)
		assert.True(t, exists)
	}
	err := repo.DeleteAllUserTokens(ctx, userID)
	require.NoError(t, err)

	for _, token := range tokens {
		key := "refresh_token:" + token
		exists := mr.Exists(key)
		assert.False(t, exists)
	}
	userTokensKey := "user_tokens:" + userID
	exists := mr.Exists(userTokensKey)
	assert.False(t, exists)
}
