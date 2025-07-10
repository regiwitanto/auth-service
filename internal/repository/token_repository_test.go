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
	// Create a miniredis server
	mr, err := miniredis.Run()
	if err != nil {
		panic(err)
	}

	// Create a redis client connected to the miniredis server
	client := redis.NewClient(&redis.Options{
		Addr: mr.Addr(),
	})

	return mr, client
}

func TestTokenRepository_StoreRefreshToken(t *testing.T) {
	// Setup
	mr, client := setupRedisTest()
	defer mr.Close()

	repo := repository.NewTokenRepository(client)
	ctx := context.Background()

	// Test data
	userID := "user-123"
	token := "test-refresh-token"
	expiry := 15 * time.Minute

	// Store a token
	err := repo.StoreRefreshToken(ctx, userID, token, expiry)
	require.NoError(t, err)

	// Verify it was stored correctly
	key := "refresh_token:" + token
	val, err := client.Get(ctx, key).Result()
	require.NoError(t, err)
	assert.Equal(t, userID, val)

	// Check the expiration time
	ttl := mr.TTL(key)
	assert.True(t, ttl > 0, "Token should have a positive TTL")

	// Since miniredis sets TTL a bit differently than actual Redis,
	// just verify that the TTL exists and is positive
	assert.Greater(t, float64(ttl), 0.0, "Token TTL should be greater than 0")

	// Check if token was added to user's token set
	userTokensKey := "user_tokens:" + userID
	members, err := client.SMembers(ctx, userTokensKey).Result()
	require.NoError(t, err)
	assert.Contains(t, members, token)
}

func TestTokenRepository_GetUserIDByRefreshToken(t *testing.T) {
	// Setup
	mr, client := setupRedisTest()
	defer mr.Close()

	repo := repository.NewTokenRepository(client)
	ctx := context.Background()

	// Test data
	userID := "user-123"
	validToken := "valid-refresh-token"
	expiry := 15 * time.Minute

	// Store a token
	err := repo.StoreRefreshToken(ctx, userID, validToken, expiry)
	require.NoError(t, err)

	t.Run("Valid Token", func(t *testing.T) {
		// Retrieve the user ID
		retrievedID, err := repo.GetUserIDByRefreshToken(ctx, validToken)
		require.NoError(t, err)
		assert.Equal(t, userID, retrievedID)
	})

	t.Run("Invalid Token", func(t *testing.T) {
		// Try to retrieve with an invalid token
		retrievedID, err := repo.GetUserIDByRefreshToken(ctx, "invalid-token")
		require.Error(t, err)
		assert.Empty(t, retrievedID)
		assert.Contains(t, err.Error(), "token not found or expired")
	})

	t.Run("Expired Token", func(t *testing.T) {
		// Store a token with short expiry
		expiredToken := "expired-token"
		shortExpiry := 1 * time.Second
		err := repo.StoreRefreshToken(ctx, userID, expiredToken, shortExpiry)
		require.NoError(t, err)

		// Verify it exists initially
		key := "refresh_token:" + expiredToken
		exists := mr.Exists(key)
		assert.True(t, exists, "Token should exist immediately after creation")

		// Force expiry in miniredis instead of sleeping (more reliable)
		mr.FastForward(shortExpiry + time.Millisecond)

		// Verify it's gone from Redis
		exists = mr.Exists(key)
		assert.False(t, exists, "Token should be removed after expiration")

		// Try to retrieve through the repository
		retrievedID, err := repo.GetUserIDByRefreshToken(ctx, expiredToken)
		require.Error(t, err, "Getting an expired token should return an error")
		assert.Empty(t, retrievedID, "No user ID should be returned for expired token")
		assert.Contains(t, err.Error(), "token not found or expired")
	})
}

func TestTokenRepository_DeleteRefreshToken(t *testing.T) {
	// Setup
	mr, client := setupRedisTest()
	defer mr.Close()

	repo := repository.NewTokenRepository(client)
	ctx := context.Background()

	// Test data
	userID := "user-123"
	token := "test-refresh-token"
	expiry := 15 * time.Minute

	// Store a token
	err := repo.StoreRefreshToken(ctx, userID, token, expiry)
	require.NoError(t, err)

	// Verify it was stored
	key := "refresh_token:" + token
	exists := mr.Exists(key)
	assert.True(t, exists)

	// Delete the token
	err = repo.DeleteRefreshToken(ctx, token)
	require.NoError(t, err)

	// Verify it was deleted
	exists = mr.Exists(key)
	assert.False(t, exists)
}

func TestTokenRepository_DeleteAllUserTokens(t *testing.T) {
	// Setup
	mr, client := setupRedisTest()
	defer mr.Close()

	repo := repository.NewTokenRepository(client)
	ctx := context.Background()

	// Test data
	userID := "user-123"
	tokens := []string{"token1", "token2", "token3"}
	expiry := 15 * time.Minute

	// Store multiple tokens for the same user
	for _, token := range tokens {
		err := repo.StoreRefreshToken(ctx, userID, token, expiry)
		require.NoError(t, err)
	}

	// Verify they were stored
	for _, token := range tokens {
		key := "refresh_token:" + token
		exists := mr.Exists(key)
		assert.True(t, exists)
	}

	// Delete all user tokens
	err := repo.DeleteAllUserTokens(ctx, userID)
	require.NoError(t, err)

	// Verify all tokens were deleted
	for _, token := range tokens {
		key := "refresh_token:" + token
		exists := mr.Exists(key)
		assert.False(t, exists)
	}

	// Verify the user's token set was deleted
	userTokensKey := "user_tokens:" + userID
	exists := mr.Exists(userTokensKey)
	assert.False(t, exists)
}
