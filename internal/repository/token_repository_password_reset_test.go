package repository_test

import (
	"context"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/regiwitanto/auth-service/internal/repository"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type mockRedisClient struct {
	mock.Mock
}

var _ repository.RedisClient = (*mockRedisClient)(nil)

func (m *mockRedisClient) Set(ctx context.Context, key string, value interface{}, expiration time.Duration) *redis.StatusCmd {
	args := m.Called(ctx, key, value, expiration)
	return args.Get(0).(*redis.StatusCmd)
}

func (m *mockRedisClient) Get(ctx context.Context, key string) *redis.StringCmd {
	args := m.Called(ctx, key)
	return args.Get(0).(*redis.StringCmd)
}

func (m *mockRedisClient) Del(ctx context.Context, keys ...string) *redis.IntCmd {
	args := m.Called(ctx, keys[0])
	return args.Get(0).(*redis.IntCmd)
}

func (m *mockRedisClient) SAdd(ctx context.Context, key string, members ...interface{}) *redis.IntCmd {
	args := m.Called(ctx, key, members[0])
	return args.Get(0).(*redis.IntCmd)
}

func (m *mockRedisClient) SRem(ctx context.Context, key string, members ...interface{}) *redis.IntCmd {
	args := m.Called(ctx, key, members[0])
	return args.Get(0).(*redis.IntCmd)
}

func (m *mockRedisClient) SMembers(ctx context.Context, key string) *redis.StringSliceCmd {
	args := m.Called(ctx, key)
	return args.Get(0).(*redis.StringSliceCmd)
}

func (m *mockRedisClient) Pipeline() redis.Pipeliner {
	args := m.Called()
	return args.Get(0).(redis.Pipeliner)
}

func TestStorePasswordResetToken(t *testing.T) {
	mockClient := new(mockRedisClient)
	mockStatusCmd := redis.NewStatusCmd(context.Background())
	mockStatusCmd.SetVal("OK")
	mockClient.On("Set", mock.Anything, "password_reset:test-token", "test@example.com", time.Minute*15).Return(mockStatusCmd)

	repo := repository.NewTokenRepository(mockClient)

	err := repo.StorePasswordResetToken(context.Background(), "test@example.com", "test-token", time.Minute*15)
	assert.NoError(t, err)
	mockClient.AssertExpectations(t)
}

func TestGetEmailByResetToken(t *testing.T) {
	mockClient := new(mockRedisClient)
	mockStringCmd := redis.NewStringCmd(context.Background())
	mockStringCmd.SetVal("test@example.com")
	mockClient.On("Get", mock.Anything, "password_reset:test-token").Return(mockStringCmd)

	repo := repository.NewTokenRepository(mockClient)

	email, err := repo.GetEmailByResetToken(context.Background(), "test-token")
	assert.NoError(t, err)
	assert.Equal(t, "test@example.com", email)
	mockClient.AssertExpectations(t)
}

func TestDeletePasswordResetToken(t *testing.T) {
	mockClient := new(mockRedisClient)
	mockIntCmd := redis.NewIntCmd(context.Background())
	mockIntCmd.SetVal(1)
	mockClient.On("Del", mock.Anything, "password_reset:test-token").Return(mockIntCmd)

	repo := repository.NewTokenRepository(mockClient)

	err := repo.DeletePasswordResetToken(context.Background(), "test-token")
	assert.NoError(t, err)
	mockClient.AssertExpectations(t)
}
