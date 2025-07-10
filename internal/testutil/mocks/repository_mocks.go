package mocks

import (
	"context"
	"time"

	"github.com/regiwitanto/auth-service/internal/domain"
	"github.com/stretchr/testify/mock"
)

// MockUserRepository is a mock implementation of the UserRepository interface
type MockUserRepository struct {
	mock.Mock
}

// MockTokenRepository is a mock implementation of the TokenRepository interface
type MockTokenRepository struct {
	mock.Mock
}

// Create mocks the Create method
func (m *MockUserRepository) Create(ctx context.Context, user *domain.User) error {
	args := m.Called(ctx, user)
	return args.Error(0)
}

// FindByID mocks the FindByID method
func (m *MockUserRepository) FindByID(ctx context.Context, id uint) (*domain.User, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.User), args.Error(1)
}

// FindByUUID mocks the FindByUUID method
func (m *MockUserRepository) FindByUUID(ctx context.Context, uuid string) (*domain.User, error) {
	args := m.Called(ctx, uuid)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.User), args.Error(1)
}

// FindByEmail mocks the FindByEmail method
func (m *MockUserRepository) FindByEmail(ctx context.Context, email string) (*domain.User, error) {
	args := m.Called(ctx, email)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.User), args.Error(1)
}

// FindByUsername mocks the FindByUsername method
func (m *MockUserRepository) FindByUsername(ctx context.Context, username string) (*domain.User, error) {
	args := m.Called(ctx, username)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.User), args.Error(1)
}

// Update mocks the Update method
func (m *MockUserRepository) Update(ctx context.Context, user *domain.User) error {
	args := m.Called(ctx, user)
	return args.Error(0)
}

// Delete mocks the Delete method
func (m *MockUserRepository) Delete(ctx context.Context, id uint) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

// MockTokenRepository methods - The struct is declared above

// StoreRefreshToken mocks the StoreRefreshToken method
func (m *MockTokenRepository) StoreRefreshToken(ctx context.Context, userID string, token string, expiry time.Duration) error {
	args := m.Called(ctx, userID, token, expiry)
	return args.Error(0)
}

// GetUserIDByRefreshToken mocks the GetUserIDByRefreshToken method
func (m *MockTokenRepository) GetUserIDByRefreshToken(ctx context.Context, token string) (string, error) {
	args := m.Called(ctx, token)
	return args.String(0), args.Error(1)
}

// DeleteRefreshToken mocks the DeleteRefreshToken method
func (m *MockTokenRepository) DeleteRefreshToken(ctx context.Context, token string) error {
	args := m.Called(ctx, token)
	return args.Error(0)
}

// DeleteAllUserTokens mocks the DeleteAllUserTokens method
func (m *MockTokenRepository) DeleteAllUserTokens(ctx context.Context, userID string) error {
	args := m.Called(ctx, userID)
	return args.Error(0)
}
