package repository

import (
	"context"

	"github.com/regiwitanto/auth-service/internal/domain"
)

// UserRepository defines the interface for user-related database operations
type UserRepository interface {
	// Create creates a new user in the database
	Create(ctx context.Context, user *domain.User) error

	// FindByID finds a user by ID
	FindByID(ctx context.Context, id uint) (*domain.User, error)

	// FindByUUID finds a user by UUID
	FindByUUID(ctx context.Context, uuid string) (*domain.User, error)

	// FindByEmail finds a user by email
	FindByEmail(ctx context.Context, email string) (*domain.User, error)

	// FindByUsername finds a user by username
	FindByUsername(ctx context.Context, username string) (*domain.User, error)

	// Update updates an existing user
	Update(ctx context.Context, user *domain.User) error

	// Delete deletes a user by ID
	Delete(ctx context.Context, id uint) error
}
