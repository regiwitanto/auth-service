package repository

import (
	"context"

	"github.com/regiwitanto/auth-service/internal/domain"
)

type UserRepository interface {
	Create(ctx context.Context, user *domain.User) error
	FindByID(ctx context.Context, id uint) (*domain.User, error)
	FindByUUID(ctx context.Context, uuid string) (*domain.User, error)
	FindByEmail(ctx context.Context, email string) (*domain.User, error)
	FindByUsername(ctx context.Context, username string) (*domain.User, error)
	Update(ctx context.Context, user *domain.User) error
	Delete(ctx context.Context, id uint) error
	UpdatePassword(ctx context.Context, email string, hashedPassword string) error
	Ping(ctx context.Context) error
}
