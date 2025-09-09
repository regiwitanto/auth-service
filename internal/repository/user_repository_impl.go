package repository

import (
	"context"
	"errors"
	"fmt"

	"github.com/regiwitanto/auth-service/internal/domain"
	"github.com/regiwitanto/auth-service/internal/pkg/logger"
	"gorm.io/gorm"
)

type userRepository struct {
	db *gorm.DB
}

func NewUserRepository(db *gorm.DB) UserRepository {
	return &userRepository{
		db: db,
	}
}

func (r *userRepository) Create(ctx context.Context, user *domain.User) error {
	if err := r.db.WithContext(ctx).Create(user).Error; err != nil {
		logger.Error("Failed to create user",
			logger.String("email", user.Email),
			logger.String("username", user.Username),
			logger.Err(err))
		return err
	}
	logger.Info("User created successfully",
		logger.String("email", user.Email),
		logger.String("username", user.Username),
		logger.String("uuid", user.UUID))
	return nil
}

var (
	ErrUserNotFound = errors.New("user not found")
	ErrDatabase     = errors.New("database error")
)

func (r *userRepository) FindByID(ctx context.Context, id uint) (*domain.User, error) {
	var user domain.User
	err := r.db.WithContext(ctx).First(&user, id).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			logger.Info("User not found by ID", logger.Int("user_id", int(id)))
			return nil, ErrUserNotFound
		}
		logger.Error("Database error when finding user by ID",
			logger.Int("user_id", int(id)),
			logger.Err(err))
		return nil, fmt.Errorf("%w: %v", ErrDatabase, err)
	}
	logger.Debug("User found by ID",
		logger.Int("user_id", int(id)),
		logger.String("email", user.Email))
	return &user, nil
}

func (r *userRepository) FindByUUID(ctx context.Context, uuid string) (*domain.User, error) {
	var user domain.User
	err := r.db.WithContext(ctx).Where("uuid = ?", uuid).First(&user).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			logger.Info("User not found by UUID", logger.String("uuid", uuid))
			return nil, ErrUserNotFound
		}
		logger.Error("Database error when finding user by UUID",
			logger.String("uuid", uuid),
			logger.Err(err))
		return nil, fmt.Errorf("%w: %v", ErrDatabase, err)
	}
	logger.Debug("User found by UUID",
		logger.String("uuid", uuid),
		logger.String("email", user.Email))
	return &user, nil
}

func (r *userRepository) FindByEmail(ctx context.Context, email string) (*domain.User, error) {
	var user domain.User
	err := r.db.WithContext(ctx).Where("email = ?", email).First(&user).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			logger.Info("User not found by email", logger.String("email", email))
			return nil, ErrUserNotFound
		}
		logger.Error("Database error when finding user by email",
			logger.String("email", email),
			logger.Err(err))
		return nil, fmt.Errorf("%w: %v", ErrDatabase, err)
	}
	logger.Debug("User found by email",
		logger.String("email", email),
		logger.String("uuid", user.UUID))
	return &user, nil
}

func (r *userRepository) FindByUsername(ctx context.Context, username string) (*domain.User, error) {
	var user domain.User
	err := r.db.WithContext(ctx).Where("username = ?", username).First(&user).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			logger.Info("User not found by username", logger.String("username", username))
			return nil, errors.New("user not found")
		}
		logger.Error("Database error when finding user by username",
			logger.String("username", username),
			logger.Err(err))
		return nil, err
	}
	logger.Debug("User found by username",
		logger.String("username", username),
		logger.String("email", user.Email))
	return &user, nil
}

func (r *userRepository) Update(ctx context.Context, user *domain.User) error {
	if err := r.db.WithContext(ctx).Save(user).Error; err != nil {
		logger.Error("Failed to update user",
			logger.String("uuid", user.UUID),
			logger.Err(err))
		return err
	}
	logger.Info("User updated successfully",
		logger.String("uuid", user.UUID),
		logger.String("email", user.Email))
	return nil
}

func (r *userRepository) Delete(ctx context.Context, id uint) error {
	return r.db.WithContext(ctx).Delete(&domain.User{}, id).Error
}

func (r *userRepository) UpdatePassword(ctx context.Context, email string, hashedPassword string) error {
	result := r.db.WithContext(ctx).
		Model(&domain.User{}).
		Where("email = ?", email).
		Update("password", hashedPassword)

	if result.Error != nil {
		return result.Error
	}

	if result.RowsAffected == 0 {
		return errors.New("user not found")
	}

	return nil
}
