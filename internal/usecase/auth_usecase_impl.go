package usecase

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/regiwitanto/auth-service/config"
	"github.com/regiwitanto/auth-service/internal/domain"
	"github.com/regiwitanto/auth-service/internal/pkg/logger"
	"github.com/regiwitanto/auth-service/internal/repository"
	"golang.org/x/crypto/bcrypt"
)

type authUseCase struct {
	userRepo  repository.UserRepository
	tokenRepo repository.TokenRepository
	config    config.Config
}

func NewAuthUseCase(
	userRepo repository.UserRepository,
	tokenRepo repository.TokenRepository,
	config config.Config,
) AuthUseCase {
	return &authUseCase{
		userRepo:  userRepo,
		tokenRepo: tokenRepo,
		config:    config,
	}
}

func (uc *authUseCase) Register(ctx context.Context, request *domain.RegisterRequest) (*domain.UserResponse, error) {
	logger.Info("User registration attempt",
		logger.String("email", request.Email),
		logger.String("username", request.Username))

	existingUser, err := uc.userRepo.FindByEmail(ctx, request.Email)
	if err == nil && existingUser != nil {
		logger.Warn("Registration failed: email already exists",
			logger.String("email", request.Email))
		return nil, errors.New("user with this email already exists")
	}

	existingUser, err = uc.userRepo.FindByUsername(ctx, request.Username)
	if err == nil && existingUser != nil {
		logger.Warn("Registration failed: username already exists",
			logger.String("username", request.Username))
		return nil, errors.New("user with this username already exists")
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(request.Password), bcrypt.DefaultCost)
	if err != nil {
		logger.Error("Failed to hash password during registration",
			logger.String("email", request.Email),
			logger.Err(err))
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	user := &domain.User{
		Email:     request.Email,
		Username:  request.Username,
		Password:  string(hashedPassword),
		FirstName: request.FirstName,
		LastName:  request.LastName,
		Role:      "user",
		Active:    true,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	if err := uc.userRepo.Create(ctx, user); err != nil {
		logger.Error("Failed to create user in database",
			logger.String("email", request.Email),
			logger.Err(err))
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	logger.Info("User registered successfully",
		logger.String("email", user.Email),
		logger.String("uuid", user.UUID))

	response := user.ToResponse()
	return &response, nil
}

func (uc *authUseCase) Login(ctx context.Context, request *domain.LoginRequest) (*domain.TokenResponse, error) {
	logger.Info("Login attempt", logger.String("email", request.Email))

	if ctx.Err() != nil {
		logger.Warn("Login context error",
			logger.String("email", request.Email),
			logger.Err(ctx.Err()))
		return nil, ctx.Err()
	}

	user, err := uc.userRepo.FindByEmail(ctx, request.Email)
	if err != nil {
		logger.Warn("Login failed: user not found",
			logger.String("email", request.Email))
		return nil, domain.ErrInvalidCredentials
	}

	if !user.Active {
		logger.Warn("Login attempt for disabled account",
			logger.String("email", user.Email),
			logger.String("uuid", user.UUID))
		return nil, domain.ErrAccountDisabled
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(request.Password)); err != nil {
		logger.Warn("Login failed: invalid password",
			logger.String("email", user.Email),
			logger.String("uuid", user.UUID))
		return nil, domain.ErrInvalidCredentials
	}

	logger.Debug("Password verified successfully", logger.String("email", user.Email))

	accessToken, err := uc.generateAccessToken(user)
	if err != nil {
		logger.Error("Failed to generate access token",
			logger.String("email", user.Email),
			logger.Err(err))
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	refreshToken, err := uc.generateRefreshToken(user)
	if err != nil {
		logger.Error("Failed to generate refresh token",
			logger.String("email", user.Email),
			logger.Err(err))
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	if err := uc.tokenRepo.StoreRefreshToken(ctx, user.UUID, refreshToken, uc.config.JWT.RefreshTokenExp); err != nil {
		logger.Error("Failed to store refresh token",
			logger.String("email", user.Email),
			logger.String("uuid", user.UUID),
			logger.Err(err))
		return nil, fmt.Errorf("failed to store refresh token: %w", err)
	}

	logger.Info("Login successful",
		logger.String("email", user.Email),
		logger.String("uuid", user.UUID))

	return &domain.TokenResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int64(uc.config.JWT.AccessTokenExp.Seconds()),
		TokenType:    "Bearer",
	}, nil
}

func (uc *authUseCase) RefreshToken(ctx context.Context, request *domain.RefreshTokenRequest) (*domain.TokenResponse, error) {
	userID, err := uc.tokenRepo.GetUserIDByRefreshToken(ctx, request.RefreshToken)
	if err != nil {
		return nil, errors.New("invalid or expired refresh token")
	}

	user, err := uc.userRepo.FindByUUID(ctx, userID)
	if err != nil {
		return nil, errors.New("user not found")
	}

	if !user.Active {
		return nil, errors.New("account is disabled")
	}
	accessToken, err := uc.generateAccessToken(user)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	refreshToken, err := uc.generateRefreshToken(user)
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	if err := uc.tokenRepo.DeleteRefreshToken(ctx, request.RefreshToken); err != nil {
		return nil, fmt.Errorf("failed to delete old refresh token: %w", err)
	}
	if err := uc.tokenRepo.StoreRefreshToken(ctx, user.UUID, refreshToken, uc.config.JWT.RefreshTokenExp); err != nil {
		return nil, fmt.Errorf("failed to store refresh token: %w", err)
	}

	return &domain.TokenResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int64(uc.config.JWT.AccessTokenExp.Seconds()),
		TokenType:    "Bearer",
	}, nil
}

func (uc *authUseCase) Logout(ctx context.Context, token string) error {
	return uc.tokenRepo.DeleteRefreshToken(ctx, token)
}

func (uc *authUseCase) GetUserProfile(ctx context.Context, userID string) (*domain.UserResponse, error) {
	user, err := uc.userRepo.FindByUUID(ctx, userID)
	if err != nil {
		return nil, errors.New("user not found")
	}
	response := user.ToResponse()
	return &response, nil
}

func (uc *authUseCase) VerifyToken(tokenString string) (map[string]interface{}, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(uc.config.JWT.Secret), nil
	})

	if err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, errors.New("invalid token")
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("invalid token claims")
	}
	claimsMap := make(map[string]interface{})
	for key, value := range claims {
		claimsMap[key] = value
	}

	return claimsMap, nil
}

func (uc *authUseCase) generateAccessToken(user *domain.User) (string, error) {
	claims := jwt.MapClaims{
		"sub":   user.UUID,
		"name":  user.Username,
		"email": user.Email,
		"role":  user.Role,
		"exp":   time.Now().Add(uc.config.JWT.AccessTokenExp).Unix(),
		"iat":   time.Now().Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	tokenString, err := token.SignedString([]byte(uc.config.JWT.Secret))
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func (uc *authUseCase) generateRefreshToken(user *domain.User) (string, error) {
	claims := jwt.MapClaims{
		"sub": user.UUID,
		"exp": time.Now().Add(uc.config.JWT.RefreshTokenExp).Unix(),
		"iat": time.Now().Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	tokenString, err := token.SignedString([]byte(uc.config.JWT.Secret))
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func (uc *authUseCase) generateSecureToken(length int) (string, error) {
	b := make([]byte, length)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

func (uc *authUseCase) ForgotPassword(ctx context.Context, request *domain.ForgotPasswordRequest) error {
	user, err := uc.userRepo.FindByEmail(ctx, request.Email)
	if err != nil {
		// Don't reveal that the email doesn't exist for security reasons
		// Just pretend we sent an email
		return nil
	}

	token, err := uc.generateSecureToken(32)
	if err != nil {
		return fmt.Errorf("failed to generate reset token: %w", err)
	}

	err = uc.tokenRepo.StorePasswordResetToken(ctx, user.Email, token, 15*time.Minute)
	if err != nil {
		return fmt.Errorf("failed to store reset token: %w", err)
	}

	// In a real implementation, we would send an email with the reset link
	// For now, we'll just log it (in a real app this should be removed)
	resetLink := fmt.Sprintf("%s/reset-password?token=%s", uc.config.Server.BaseURL, token)
	fmt.Printf("Password reset requested for %s. Reset link: %s\n", user.Email, resetLink)

	return nil
}

func (uc *authUseCase) ResetPassword(ctx context.Context, request *domain.ResetPasswordRequest) error {
	email, err := uc.tokenRepo.GetEmailByResetToken(ctx, request.Token)
	if err != nil {
		return errors.New("invalid or expired reset token")
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(request.Password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	err = uc.userRepo.UpdatePassword(ctx, email, string(hashedPassword))
	if err != nil {
		return fmt.Errorf("failed to update password: %w", err)
	}

	err = uc.tokenRepo.DeletePasswordResetToken(ctx, request.Token)
	if err != nil {
		// This is not critical, we can continue even if this fails
		fmt.Printf("Failed to delete reset token: %v\n", err)
	}

	return nil
}
