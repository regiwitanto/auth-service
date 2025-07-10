package usecase

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/regiwitanto/auth-service/config"
	"github.com/regiwitanto/auth-service/internal/domain"
	"github.com/regiwitanto/auth-service/internal/repository"
	"golang.org/x/crypto/bcrypt"
)

// authUseCase implements the AuthUseCase interface
type authUseCase struct {
	userRepo  repository.UserRepository
	tokenRepo repository.TokenRepository
	config    config.Config
}

// NewAuthUseCase creates a new auth use case
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

// Register creates a new user account
func (uc *authUseCase) Register(ctx context.Context, request *domain.RegisterRequest) (*domain.UserResponse, error) {
	// Check if user with the same email already exists
	existingUser, err := uc.userRepo.FindByEmail(ctx, request.Email)
	if err == nil && existingUser != nil {
		return nil, errors.New("user with this email already exists")
	}

	// Check if user with the same username already exists
	existingUser, err = uc.userRepo.FindByUsername(ctx, request.Username)
	if err == nil && existingUser != nil {
		return nil, errors.New("user with this username already exists")
	}

	// Hash the password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(request.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	// Create a new user
	user := &domain.User{
		Email:     request.Email,
		Username:  request.Username,
		Password:  string(hashedPassword),
		FirstName: request.FirstName,
		LastName:  request.LastName,
		Role:      "user", // Default role
		Active:    true,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	// Save to database
	if err := uc.userRepo.Create(ctx, user); err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	// Return the user without sensitive data
	response := user.ToResponse()
	return &response, nil
}

// Login authenticates a user and returns JWT tokens
func (uc *authUseCase) Login(ctx context.Context, request *domain.LoginRequest) (*domain.TokenResponse, error) {
	// Find user by email
	user, err := uc.userRepo.FindByEmail(ctx, request.Email)
	if err != nil {
		return nil, errors.New("invalid email or password")
	}

	// Check if user is active
	if !user.Active {
		return nil, errors.New("account is disabled")
	}

	// Verify password
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(request.Password)); err != nil {
		return nil, errors.New("invalid email or password")
	}

	// Generate tokens
	accessToken, err := uc.generateAccessToken(user)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	refreshToken, err := uc.generateRefreshToken(user)
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	// Store refresh token in Redis
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

// RefreshToken refreshes an access token using a valid refresh token
func (uc *authUseCase) RefreshToken(ctx context.Context, request *domain.RefreshTokenRequest) (*domain.TokenResponse, error) {
	// Verify refresh token in Redis
	userID, err := uc.tokenRepo.GetUserIDByRefreshToken(ctx, request.RefreshToken)
	if err != nil {
		return nil, errors.New("invalid or expired refresh token")
	}

	// Find user by UUID
	user, err := uc.userRepo.FindByUUID(ctx, userID)
	if err != nil {
		return nil, errors.New("user not found")
	}

	// Check if user is active
	if !user.Active {
		return nil, errors.New("account is disabled")
	}

	// Generate new tokens
	accessToken, err := uc.generateAccessToken(user)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	refreshToken, err := uc.generateRefreshToken(user)
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	// Delete old refresh token
	if err := uc.tokenRepo.DeleteRefreshToken(ctx, request.RefreshToken); err != nil {
		return nil, fmt.Errorf("failed to delete old refresh token: %w", err)
	}

	// Store new refresh token in Redis
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

// Logout invalidates the user's refresh token
func (uc *authUseCase) Logout(ctx context.Context, token string) error {
	return uc.tokenRepo.DeleteRefreshToken(ctx, token)
}

// GetUserProfile gets the user profile from a JWT token
func (uc *authUseCase) GetUserProfile(ctx context.Context, userID string) (*domain.UserResponse, error) {
	// Find user by UUID
	user, err := uc.userRepo.FindByUUID(ctx, userID)
	if err != nil {
		return nil, errors.New("user not found")
	}

	// Return the user without sensitive data
	response := user.ToResponse()
	return &response, nil
}

// VerifyToken verifies if a JWT token is valid and returns the claims
func (uc *authUseCase) VerifyToken(tokenString string) (map[string]interface{}, error) {
	// Parse the token
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Validate the signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(uc.config.JWT.Secret), nil
	})

	if err != nil {
		return nil, err
	}

	// Check if the token is valid
	if !token.Valid {
		return nil, errors.New("invalid token")
	}

	// Extract claims
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("invalid token claims")
	}

	// Convert claims to map
	claimsMap := make(map[string]interface{})
	for key, value := range claims {
		claimsMap[key] = value
	}

	return claimsMap, nil
}

// Helper methods

// generateAccessToken generates a new JWT access token
func (uc *authUseCase) generateAccessToken(user *domain.User) (string, error) {
	// Set claims
	claims := jwt.MapClaims{
		"sub":   user.UUID,
		"name":  user.Username,
		"email": user.Email,
		"role":  user.Role,
		"exp":   time.Now().Add(uc.config.JWT.AccessTokenExp).Unix(),
		"iat":   time.Now().Unix(),
	}

	// Create token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Sign token
	tokenString, err := token.SignedString([]byte(uc.config.JWT.Secret))
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

// generateRefreshToken generates a new JWT refresh token
func (uc *authUseCase) generateRefreshToken(user *domain.User) (string, error) {
	// Set claims
	claims := jwt.MapClaims{
		"sub": user.UUID,
		"exp": time.Now().Add(uc.config.JWT.RefreshTokenExp).Unix(),
		"iat": time.Now().Unix(),
	}

	// Create token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Sign token
	tokenString, err := token.SignedString([]byte(uc.config.JWT.Secret))
	if err != nil {
		return "", err
	}

	return tokenString, nil
}
