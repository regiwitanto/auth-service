package handler

import (
	"net/http"
	"strings"

	"github.com/go-playground/validator/v10"
	"github.com/golang-jwt/jwt"
	"github.com/labstack/echo/v4"
	"github.com/regiwitanto/auth-service/internal/domain"
	"github.com/regiwitanto/auth-service/internal/usecase"
)

type AuthHandler struct {
	authUseCase usecase.AuthUseCase
	validator   *validator.Validate
}

func NewAuthHandler(authUseCase usecase.AuthUseCase) *AuthHandler {
	return &AuthHandler{
		authUseCase: authUseCase,
		validator:   validator.New(),
	}
}

// Register handles user registration
func (h *AuthHandler) Register(c echo.Context) error {
	var request domain.RegisterRequest
	if err := c.Bind(&request); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "Invalid request format",
		})
	}

	// Validate the request
	if err := h.validator.Struct(request); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "Validation failed: " + err.Error(),
		})
	}

	// Call the use case
	response, err := h.authUseCase.Register(c.Request().Context(), &request)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": err.Error(),
		})
	}

	return c.JSON(http.StatusCreated, response)
}

// Login handles user login
func (h *AuthHandler) Login(c echo.Context) error {
	var request domain.LoginRequest
	if err := c.Bind(&request); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "Invalid request format",
		})
	}

	// Validate the request
	if err := h.validator.Struct(request); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "Validation failed: " + err.Error(),
		})
	}

	// Call the use case
	response, err := h.authUseCase.Login(c.Request().Context(), &request)
	if err != nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{
			"error": err.Error(),
		})
	}

	return c.JSON(http.StatusOK, response)
}

// RefreshToken handles token refresh
func (h *AuthHandler) RefreshToken(c echo.Context) error {
	var request domain.RefreshTokenRequest
	if err := c.Bind(&request); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "Invalid request format",
		})
	}

	// Validate the request
	if err := h.validator.Struct(request); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "Validation failed: " + err.Error(),
		})
	}

	// Call the use case
	response, err := h.authUseCase.RefreshToken(c.Request().Context(), &request)
	if err != nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{
			"error": err.Error(),
		})
	}

	return c.JSON(http.StatusOK, response)
}

// Logout handles user logout
func (h *AuthHandler) Logout(c echo.Context) error {
	// Extract the refresh token from the request
	var request domain.RefreshTokenRequest
	if err := c.Bind(&request); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "Invalid request format",
		})
	}

	// Call the use case
	if err := h.authUseCase.Logout(c.Request().Context(), request.RefreshToken); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": err.Error(),
		})
	}

	return c.JSON(http.StatusOK, map[string]string{
		"message": "Logged out successfully",
	})
}

// GetUserProfile handles retrieving the user profile
func (h *AuthHandler) GetUserProfile(c echo.Context) error {
	// Extract user ID from JWT token
	userID, err := h.extractUserID(c)
	if err != nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{
			"error": "Invalid or missing token",
		})
	}

	// Call the use case
	response, err := h.authUseCase.GetUserProfile(c.Request().Context(), userID)
	if err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{
			"error": err.Error(),
		})
	}

	return c.JSON(http.StatusOK, response)
}

// ForgotPassword initiates the password reset process
func (h *AuthHandler) ForgotPassword(c echo.Context) error {
	var request domain.ForgotPasswordRequest
	if err := c.Bind(&request); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "Invalid request format",
		})
	}

	// Validate the request
	if err := h.validator.Struct(request); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "Validation failed: " + err.Error(),
		})
	}

	// Call the use case
	err := h.authUseCase.ForgotPassword(c.Request().Context(), &request)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": err.Error(),
		})
	}

	// Always return success, even if email doesn't exist (security best practice)
	return c.JSON(http.StatusOK, map[string]string{
		"message": "If your email is registered, you will receive password reset instructions",
	})
}

// ResetPassword resets the user's password
func (h *AuthHandler) ResetPassword(c echo.Context) error {
	var request domain.ResetPasswordRequest
	if err := c.Bind(&request); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "Invalid request format",
		})
	}

	// Validate the request
	if err := h.validator.Struct(request); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "Validation failed: " + err.Error(),
		})
	}

	// Call the use case
	if err := h.authUseCase.ResetPassword(c.Request().Context(), &request); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": err.Error(),
		})
	}

	return c.JSON(http.StatusOK, map[string]string{
		"message": "Password has been reset successfully",
	})
}

// Helper methods

// extractUserID extracts the user ID from the JWT token
func (h *AuthHandler) extractUserID(c echo.Context) (string, error) {
	// Get the token from the context (set by JWT middleware)
	// First check if the userID has been directly set (for tests)
	if userID, ok := c.Get("userID").(string); ok && userID != "" {
		return userID, nil
	}

	user := c.Get("user")
	if user == nil {
		authHeader := c.Request().Header.Get("Authorization")
		if authHeader == "" {
			return "", echo.NewHTTPError(http.StatusUnauthorized, "Missing authorization header")
		}

		// Extract the token from the Bearer token
		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			return "", echo.NewHTTPError(http.StatusUnauthorized, "Invalid authorization format")
		}

		// Verify the token manually
		claims, err := h.authUseCase.VerifyToken(parts[1])
		if err != nil {
			return "", echo.NewHTTPError(http.StatusUnauthorized, "Invalid token")
		}

		// Extract the user ID from claims
		sub, ok := claims["sub"].(string)
		if !ok {
			return "", echo.NewHTTPError(http.StatusUnauthorized, "Invalid token claims")
		}

		return sub, nil
	}

	// If the middleware has already processed the token
	token, ok := user.(*jwt.Token)
	if !ok {
		return "", echo.NewHTTPError(http.StatusUnauthorized, "Invalid token")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return "", echo.NewHTTPError(http.StatusUnauthorized, "Invalid token claims")
	}

	sub, ok := claims["sub"].(string)
	if !ok {
		return "", echo.NewHTTPError(http.StatusUnauthorized, "Invalid token claims")
	}

	return sub, nil
}
