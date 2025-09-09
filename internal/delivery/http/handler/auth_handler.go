package handler

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/golang-jwt/jwt"
	"github.com/labstack/echo/v4"
	"github.com/regiwitanto/auth-service/config"
	customMiddleware "github.com/regiwitanto/auth-service/internal/delivery/http/middleware"
	"github.com/regiwitanto/auth-service/internal/domain"
	"github.com/regiwitanto/auth-service/internal/usecase"
)

type AuthHandler struct {
	authUseCase    usecase.AuthUseCase
	validator      *validator.Validate
	config         *config.Config
	rbacMiddleware *customMiddleware.RBACMiddleware
}

func NewAuthHandler(authUseCase usecase.AuthUseCase, cfg *config.Config) *AuthHandler {
	return &AuthHandler{
		authUseCase:    authUseCase,
		validator:      validator.New(),
		config:         cfg,
		rbacMiddleware: customMiddleware.NewRBACMiddleware(),
	}
}

func (h *AuthHandler) RegisterRoutes(e *echo.Echo) {
	api := e.Group("/api/v1")
	auth := api.Group("/auth")

	var authRateLimiter, loginRateLimiter *customMiddleware.RateLimiter

	if !h.config.RateLimit.Enabled || h.config.Environment == "development" {
		authRateLimiter = customMiddleware.NewRateLimiterWithConfig(customMiddleware.RateLimiterConfig{
			Requests:  1000,
			Window:    time.Minute,
			BurstSize: 50,
			Strategy:  "ip",
		})

		loginRateLimiter = customMiddleware.NewRateLimiterWithConfig(customMiddleware.RateLimiterConfig{
			Requests:  1000,
			Window:    time.Minute,
			BurstSize: 50,
			Strategy:  "ip",
		})
	} else {
		authRateLimiter = customMiddleware.NewRateLimiterWithConfig(customMiddleware.RateLimiterConfig{
			Requests:  h.config.RateLimit.APIRequestsPerMin,
			Window:    time.Minute,
			BurstSize: h.config.RateLimit.APIBurstSize,
			Strategy:  "ip",
		})

		loginRateLimiter = customMiddleware.NewRateLimiterWithConfig(customMiddleware.RateLimiterConfig{
			Requests:  h.config.RateLimit.LoginRequestsPerMin,
			Window:    time.Minute,
			BurstSize: h.config.RateLimit.LoginBurstSize,
			Strategy:  "ip",
		})
	}

	if h.config.RateLimit.Enabled {
		auth.POST("/register", h.Register, authRateLimiter.Limit())
		auth.POST("/login", h.Login, loginRateLimiter.Limit())
		auth.POST("/refresh", h.RefreshToken, authRateLimiter.Limit())
		auth.POST("/logout", h.Logout, authRateLimiter.Limit())
		auth.POST("/forgot-password", h.ForgotPassword, authRateLimiter.Limit())
		auth.POST("/reset-password", h.ResetPassword, authRateLimiter.Limit())
	} else {
		auth.POST("/register", h.Register)
		auth.POST("/login", h.Login)
		auth.POST("/refresh", h.RefreshToken)
		auth.POST("/logout", h.Logout)
		auth.POST("/forgot-password", h.ForgotPassword)
		auth.POST("/reset-password", h.ResetPassword)
	}

	jwtValidator := customMiddleware.NewJWTValidatorMiddleware(h.config)

	user := api.Group("/user")
	user.Use(jwtValidator.ValidateToken())
	user.Use(h.rbacMiddleware.IsUser())
	user.GET("/me", h.GetUserProfile)
}

func (h *AuthHandler) Register(c echo.Context) error {
	var request domain.RegisterRequest
	if err := c.Bind(&request); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "Invalid request format",
		})
	}

	if err := h.validator.Struct(request); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "Validation failed: " + err.Error(),
		})
	}

	response, err := h.authUseCase.Register(c.Request().Context(), &request)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": err.Error(),
		})
	}

	return c.JSON(http.StatusCreated, response)
}

func (h *AuthHandler) Login(c echo.Context) error {
	ctx, cancel := context.WithTimeout(c.Request().Context(), 5*time.Second)
	defer cancel()

	var request domain.LoginRequest
	if err := c.Bind(&request); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]interface{}{
			"error":   "Invalid request format",
			"details": err.Error(),
		})
	}

	request.Email = strings.TrimSpace(request.Email)
	if err := h.validator.Struct(request); err != nil {
		// Extract validation errors for better user feedback
		validationErrors := []map[string]interface{}{}

		if validationErrs, ok := err.(validator.ValidationErrors); ok {
			for _, e := range validationErrs {
				validationErrors = append(validationErrors, map[string]interface{}{
					"field": e.Field(),
					"tag":   e.Tag(),
					"value": e.Value(),
				})
			}
		}

		return c.JSON(http.StatusBadRequest, map[string]interface{}{
			"error":   "Validation failed",
			"details": validationErrors,
		})
	}

	// Call the use case with timeout context
	response, err := h.authUseCase.Login(ctx, &request)
	if err != nil {
		// Differentiate between different error types
		switch {
		case ctx.Err() != nil:
			return c.JSON(http.StatusGatewayTimeout, map[string]string{
				"error": "Login request timed out",
			})
		case errors.Is(err, domain.ErrInvalidCredentials): // Add this error type to your domain
			return c.JSON(http.StatusUnauthorized, map[string]string{
				"error": "Invalid email or password",
			})
		case errors.Is(err, domain.ErrAccountDisabled): // Add this error type to your domain
			return c.JSON(http.StatusForbidden, map[string]string{
				"error": "Account is disabled",
			})
		default:
			// Log the actual error for debugging but don't expose it to the client
			c.Logger().Error("Login error:", err)
			return c.JSON(http.StatusInternalServerError, map[string]string{
				"error": "An unexpected error occurred during login",
			})
		}
	}

	return c.JSON(http.StatusOK, response)
}

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

		// Clean up and extract the token from the Bearer token
		authHeader = strings.TrimSpace(authHeader)
		if !strings.HasPrefix(authHeader, "Bearer ") {
			return "", echo.NewHTTPError(http.StatusUnauthorized, "Invalid authorization format")
		}

		// Extract token and trim any spaces
		token := strings.TrimSpace(authHeader[7:])

		// Verify the token manually
		claims, err := h.authUseCase.VerifyToken(token)
		if err != nil {
			return "", echo.NewHTTPError(http.StatusUnauthorized, "Invalid token: "+err.Error())
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
