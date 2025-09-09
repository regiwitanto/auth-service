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
	"github.com/regiwitanto/auth-service/internal/pkg/logger"
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
	logger.Info("Register request received",
		logger.String("ip", c.RealIP()),
		logger.String("user_agent", c.Request().UserAgent()))

	var request domain.RegisterRequest
	if err := c.Bind(&request); err != nil {
		logger.Warn("Failed to bind register request",
			logger.String("ip", c.RealIP()),
			logger.Err(err))
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "Invalid request format",
		})
	}

	if err := h.validator.Struct(request); err != nil {
		logger.Warn("Register validation failed",
			logger.String("email", request.Email),
			logger.String("username", request.Username),
			logger.Err(err))
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "Validation failed: " + err.Error(),
		})
	}

	response, err := h.authUseCase.Register(c.Request().Context(), &request)
	if err != nil {
		logger.Warn("Register use case failed",
			logger.String("email", request.Email),
			logger.String("username", request.Username),
			logger.Err(err))
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": err.Error(),
		})
	}

	logger.Info("User registered successfully via API",
		logger.String("email", request.Email),
		logger.String("username", request.Username))
	return c.JSON(http.StatusCreated, response)
}

func (h *AuthHandler) Login(c echo.Context) error {
	logger.Info("Login request received",
		logger.String("ip", c.RealIP()),
		logger.String("user_agent", c.Request().UserAgent()))

	ctx, cancel := context.WithTimeout(c.Request().Context(), 5*time.Second)
	defer cancel()

	var request domain.LoginRequest
	if err := c.Bind(&request); err != nil {
		logger.Warn("Failed to bind login request",
			logger.String("ip", c.RealIP()),
			logger.Err(err))
		return c.JSON(http.StatusBadRequest, map[string]interface{}{
			"error":   "Invalid request format",
			"details": err.Error(),
		})
	}

	request.Email = strings.TrimSpace(request.Email)
	logger.Debug("Login request validation", logger.String("email", request.Email))

	if err := h.validator.Struct(request); err != nil {
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

		logger.Warn("Login validation failed",
			logger.String("email", request.Email),
			logger.Any("validation_errors", validationErrors))

		return c.JSON(http.StatusBadRequest, map[string]interface{}{
			"error":   "Validation failed",
			"details": validationErrors,
		})
	}

	response, err := h.authUseCase.Login(ctx, &request)
	if err != nil {
		switch {
		case ctx.Err() != nil:
			logger.Warn("Login request timed out",
				logger.String("email", request.Email),
				logger.Err(ctx.Err()))
			return c.JSON(http.StatusGatewayTimeout, map[string]string{
				"error": "Login request timed out",
			})
		case errors.Is(err, domain.ErrInvalidCredentials):
			logger.Warn("Failed login attempt: invalid credentials",
				logger.String("email", request.Email),
				logger.String("ip", c.RealIP()))
			return c.JSON(http.StatusUnauthorized, map[string]string{
				"error": "Invalid email or password",
			})
		case errors.Is(err, domain.ErrAccountDisabled):
			logger.Warn("Login attempt for disabled account",
				logger.String("email", request.Email),
				logger.String("ip", c.RealIP()))
			return c.JSON(http.StatusForbidden, map[string]string{
				"error": "Account is disabled",
			})
		default:
			logger.Error("Unexpected login error",
				logger.String("email", request.Email),
				logger.String("ip", c.RealIP()),
				logger.Err(err))
			return c.JSON(http.StatusInternalServerError, map[string]string{
				"error": "An unexpected error occurred during login",
			})
		}
	}

	logger.Info("User logged in successfully",
		logger.String("email", request.Email),
		logger.String("ip", c.RealIP()))
	return c.JSON(http.StatusOK, response)
}

func (h *AuthHandler) RefreshToken(c echo.Context) error {
	logger.Debug("Refresh token request received",
		logger.String("ip", c.RealIP()),
		logger.String("user_agent", c.Request().UserAgent()))

	var request domain.RefreshTokenRequest
	if err := c.Bind(&request); err != nil {
		logger.Warn("Failed to bind refresh token request",
			logger.String("ip", c.RealIP()),
			logger.Err(err))
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "Invalid request format",
		})
	}

	if err := h.validator.Struct(request); err != nil {
		logger.Warn("Refresh token validation failed",
			logger.String("ip", c.RealIP()),
			logger.Err(err))
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "Validation failed: " + err.Error(),
		})
	}

	response, err := h.authUseCase.RefreshToken(c.Request().Context(), &request)
	if err != nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{
			"error": err.Error(),
		})
	}

	return c.JSON(http.StatusOK, response)
}

func (h *AuthHandler) Logout(c echo.Context) error {
	var request domain.RefreshTokenRequest
	if err := c.Bind(&request); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "Invalid request format",
		})
	}

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
	userID, err := h.extractUserID(c)
	if err != nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{
			"error": "Invalid or missing token",
		})
	}

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

	if err := h.validator.Struct(request); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "Validation failed: " + err.Error(),
		})
	}

	err := h.authUseCase.ForgotPassword(c.Request().Context(), &request)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": err.Error(),
		})
	}

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

	if err := h.validator.Struct(request); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "Validation failed: " + err.Error(),
		})
	}

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
	if userID, ok := c.Get("userID").(string); ok && userID != "" {
		return userID, nil
	}

	user := c.Get("user")
	if user == nil {
		authHeader := c.Request().Header.Get("Authorization")
		if authHeader == "" {
			return "", echo.NewHTTPError(http.StatusUnauthorized, "Missing authorization header")
		}

		authHeader = strings.TrimSpace(authHeader)
		if !strings.HasPrefix(authHeader, "Bearer ") {
			return "", echo.NewHTTPError(http.StatusUnauthorized, "Invalid authorization format")
		}

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
