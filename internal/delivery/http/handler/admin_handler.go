package handler

import (
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/regiwitanto/auth-service/internal/usecase"
)

type AdminHandler struct {
	authUseCase usecase.AuthUseCase
}

func NewAdminHandler(authUseCase usecase.AuthUseCase) *AdminHandler {
	return &AdminHandler{
		authUseCase: authUseCase,
	}
}

// GetAllUsers returns a list of all users
// @Summary Get all users
// @Description Get a list of all users in the system (admin access required)
// @Tags admin
// @Accept json
// @Produce json
// @Security Bearer
// @Success 200 {object} map[string]interface{} "List of users"
// @Failure 401 {object} map[string]string "Unauthorized"
// @Router /admin/users [get]
func (h *AdminHandler) GetAllUsers(c echo.Context) error {

	return c.JSON(http.StatusOK, map[string]interface{}{
		"message": "Admin access granted. Users list would be shown here.",
		"users": []map[string]interface{}{
			{"uuid": "sample-uuid-1", "email": "user1@example.com", "role": "user"},
			{"uuid": "sample-uuid-2", "email": "user2@example.com", "role": "user"},
			{"uuid": "sample-uuid-3", "email": "admin@example.com", "role": "admin"},
		},
	})
}

// GetSystemStats returns system statistics
// @Summary Get system stats
// @Description Get system statistics and metrics (admin access required)
// @Tags admin
// @Accept json
// @Produce json
// @Security Bearer
// @Success 200 {object} map[string]interface{} "System statistics"
// @Failure 401 {object} map[string]string "Unauthorized"
// @Router /admin/stats [get]
func (h *AdminHandler) GetSystemStats(c echo.Context) error {
	return c.JSON(http.StatusOK, map[string]interface{}{
		"message": "Admin access granted. System stats:",
		"stats": map[string]interface{}{
			"total_users":           1205,
			"active_users":          843,
			"total_logins_today":    328,
			"failed_login_attempts": 42,
		},
	})
}
