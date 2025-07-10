package handler_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang-jwt/jwt"
	"github.com/labstack/echo/v4"
	"github.com/regiwitanto/auth-service/internal/delivery/http/handler"
	"github.com/regiwitanto/auth-service/internal/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type AdminHandlerTestSuite struct {
	suite.Suite
	mockAuthUseCase *mocks.MockAuthUseCase
	adminHandler    *handler.AdminHandler
	e               *echo.Echo
}

func (suite *AdminHandlerTestSuite) SetupTest() {
	suite.mockAuthUseCase = new(mocks.MockAuthUseCase)
	suite.adminHandler = handler.NewAdminHandler(suite.mockAuthUseCase)
	suite.e = echo.New()
}

func TestAdminHandlerSuite(t *testing.T) {
	suite.Run(t, new(AdminHandlerTestSuite))
}

func (suite *AdminHandlerTestSuite) TestGetAllUsers() {
	// Arrange
	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/users", nil)
	rec := httptest.NewRecorder()
	c := suite.e.NewContext(req, rec)

	// Mock JWT token with admin role
	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)
	claims["sub"] = "admin-uuid"
	claims["role"] = "admin"
	c.Set("user", token)

	// Act
	err := suite.adminHandler.GetAllUsers(c)

	// Assert
	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), http.StatusOK, rec.Code)
	assert.Contains(suite.T(), rec.Body.String(), "Admin access granted")
	assert.Contains(suite.T(), rec.Body.String(), "users")
}

func (suite *AdminHandlerTestSuite) TestGetSystemStats() {
	// Arrange
	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/stats", nil)
	rec := httptest.NewRecorder()
	c := suite.e.NewContext(req, rec)

	// Mock JWT token with admin role
	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)
	claims["sub"] = "admin-uuid"
	claims["role"] = "admin"
	c.Set("user", token)

	// Act
	err := suite.adminHandler.GetSystemStats(c)

	// Assert
	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), http.StatusOK, rec.Code)
	assert.Contains(suite.T(), rec.Body.String(), "Admin access granted")
	assert.Contains(suite.T(), rec.Body.String(), "stats")
}
