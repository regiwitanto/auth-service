package repository_test

import (
	"context"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/regiwitanto/auth-service/internal/domain"
	"github.com/regiwitanto/auth-service/internal/repository"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func setupUserRepoMock() (repository.UserRepository, sqlmock.Sqlmock, error) {
	// Create sqlmock db connection
	db, mock, err := sqlmock.New()
	if err != nil {
		return nil, nil, err
	}

	// Create GORM DB with the mocked connection
	dialector := postgres.New(postgres.Config{
		DSN:                  "sqlmock_db_0",
		DriverName:           "postgres",
		Conn:                 db,
		PreferSimpleProtocol: true,
	})

	gormDB, err := gorm.Open(dialector, &gorm.Config{})
	if err != nil {
		return nil, nil, err
	}

	// Create repository with mocked DB
	repo := repository.NewUserRepository(gormDB)
	return repo, mock, nil
}

func TestUserRepository_Create(t *testing.T) {
	repo, mock, err := setupUserRepoMock()
	require.NoError(t, err)

	// Create a test user
	now := time.Now()
	user := &domain.User{
		UUID:      "test-uuid",
		Email:     "test@example.com",
		Username:  "testuser",
		Password:  "hashedpassword",
		FirstName: "Test",
		LastName:  "User",
		Role:      "user",
		Active:    true,
		CreatedAt: now,
		UpdatedAt: now,
	}

	// Simplified expectation that matches any INSERT query with any parameters
	mock.ExpectBegin()
	mock.ExpectQuery(`INSERT INTO "users"`).
		WillReturnRows(sqlmock.NewRows([]string{"uuid", "id"}).AddRow("test-uuid", 1))
	mock.ExpectCommit()

	// Execute test
	err = repo.Create(context.Background(), user)
	assert.NoError(t, err)

	// Verify all expectations were met
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestUserRepository_FindByID(t *testing.T) {
	repo, mock, err := setupUserRepoMock()
	require.NoError(t, err)

	// Mock data
	now := time.Now()
	expectedUser := domain.User{
		ID:        1,
		UUID:      "test-uuid",
		Email:     "test@example.com",
		Username:  "testuser",
		Password:  "hashedpassword",
		FirstName: "Test",
		LastName:  "User",
		Role:      "user",
		Active:    true,
		CreatedAt: now,
		UpdatedAt: now,
	}

	t.Run("Success", func(t *testing.T) {
		// Setup expectations
		rows := sqlmock.NewRows([]string{"id", "uuid", "email", "username", "password", "first_name", "last_name", "role", "active", "created_at", "updated_at"}).
			AddRow(expectedUser.ID, expectedUser.UUID, expectedUser.Email, expectedUser.Username, expectedUser.Password,
				expectedUser.FirstName, expectedUser.LastName, expectedUser.Role, expectedUser.Active,
				expectedUser.CreatedAt, expectedUser.UpdatedAt)

		mock.ExpectQuery(`SELECT \* FROM "users" WHERE`).
			WithArgs(expectedUser.ID).
			WillReturnRows(rows)

		// Execute test
		user, err := repo.FindByID(context.Background(), uint(expectedUser.ID))
		assert.NoError(t, err)
		assert.Equal(t, expectedUser.ID, user.ID)
		assert.Equal(t, expectedUser.Email, user.Email)
		assert.Equal(t, expectedUser.Username, user.Username)
	})

	t.Run("User Not Found", func(t *testing.T) {
		// Setup expectations - Return empty result
		mock.ExpectQuery(`SELECT \* FROM "users" WHERE`).
			WithArgs(999).
			WillReturnError(gorm.ErrRecordNotFound)

		// Execute test
		user, err := repo.FindByID(context.Background(), 999)
		assert.Error(t, err)
		assert.Nil(t, user)
		assert.Equal(t, "user not found", err.Error())
	})

	// Verify all expectations were met
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestUserRepository_FindByEmail(t *testing.T) {
	repo, mock, err := setupUserRepoMock()
	require.NoError(t, err)

	// Mock data
	now := time.Now()
	expectedUser := domain.User{
		ID:        1,
		UUID:      "test-uuid",
		Email:     "test@example.com",
		Username:  "testuser",
		Password:  "hashedpassword",
		FirstName: "Test",
		LastName:  "User",
		Role:      "user",
		Active:    true,
		CreatedAt: now,
		UpdatedAt: now,
	}

	t.Run("Success", func(t *testing.T) {
		// Setup expectations
		rows := sqlmock.NewRows([]string{"id", "uuid", "email", "username", "password", "first_name", "last_name", "role", "active", "created_at", "updated_at"}).
			AddRow(expectedUser.ID, expectedUser.UUID, expectedUser.Email, expectedUser.Username, expectedUser.Password,
				expectedUser.FirstName, expectedUser.LastName, expectedUser.Role, expectedUser.Active,
				expectedUser.CreatedAt, expectedUser.UpdatedAt)

		mock.ExpectQuery(`SELECT \* FROM "users" WHERE`).
			WithArgs(expectedUser.Email).
			WillReturnRows(rows)

		// Execute test
		user, err := repo.FindByEmail(context.Background(), expectedUser.Email)
		assert.NoError(t, err)
		assert.Equal(t, expectedUser.ID, user.ID)
		assert.Equal(t, expectedUser.Email, user.Email)
	})

	t.Run("Email Not Found", func(t *testing.T) {
		// Setup expectations - Return empty result
		mock.ExpectQuery(`SELECT \* FROM "users" WHERE`).
			WithArgs("nonexistent@example.com").
			WillReturnError(gorm.ErrRecordNotFound)

		// Execute test
		user, err := repo.FindByEmail(context.Background(), "nonexistent@example.com")
		assert.Error(t, err)
		assert.Nil(t, user)
		assert.Equal(t, "user not found", err.Error())
	})

	// Verify all expectations were met
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestUserRepository_Update(t *testing.T) {
	repo, mock, err := setupUserRepoMock()
	require.NoError(t, err)

	// Create a test user
	now := time.Now()
	user := &domain.User{
		ID:        1,
		UUID:      "test-uuid",
		Email:     "updated@example.com",
		Username:  "updateduser",
		Password:  "newhashpass",
		FirstName: "Updated",
		LastName:  "User",
		Role:      "admin", // Updated role
		Active:    true,
		CreatedAt: now,
		UpdatedAt: now,
	}

	// Expect update query with any parameters
	mock.ExpectBegin()
	mock.ExpectExec(`UPDATE "users" SET`).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	// Execute test
	err = repo.Update(context.Background(), user)
	assert.NoError(t, err)

	// Verify all expectations were met
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestUserRepository_Delete(t *testing.T) {
	repo, mock, err := setupUserRepoMock()
	require.NoError(t, err)

	t.Run("Success", func(t *testing.T) {
		// Setup expectations
		mock.ExpectBegin()
		mock.ExpectExec(`DELETE FROM "users" WHERE`).
			WithArgs(1).
			WillReturnResult(sqlmock.NewResult(0, 1))
		mock.ExpectCommit()

		// Execute test
		err := repo.Delete(context.Background(), 1)
		assert.NoError(t, err)
	})

	t.Run("User Not Found", func(t *testing.T) {
		// Setup expectations
		mock.ExpectBegin()
		mock.ExpectExec(`DELETE FROM "users" WHERE`).
			WithArgs(999).
			WillReturnResult(sqlmock.NewResult(0, 0))
		mock.ExpectCommit()

		// Execute test
		err := repo.Delete(context.Background(), 999)
		assert.NoError(t, err) // GORM doesn't return error if no rows affected
	})

	// Verify all expectations were met
	assert.NoError(t, mock.ExpectationsWereMet())
}
