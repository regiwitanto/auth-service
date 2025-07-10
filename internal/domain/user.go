package domain

import (
	"time"
)

// User represents the user entity in the domain
type User struct {
	ID        uint      `json:"id" gorm:"primaryKey"`
	UUID      string    `json:"uuid" gorm:"type:uuid;default:uuid_generate_v4();unique"`
	Email     string    `json:"email" gorm:"unique;not null"`
	Username  string    `json:"username" gorm:"unique;not null"`
	Password  string    `json:"-" gorm:"not null"` // Password is not exposed in JSON
	FirstName string    `json:"first_name"`
	LastName  string    `json:"last_name"`
	Role      string    `json:"role" gorm:"default:'user'"`
	Active    bool      `json:"active" gorm:"default:true"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// UserResponse represents the user response without sensitive data
type UserResponse struct {
	UUID      string    `json:"uuid"`
	Email     string    `json:"email"`
	Username  string    `json:"username"`
	FirstName string    `json:"first_name"`
	LastName  string    `json:"last_name"`
	Role      string    `json:"role"`
	CreatedAt time.Time `json:"created_at"`
}

// ToResponse converts User entity to UserResponse
func (u *User) ToResponse() UserResponse {
	return UserResponse{
		UUID:      u.UUID,
		Email:     u.Email,
		Username:  u.Username,
		FirstName: u.FirstName,
		LastName:  u.LastName,
		Role:      u.Role,
		CreatedAt: u.CreatedAt,
	}
}
