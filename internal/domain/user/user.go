// Package user defines the User core domain entity and repository interface.
package user

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
)

var (
	// ErrNotFound is returned when a requested user does not exist.
	ErrNotFound = errors.New("user: not found")
	// ErrAlreadyExists is returned when attempting to create an existing user.
	ErrAlreadyExists = errors.New("user: already exists")
)

// User represents a registered individual or identity owner in the system.
type User struct {
	ID        uuid.UUID
	CreatedAt time.Time
}

// Repository defines storage operations for users.
type Repository interface {
	Create(ctx context.Context, u *User) error
	GetByID(ctx context.Context, id uuid.UUID) (*User, error)
}
