package user

import (
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
