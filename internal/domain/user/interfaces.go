package user

import (
	"context"

	"github.com/google/uuid"
)

// Repository defines storage operations for users.
type Repository interface {
	Create(ctx context.Context, u *User) error
	GetByID(ctx context.Context, id uuid.UUID) (*User, error)
}
