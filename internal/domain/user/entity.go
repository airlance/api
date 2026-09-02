package user

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

var (
	ErrNotFound      = errors.New("user: not found")
	ErrAlreadyExists = errors.New("user: already exists")
)

type User struct {
	ID        uuid.UUID
	CreatedAt time.Time
}
