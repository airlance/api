package user

import (
	"errors"
	"time"
)

var ErrNotFound = errors.New("user: not found")

type User struct {
	ID            int32
	Email         string
	FullName      *string
	AvatarKey     *string
	CreatedAt     time.Time
	DeactivatedAt *time.Time
}

func (u *User) IsActive() bool {
	return u.DeactivatedAt == nil
}
