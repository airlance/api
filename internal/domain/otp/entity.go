package otp

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

var (
	ErrNotFound        = errors.New("otp: not found or already consumed")
	ErrExpired         = errors.New("otp: expired")
	ErrTooManyAttempts = errors.New("otp: too many attempts")
	ErrInvalidCode     = errors.New("otp: invalid code")
	ErrAlreadyLinked   = errors.New("otp: email already linked to another account")
)

type Purpose string

const PurposeLinkEmail Purpose = "link_email"

type Code struct {
	ID          uuid.UUID
	UserID      uuid.UUID
	Email       string
	Purpose     Purpose
	CodeHash    []byte
	KeyID       uint16
	Attempts    int
	MaxAttempts int
	ExpiresAt   time.Time
	ConsumedAt  *time.Time
	CreatedAt   time.Time
}

func (c *Code) IsActive(now time.Time) bool {
	return c.ConsumedAt == nil && now.Before(c.ExpiresAt) && c.Attempts < c.MaxAttempts
}
