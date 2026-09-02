package wsticket

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

var (
	ErrNotFound = errors.New("wsticket: not found or already consumed")
	ErrExpired  = errors.New("wsticket: expired")
)

type Ticket struct {
	ID        string
	UserID    uuid.UUID
	SessionID uuid.UUID
	DeviceID  *uuid.UUID
	ExpiresAt time.Time
}
