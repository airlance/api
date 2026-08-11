package account

import (
	"errors"
	"time"
)

var (
	ErrEmailAlreadyConfirmed = errors.New("email already confirmed")
	ErrAccountNotFound       = errors.New("account not found")
	ErrInvalidCode           = errors.New("invalid or expired confirmation code")
	ErrTooManyAttempts       = errors.New("too many confirmation attempts")
	ErrRateLimitExceeded     = errors.New("rate limit exceeded")
	ErrInvalidSessionTTL     = errors.New("invalid session ttl months")
)

type AccountID uint64

type Account struct {
	ID               AccountID
	Email            string
	FirstName        string
	LastName         string
	Confirmed        bool
	SessionTTLMonths *int
	CreatedAt        time.Time
}
