package ratelimit

import (
	"errors"
	"time"
)

var (
	// ErrRateLimitExceeded is returned when an operation exceeds configured thresholds.
	ErrRateLimitExceeded = errors.New("ratelimit: threshold exceeded")
)

// Limit defines a threshold limit over a duration window.
type Limit struct {
	Name   string
	Max    int64
	Window time.Duration
}

// Result describes the rate-limiting decision for a single Limit window.
type Result struct {
	Allowed    bool
	Remaining  int64
	ResetAt    time.Time
	RetryAfter time.Duration
}
