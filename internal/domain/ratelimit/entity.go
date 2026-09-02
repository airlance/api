package ratelimit

import (
	"errors"
	"time"
)

var (
	ErrRateLimitExceeded = errors.New("ratelimit: threshold exceeded")
)

type Limit struct {
	Name   string
	Max    int64
	Window time.Duration
}

type Result struct {
	Allowed    bool
	Remaining  int64
	ResetAt    time.Time
	RetryAfter time.Duration
}
