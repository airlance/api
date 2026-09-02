// Package ratelimit defines rate limiting configuration, multi-window results, and engine interfaces.
package ratelimit

import (
	"context"
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

// Limiter provides multi-window rate limiting evaluation and usage querying.
type Limiter interface {
	Allow(ctx context.Context, key string, limits []Limit) ([]Result, error)
	Usage(ctx context.Context, key string, limits []Limit) ([]Result, error)
}
