package ratelimit

import (
	"context"
)

// Limiter provides multi-window rate limiting evaluation and usage querying.
type Limiter interface {
	Allow(ctx context.Context, key string, limits []Limit) ([]Result, error)
	Usage(ctx context.Context, key string, limits []Limit) ([]Result, error)
}
