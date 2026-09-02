package ratelimit

import (
	"context"
)

type Limiter interface {
	Allow(ctx context.Context, key string, limits []Limit) ([]Result, error)
	Usage(ctx context.Context, key string, limits []Limit) ([]Result, error)
}
