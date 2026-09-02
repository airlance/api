package auth

import (
	"context"
	"fmt"
	"time"

	"airlance.org/api/internal/domain/ratelimit"
)

func (u *Usecase) checkChallengeRateLimit(ctx context.Context, key string) error {
	if u.limiter == nil {
		return nil
	}
	limits := []ratelimit.Limit{
		{Name: "auth_challenge_min", Max: 20, Window: time.Minute},
		{Name: "auth_challenge_hour", Max: 100, Window: time.Hour},
	}
	results, err := u.limiter.Allow(ctx, key, limits)
	if err != nil {
		// Fail-closed policy for authentication ceremonies
		return fmt.Errorf("%w: limiter check failed: %v", ratelimit.ErrRateLimitExceeded, err)
	}
	for _, res := range results {
		if !res.Allowed {
			return ratelimit.ErrRateLimitExceeded
		}
	}
	return nil
}
