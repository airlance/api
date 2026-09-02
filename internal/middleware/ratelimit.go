package middleware

import (
	"fmt"
	"net/http"
	"strconv"

	domainRL "airlance.org/api/internal/domain/ratelimit"
	"airlance.org/api/internal/infrastructure/logger"
)

// RateLimitConfig defines route-specific rate limiting behavior.
type RateLimitConfig struct {
	Limiter        domainRL.Limiter
	KeyExtractor   func(r *http.Request) string
	LimitsProvider func(r *http.Request) []domainRL.Limit
	FailClosed     bool
}

// RateLimitMiddleware enforces multi-window rate limits.
func RateLimitMiddleware(cfg RateLimitConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if cfg.Limiter == nil {
				next.ServeHTTP(w, r)
				return
			}

			key := ""
			if cfg.KeyExtractor != nil {
				key = cfg.KeyExtractor(r)
			}
			if key == "" {
				key = GetClientIP(r.Context())
			}

			var limits []domainRL.Limit
			if cfg.LimitsProvider != nil {
				limits = cfg.LimitsProvider(r)
			}
			if len(limits) == 0 {
				next.ServeHTTP(w, r)
				return
			}

			results, err := cfg.Limiter.Allow(r.Context(), key, limits)
			if err != nil {
				log := logger.FromContext(r.Context()).Named(logger.CategoryRateLimit)
				log.Error(err, "Rate limiter backend check failed", "key", key)

				if cfg.FailClosed {
					writeJSONError(w, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", "Rate limiting service temporarily unavailable")
					return
				}
				// Fail-open: allow request to proceed
				next.ServeHTTP(w, r)
				return
			}

			// Check results and find most restrictive
			allAllowed := true
			var mostRestrictive domainRL.Result
			var minRemaining int64 = 1<<62 - 1

			for _, res := range results {
				if !res.Allowed {
					allAllowed = false
					if res.RetryAfter > mostRestrictive.RetryAfter {
						mostRestrictive = res
					}
				}
				if res.Remaining < minRemaining {
					minRemaining = res.Remaining
				}
			}

			w.Header().Set("X-RateLimit-Remaining", strconv.FormatInt(minRemaining, 10))

			if !allAllowed {
				retryAfterSec := int(mostRestrictive.RetryAfter.Seconds())
				if retryAfterSec < 1 {
					retryAfterSec = 1
				}
				w.Header().Set("Retry-After", strconv.Itoa(retryAfterSec))
				w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(mostRestrictive.ResetAt.Unix(), 10))

				writeJSONError(w, http.StatusTooManyRequests, "RATE_LIMITED", fmt.Sprintf("Too many requests. Retry after %d seconds.", retryAfterSec))
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// FixedLimits helper returns a LimitsProvider for static rules.
func FixedLimits(limits ...domainRL.Limit) func(r *http.Request) []domainRL.Limit {
	return func(r *http.Request) []domainRL.Limit {
		return limits
	}
}

// IPKeyExtractor helper extracts the client IP as the rate limit key.
func IPKeyExtractor(prefix string) func(r *http.Request) string {
	return func(r *http.Request) string {
		ip := GetClientIP(r.Context())
		return fmt.Sprintf("%s:ip:%s", prefix, ip)
	}
}
