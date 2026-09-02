package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	domainRL "airlance.org/api/internal/domain/ratelimit"
)

type mockLimiter struct {
	allowFunc func(ctx context.Context, key string, limits []domainRL.Limit) ([]domainRL.Result, error)
}

func (m *mockLimiter) Allow(ctx context.Context, key string, limits []domainRL.Limit) ([]domainRL.Result, error) {
	if m.allowFunc != nil {
		return m.allowFunc(ctx, key, limits)
	}
	return []domainRL.Result{{Allowed: true, Remaining: 10, ResetAt: time.Now().Add(time.Minute)}}, nil
}

func (m *mockLimiter) Usage(ctx context.Context, key string, limits []domainRL.Limit) ([]domainRL.Result, error) {
	return nil, nil
}

func TestRateLimitMiddleware_Allow(t *testing.T) {
	limiter := &mockLimiter{
		allowFunc: func(ctx context.Context, key string, limits []domainRL.Limit) ([]domainRL.Result, error) {
			return []domainRL.Result{
				{Allowed: true, Remaining: 5, ResetAt: time.Now().Add(time.Minute)},
			}, nil
		},
	}

	mw := RateLimitMiddleware(RateLimitConfig{
		Limiter:        limiter,
		LimitsProvider: FixedLimits(domainRL.Limit{Name: "min", Max: 10, Window: time.Minute}),
		FailClosed:     true,
	})

	req := httptest.NewRequest("GET", "/api/v1/test", nil)
	rec := httptest.NewRecorder()

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	if rec.Header().Get("X-RateLimit-Remaining") != "5" {
		t.Errorf("expected remaining 5, got %s", rec.Header().Get("X-RateLimit-Remaining"))
	}
}

func TestRateLimitMiddleware_Deny(t *testing.T) {
	limiter := &mockLimiter{
		allowFunc: func(ctx context.Context, key string, limits []domainRL.Limit) ([]domainRL.Result, error) {
			return []domainRL.Result{
				{Allowed: false, Remaining: 0, ResetAt: time.Now().Add(30 * time.Second), RetryAfter: 30 * time.Second},
			}, nil
		},
	}

	mw := RateLimitMiddleware(RateLimitConfig{
		Limiter:        limiter,
		LimitsProvider: FixedLimits(domainRL.Limit{Name: "min", Max: 10, Window: time.Minute}),
		FailClosed:     true,
	})

	req := httptest.NewRequest("GET", "/api/v1/test", nil)
	rec := httptest.NewRecorder()

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429, got %d", rec.Code)
	}
	if rec.Header().Get("Retry-After") != "30" {
		t.Errorf("expected Retry-After 30, got %s", rec.Header().Get("Retry-After"))
	}
}
