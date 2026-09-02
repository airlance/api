// Package ratelimit provides an atomic multi-window Redis rate limiter and key registries.
package ratelimit

import (
	"context"
	"fmt"
	"strconv"
	"time"

	goredis "github.com/redis/go-redis/v9"

	domainRL "airlance.org/api/internal/domain/ratelimit"
)

// RedisLimiter implements domainRL.Limiter using atomic Redis Lua scripts.
type RedisLimiter struct {
	client *goredis.Client
}

// NewRedisLimiter constructs a RedisLimiter.
func NewRedisLimiter(client *goredis.Client) *RedisLimiter {
	return &RedisLimiter{client: client}
}

// allowLuaScript atomically inspects and increments multiple window limits.
const allowLuaScript = `
local key_prefix = KEYS[1]
local now_ms = tonumber(ARGV[1])
local num_limits = tonumber(ARGV[2])

local results = {}
local any_exceeded = 0
local max_retry_after_ms = 0

-- First pass: check limits without modifying
for i = 1, num_limits do
    local idx = 2 + (i - 1) * 3
    local name = ARGV[idx + 1]
    local max_allowed = tonumber(ARGV[idx + 2])
    local window_ms = tonumber(ARGV[idx + 3])
    
    local bucket = math.floor(now_ms / window_ms)
    local rkey = key_prefix .. ":" .. name .. ":" .. bucket
    
    local current = tonumber(redis.call("GET", rkey) or "0")
    if current >= max_allowed then
        any_exceeded = 1
        local reset_in_ms = (bucket + 1) * window_ms - now_ms
        if reset_in_ms > max_retry_after_ms then
            max_retry_after_ms = reset_in_ms
        end
    end
end

-- Second pass: if allowed, increment all; record results
for i = 1, num_limits do
    local idx = 2 + (i - 1) * 3
    local name = ARGV[idx + 1]
    local max_allowed = tonumber(ARGV[idx + 2])
    local window_ms = tonumber(ARGV[idx + 3])
    
    local bucket = math.floor(now_ms / window_ms)
    local rkey = key_prefix .. ":" .. name .. ":" .. bucket
    local reset_in_ms = (bucket + 1) * window_ms - now_ms
    
    local count = tonumber(redis.call("GET", rkey) or "0")
    if any_exceeded == 0 then
        count = redis.call("INCR", rkey)
        if count == 1 then
            redis.call("PEXPIRE", rkey, window_ms * 2)
        end
    end
    
    local remaining = max_allowed - count
    if remaining < 0 then
        remaining = 0
    end
    
    -- push to output: [allowed (0/1), remaining, reset_in_ms]
    table.insert(results, any_exceeded == 0 and 1 or 0)
    table.insert(results, remaining)
    table.insert(results, reset_in_ms)
end

return results
`

// usageLuaScript inspects current usage across multiple windows without incrementing.
const usageLuaScript = `
local key_prefix = KEYS[1]
local now_ms = tonumber(ARGV[1])
local num_limits = tonumber(ARGV[2])

local results = {}

for i = 1, num_limits do
    local idx = 2 + (i - 1) * 3
    local name = ARGV[idx + 1]
    local max_allowed = tonumber(ARGV[idx + 2])
    local window_ms = tonumber(ARGV[idx + 3])
    
    local bucket = math.floor(now_ms / window_ms)
    local rkey = key_prefix .. ":" .. name .. ":" .. bucket
    local reset_in_ms = (bucket + 1) * window_ms - now_ms
    
    local count = tonumber(redis.call("GET", rkey) or "0")
    local remaining = max_allowed - count
    if remaining < 0 then
        remaining = 0
    end
    
    local allowed = (count < max_allowed) and 1 or 0
    table.insert(results, allowed)
    table.insert(results, remaining)
    table.insert(results, reset_in_ms)
end

return results
`

// Allow checks and atomically records rate limit attempts.
func (r *RedisLimiter) Allow(ctx context.Context, key string, limits []domainRL.Limit) ([]domainRL.Result, error) {
	if len(limits) == 0 {
		return nil, nil
	}

	now := time.Now()
	nowMs := now.UnixNano() / int64(time.Millisecond)

	args := []any{nowMs, len(limits)}
	for _, l := range limits {
		windowMs := l.Window.Milliseconds()
		if windowMs <= 0 {
			windowMs = 1000
		}
		args = append(args, l.Name, l.Max, windowMs)
	}

	redisKey := fmt.Sprintf("rl:%s", key)
	val, err := r.client.Eval(ctx, allowLuaScript, []string{redisKey}, args...).Slice()
	if err != nil {
		return nil, fmt.Errorf("ratelimit: redis allow error: %w", err)
	}

	return parseLuaResults(val, limits, now)
}

// Usage inspects current rate limit usage without incrementing counts.
func (r *RedisLimiter) Usage(ctx context.Context, key string, limits []domainRL.Limit) ([]domainRL.Result, error) {
	if len(limits) == 0 {
		return nil, nil
	}

	now := time.Now()
	nowMs := now.UnixNano() / int64(time.Millisecond)

	args := []any{nowMs, len(limits)}
	for _, l := range limits {
		windowMs := l.Window.Milliseconds()
		if windowMs <= 0 {
			windowMs = 1000
		}
		args = append(args, l.Name, l.Max, windowMs)
	}

	redisKey := fmt.Sprintf("rl:%s", key)
	val, err := r.client.Eval(ctx, usageLuaScript, []string{redisKey}, args...).Slice()
	if err != nil {
		return nil, fmt.Errorf("ratelimit: redis usage error: %w", err)
	}

	return parseLuaResults(val, limits, now)
}

func parseLuaResults(raw []any, limits []domainRL.Limit, now time.Time) ([]domainRL.Result, error) {
	if len(raw) != len(limits)*3 {
		return nil, fmt.Errorf("ratelimit: unexpected result length %d for %d limits", len(raw), len(limits))
	}

	res := make([]domainRL.Result, len(limits))
	for i := 0; i < len(limits); i++ {
		idx := i * 3
		allowedVal := toInt64(raw[idx])
		remaining := toInt64(raw[idx+1])
		resetInMs := toInt64(raw[idx+2])

		allowed := allowedVal == 1
		resetAt := now.Add(time.Duration(resetInMs) * time.Millisecond)
		retryAfter := time.Duration(0)
		if !allowed {
			retryAfter = time.Duration(resetInMs) * time.Millisecond
		}

		res[i] = domainRL.Result{
			Allowed:    allowed,
			Remaining:  remaining,
			ResetAt:    resetAt,
			RetryAfter: retryAfter,
		}
	}
	return res, nil
}

func toInt64(val any) int64 {
	switch v := val.(type) {
	case int64:
		return v
	case int:
		return int64(v)
	case string:
		i, _ := strconv.ParseInt(v, 10, 64)
		return i
	default:
		return 0
	}
}
