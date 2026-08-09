package redis

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/airlance/api/internal/domain/session"
	"github.com/redis/go-redis/v9"
)

const cacheTTL = 30 * 24 * time.Hour

type cachePayload struct {
	UserID      int32  `json:"user_id"`
	LastSeenSeq uint64 `json:"last_seen_seq"`
}

type SessionCache struct {
	client *redis.Client
}

func NewSessionCache(client *redis.Client) *SessionCache {
	return &SessionCache{client: client}
}

func cacheKey(authKeyID uint64) string {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, authKeyID)
	return "session:" + hex.EncodeToString(buf)
}

func (c *SessionCache) Get(ctx context.Context, authKeyID uint64) (*session.CacheEntry, error) {
	raw, err := c.client.Get(ctx, cacheKey(authKeyID)).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("redis: get session cache entry: %w", err)
	}

	var p cachePayload
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, fmt.Errorf("redis: unmarshal session cache entry: %w", err)
	}
	return &session.CacheEntry{
		UserID:      p.UserID,
		LastSeenSeq: p.LastSeenSeq,
	}, nil
}

func (c *SessionCache) Set(ctx context.Context, authKeyID uint64, entry session.CacheEntry) error {
	raw, err := json.Marshal(cachePayload{
		UserID:      entry.UserID,
		LastSeenSeq: entry.LastSeenSeq,
	})
	if err != nil {
		return fmt.Errorf("redis: marshal session cache entry: %w", err)
	}
	if err := c.client.Set(ctx, cacheKey(authKeyID), raw, cacheTTL).Err(); err != nil {
		return fmt.Errorf("redis: set session cache entry: %w", err)
	}
	return nil
}

func (c *SessionCache) Delete(ctx context.Context, authKeyID uint64) error {
	if err := c.client.Del(ctx, cacheKey(authKeyID)).Err(); err != nil {
		return fmt.Errorf("redis: delete session cache entry: %w", err)
	}
	return nil
}

var _ session.SessionCache = (*SessionCache)(nil)
