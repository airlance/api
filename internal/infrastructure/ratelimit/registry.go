package ratelimit

import (
	"sync"
	"time"

	domainRL "airlance.org/api/internal/domain/ratelimit"
)

type cachedLimiter struct {
	limits   []domainRL.Limit
	lastSeen time.Time
}

type Registry struct {
	mu      sync.RWMutex
	cache   map[string]*cachedLimiter
	limiter domainRL.Limiter
	ttl     time.Duration
}

func NewRegistry(limiter domainRL.Limiter, idleTTL time.Duration) *Registry {
	r := &Registry{
		cache:   make(map[string]*cachedLimiter),
		limiter: limiter,
		ttl:     idleTTL,
	}
	go r.evictionLoop()
	return r
}

func (r *Registry) SetLimits(key string, limits []domainRL.Limit) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cache[key] = &cachedLimiter{
		limits:   limits,
		lastSeen: time.Now(),
	}
}

func (r *Registry) GetLimits(key string) ([]domainRL.Limit, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	item, ok := r.cache[key]
	if !ok {
		return nil, false
	}
	item.lastSeen = time.Now()
	return item.limits, true
}

func (r *Registry) evictionLoop() {
	ticker := time.NewTicker(r.ttl)
	defer ticker.Stop()

	for now := range ticker.C {
		r.mu.Lock()
		for k, v := range r.cache {
			if now.Sub(v.lastSeen) > r.ttl {
				delete(r.cache, k)
			}
		}
		r.mu.Unlock()
	}
}
