package oidc

import (
	"context"
	"sync"
	"time"
)

// RateLimiter gates calls per opaque key over a fixed window. The
// in-memory implementation is sufficient for single-pod MVP; a Redis-
// backed implementation can swap in via the same interface as
// `NewRedisRateLimit(client, limit, window)` without touching callers.
type RateLimiter interface {
	Allow(ctx context.Context, key string) bool
}

// memoryRateLimit is a fixed-window counter — simpler than token-bucket
// or sliding-window; acceptable for MVP given Phase 1 traffic volume.
// Trade-off: a burst at the window boundary can deliver up to 2*limit
// requests across two adjacent windows.
type memoryRateLimit struct {
	mu      sync.Mutex
	buckets map[string]*bucket
	limit   int
	window  time.Duration
}

type bucket struct {
	count       int
	windowStart time.Time
}

// NewMemoryRateLimit returns a RateLimiter that allows up to `limit`
// calls per `window` per key, holding state in process memory.
func NewMemoryRateLimit(limit int, window time.Duration) RateLimiter {
	return &memoryRateLimit{
		buckets: map[string]*bucket{},
		limit:   limit,
		window:  window,
	}
}

func (m *memoryRateLimit) Allow(_ context.Context, key string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	b, ok := m.buckets[key]
	if !ok || now.Sub(b.windowStart) > m.window {
		m.buckets[key] = &bucket{count: 1, windowStart: now}
		return true
	}
	if b.count >= m.limit {
		return false
	}
	b.count++
	return true
}
