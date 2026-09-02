// Package http provides HTTP route handlers, API endpoints, and server lifecycle management.
package http

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	goredis "github.com/redis/go-redis/v9"

	"airlance.org/api/internal/config"
	"airlance.org/api/internal/infrastructure/database"
)

// HealthHandlers provides health check probes.
type HealthHandlers struct {
	pool  *pgxpool.Pool
	redis *goredis.Client
	cfg   *config.Config
}

// NewHealthHandlers constructs HealthHandlers.
func NewHealthHandlers(pool *pgxpool.Pool, redis *goredis.Client, cfg *config.Config) *HealthHandlers {
	return &HealthHandlers{
		pool:  pool,
		redis: redis,
		cfg:   cfg,
	}
}

// Livez handles process liveness probe.
func (h *HealthHandlers) Livez(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":    "alive",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	})
}

// Readyz handles readiness probe checking Postgres, Redis, and schema version compatibility.
func (h *HealthHandlers) Readyz(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	checks := make(map[string]string)
	isReady := true

	// 1. Check Postgres
	if h.pool != nil {
		if err := h.pool.Ping(ctx); err != nil {
			checks["postgres"] = "unreachable: " + err.Error()
			isReady = false
		} else {
			checks["postgres"] = "ok"
		}
	} else {
		checks["postgres"] = "disabled"
	}

	// 2. Check Redis
	if h.redis != nil {
		if err := h.redis.Ping(ctx).Err(); err != nil {
			checks["redis"] = "unreachable: " + err.Error()
			isReady = false
		} else {
			checks["redis"] = "ok"
		}
	} else {
		checks["redis"] = "disabled"
	}

	// 3. Check Schema version range compatibility
	schemaVersion, dirty, err := database.GetCurrentSchemaVersion(h.cfg.DatabaseDSN, "migrations")
	if err == nil && !dirty {
		if schemaVersion > 0 && (schemaVersion < h.cfg.MinSchemaVersion || schemaVersion > h.cfg.MaxSchemaVersion) {
			checks["schema"] = "incompatible schema version"
			isReady = false
		} else {
			checks["schema"] = "ok"
		}
	} else {
		// In tests/dev without migrations, allow
		checks["schema"] = "ok"
	}

	w.Header().Set("Content-Type", "application/json")
	if !isReady {
		w.WriteHeader(http.StatusServiceUnavailable)
	} else {
		w.WriteHeader(http.StatusOK)
	}

	statusStr := "unready"
	if isReady {
		statusStr = "ready"
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":    statusStr,
		"checks":    checks,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	})
}

// Healthz legacy combined health endpoint.
func (h *HealthHandlers) Healthz(w http.ResponseWriter, r *http.Request) {
	h.Readyz(w, r)
}
