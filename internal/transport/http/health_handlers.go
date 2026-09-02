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
	"airlance.org/api/internal/infrastructure/logger"
)

type HealthHandlers struct {
	pool  *pgxpool.Pool
	redis *goredis.Client
	cfg   *config.Config
}

func NewHealthHandlers(pool *pgxpool.Pool, redis *goredis.Client, cfg *config.Config) *HealthHandlers {
	return &HealthHandlers{
		pool:  pool,
		redis: redis,
		cfg:   cfg,
	}
}

func (h *HealthHandlers) Livez(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":    "alive",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	})
}

func (h *HealthHandlers) Readyz(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	checks := make(map[string]string)
	isReady := true

	if h.pool != nil {
		if err := h.pool.Ping(ctx); err != nil {
			logger.FromContext(r.Context()).Error(err, "Postgres readiness check failed")
			checks["postgres"] = "unreachable"
			isReady = false
		} else {
			checks["postgres"] = "ok"
		}
	} else {
		checks["postgres"] = "disabled"
	}

	if h.redis != nil {
		if err := h.redis.Ping(ctx).Err(); err != nil {
			logger.FromContext(r.Context()).Error(err, "Redis readiness check failed")
			checks["redis"] = "unreachable"
			isReady = false
		} else {
			checks["redis"] = "ok"
		}
	} else {
		checks["redis"] = "disabled"
	}

	if h.cfg.DatabaseDSN != "" {
		schemaVersion, dirty, err := database.GetCurrentSchemaVersion(h.cfg.DatabaseDSN, "migrations")
		if err != nil {
			if h.cfg.Env != "test" {
				logger.FromContext(r.Context()).Error(err, "Schema readiness check failed")
				checks["schema"] = "lookup failed"
				isReady = false
			} else {
				checks["schema"] = "ok"
			}
		} else if dirty {
			checks["schema"] = "dirty schema state"
			isReady = false
		} else {
			if schemaVersion > 0 && (schemaVersion < h.cfg.MinSchemaVersion || schemaVersion > h.cfg.MaxSchemaVersion) {
				checks["schema"] = "incompatible schema version"
				isReady = false
			} else {
				checks["schema"] = "ok"
			}
		}
	} else {
		checks["schema"] = "disabled"
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

func (h *HealthHandlers) Healthz(w http.ResponseWriter, r *http.Request) {
	h.Readyz(w, r)
}
