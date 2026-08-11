package sessioncleanup

import (
	"context"
	"time"

	"github.com/airlance/api/internal/domain/session"
	"github.com/airlance/api/internal/infrastructure/logger"
)

type Worker struct {
	sessions session.Repository
	interval time.Duration
}

func NewWorker(sessions session.Repository, interval time.Duration) *Worker {
	if interval <= 0 {
		interval = 1 * time.Hour
	}
	return &Worker{
		sessions: sessions,
		interval: interval,
	}
}

func (w *Worker) Run(ctx context.Context) {
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			w.cleanInactiveSessions(ctx)
		}
	}
}

func (w *Worker) cleanInactiveSessions(ctx context.Context) {
	revokedCount, err := w.sessions.RevokeInactiveOlderThan(ctx, time.Now())
	if err != nil {
		logger.FromContext(ctx).WithField("error", err).Warn("failed to cleanup inactive sessions")
		return
	}
	if revokedCount > 0 {
		logger.FromContext(ctx).WithField("revoked_count", revokedCount).Info("auto-expired inactive sessions")
	}
}
