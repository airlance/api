package postgres

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"

	"airlance.org/api/internal/domain/audit"
	"airlance.org/api/internal/infrastructure/database"
)

type AuditRepository struct {
	pool *pgxpool.Pool
}

func NewAuditRepository(pool *pgxpool.Pool) *AuditRepository {
	return &AuditRepository{pool: pool}
}

func (r *AuditRepository) Record(ctx context.Context, e *audit.Event) error {
	exec := database.GetExecutor(ctx, r.pool)

	metaJSON, err := json.Marshal(e.Metadata)
	if err != nil {
		metaJSON = []byte("{}")
	}

	query := `
		INSERT INTO audit_events (
			id, occurred_at, user_id, actor_type, actor_id, subject_type,
			subject_hash, subject_hash_key_id, event_type, ip, user_agent,
			request_id, metadata, created_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14
		)
	`
	_, err = exec.Exec(
		ctx, query,
		e.ID, e.OccurredAt, e.UserID, e.ActorType, e.ActorID, e.SubjectType,
		e.SubjectHash, e.SubjectHashKeyID, e.EventType, e.IP, e.UserAgent,
		e.RequestID, metaJSON, e.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("audit_repo: record failed: %w", err)
	}
	return nil
}
