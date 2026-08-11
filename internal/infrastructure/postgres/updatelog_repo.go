package postgres

import (
	"context"
	"fmt"

	"github.com/airlance/api/internal/domain/account"
	"github.com/airlance/api/internal/domain/updatelog"
)

type UpdateLogRepository struct {
	db DBTX
}

var _ updatelog.Repository = (*UpdateLogRepository)(nil)

func NewUpdateLogRepository(db DBTX) *UpdateLogRepository {
	return &UpdateLogRepository{db: db}
}

func (r *UpdateLogRepository) Append(
	ctx context.Context,
	accountID account.AccountID,
	kind updatelog.UpdateKind,
	payload []byte,
) (updatelog.Seq, error) {
	const upsertSeq = `
		INSERT INTO account_seq_counters (account_id, current_seq)
		VALUES ($1, 1)
		ON CONFLICT (account_id) DO UPDATE
		  SET current_seq = account_seq_counters.current_seq + 1
		RETURNING current_seq
	`
	var seq int64
	if err := r.db.QueryRowContext(ctx, upsertSeq, accountID).Scan(&seq); err != nil {
		return 0, fmt.Errorf("postgres: upsert seq counter failed: %w", err)
	}

	const insertUpdate = `
		INSERT INTO account_updates (account_id, seq, kind, payload)
		VALUES ($1, $2, $3, $4)
	`
	if _, err := r.db.ExecContext(ctx, insertUpdate, accountID, seq, kind, payload); err != nil {
		return 0, fmt.Errorf("postgres: insert update log failed: %w", err)
	}

	return updatelog.Seq(seq), nil
}

func (r *UpdateLogRepository) ListSince(
	ctx context.Context,
	accountID account.AccountID,
	sinceSeq updatelog.Seq,
	limit int,
) (updates []updatelog.Update, currentSeq updatelog.Seq, hasMore bool, err error) {
	currentSeq, err = r.CurrentSeq(ctx, accountID)
	if err != nil {
		return nil, 0, false, err
	}

	const query = `
		SELECT seq, kind, payload, created_at
		FROM account_updates
		WHERE account_id = $1 AND seq > $2
		ORDER BY seq ASC
		LIMIT $3
	`

	rows, err := r.db.QueryContext(ctx, query, accountID, sinceSeq, limit+1)
	if err != nil {
		return nil, 0, false, fmt.Errorf("postgres: list updates failed: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var u updatelog.Update
		var seq int64
		var kind uint8
		if err := rows.Scan(&seq, &kind, &u.Payload, &u.CreatedAt); err != nil {
			return nil, 0, false, fmt.Errorf("postgres: scan update row failed: %w", err)
		}
		u.AccountID = accountID
		u.Seq = updatelog.Seq(seq)
		u.Kind = updatelog.UpdateKind(kind)
		updates = append(updates, u)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, false, fmt.Errorf("postgres: iterate update rows failed: %w", err)
	}

	if len(updates) > limit {
		hasMore = true
		updates = updates[:limit]
	}

	return updates, currentSeq, hasMore, nil
}

func (r *UpdateLogRepository) CurrentSeq(
	ctx context.Context,
	accountID account.AccountID,
) (updatelog.Seq, error) {
	const query = `
		SELECT COALESCE(MAX(seq), 0)
		FROM account_updates
		WHERE account_id = $1
	`
	var seq int64
	if err := r.db.QueryRowContext(ctx, query, accountID).Scan(&seq); err != nil {
		return 0, fmt.Errorf("postgres: get current seq failed: %w", err)
	}
	return updatelog.Seq(seq), nil
}
