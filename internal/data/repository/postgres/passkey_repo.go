package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"airlance.org/api/internal/domain/passkey"
	"airlance.org/api/internal/infrastructure/database"
)

type PasskeyCredentialRepository struct {
	pool *pgxpool.Pool
}

func NewPasskeyCredentialRepository(pool *pgxpool.Pool) *PasskeyCredentialRepository {
	return &PasskeyCredentialRepository{pool: pool}
}

func (r *PasskeyCredentialRepository) Create(ctx context.Context, cred *passkey.Credential) error {
	exec := database.GetExecutor(ctx, r.pool)
	query := `
		INSERT INTO passkey_credentials (id, identity_id, credential_id, public_key, sign_count, transports, aaguid, created_at, last_used_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`
	_, err := exec.Exec(ctx, query, cred.ID, cred.IdentityID, cred.CredentialID, cred.PublicKey, cred.SignCount, cred.Transports, cred.AAGUID, cred.CreatedAt, cred.LastUsedAt)
	if err != nil {
		return fmt.Errorf("passkey_repo: create credential failed: %w", err)
	}
	return nil
}

func (r *PasskeyCredentialRepository) GetByCredentialID(ctx context.Context, credID []byte) (*passkey.Credential, error) {
	exec := database.GetExecutor(ctx, r.pool)
	query := `
		SELECT id, identity_id, credential_id, public_key, sign_count, transports, aaguid, created_at, last_used_at
		FROM passkey_credentials
		WHERE credential_id = $1
	`
	row := exec.QueryRow(ctx, query, credID)

	var c passkey.Credential
	if err := row.Scan(&c.ID, &c.IdentityID, &c.CredentialID, &c.PublicKey, &c.SignCount, &c.Transports, &c.AAGUID, &c.CreatedAt, &c.LastUsedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, passkey.ErrCredentialNotFound
		}
		return nil, fmt.Errorf("passkey_repo: get by cred id failed: %w", err)
	}
	return &c, nil
}

func (r *PasskeyCredentialRepository) GetByID(ctx context.Context, id uuid.UUID) (*passkey.Credential, error) {
	exec := database.GetExecutor(ctx, r.pool)
	query := `
		SELECT id, identity_id, credential_id, public_key, sign_count, transports, aaguid, created_at, last_used_at
		FROM passkey_credentials
		WHERE id = $1
	`
	row := exec.QueryRow(ctx, query, id)

	var c passkey.Credential
	if err := row.Scan(&c.ID, &c.IdentityID, &c.CredentialID, &c.PublicKey, &c.SignCount, &c.Transports, &c.AAGUID, &c.CreatedAt, &c.LastUsedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, passkey.ErrCredentialNotFound
		}
		return nil, fmt.Errorf("passkey_repo: get by id failed: %w", err)
	}
	return &c, nil
}

func (r *PasskeyCredentialRepository) ListByIdentityID(ctx context.Context, identityID uuid.UUID) ([]*passkey.Credential, error) {
	exec := database.GetExecutor(ctx, r.pool)
	query := `
		SELECT id, identity_id, credential_id, public_key, sign_count, transports, aaguid, created_at, last_used_at
		FROM passkey_credentials
		WHERE identity_id = $1
		ORDER BY created_at ASC
	`
	rows, err := exec.Query(ctx, query, identityID)
	if err != nil {
		return nil, fmt.Errorf("passkey_repo: list by identity id failed: %w", err)
	}
	defer rows.Close()

	var res []*passkey.Credential
	for rows.Next() {
		var c passkey.Credential
		if err := rows.Scan(&c.ID, &c.IdentityID, &c.CredentialID, &c.PublicKey, &c.SignCount, &c.Transports, &c.AAGUID, &c.CreatedAt, &c.LastUsedAt); err != nil {
			return nil, fmt.Errorf("passkey_repo: scan failed: %w", err)
		}
		res = append(res, &c)
	}
	return res, rows.Err()
}

func (r *PasskeyCredentialRepository) ListByUserID(ctx context.Context, userID uuid.UUID) ([]*passkey.Credential, error) {
	exec := database.GetExecutor(ctx, r.pool)
	query := `
		SELECT pc.id, pc.identity_id, pc.credential_id, pc.public_key, pc.sign_count, pc.transports, pc.aaguid, pc.created_at, pc.last_used_at
		FROM passkey_credentials pc
		JOIN identities i ON pc.identity_id = i.id
		WHERE i.user_id = $1
		ORDER BY pc.created_at ASC
	`
	rows, err := exec.Query(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("passkey_repo: list by user id failed: %w", err)
	}
	defer rows.Close()

	var res []*passkey.Credential
	for rows.Next() {
		var c passkey.Credential
		if err := rows.Scan(&c.ID, &c.IdentityID, &c.CredentialID, &c.PublicKey, &c.SignCount, &c.Transports, &c.AAGUID, &c.CreatedAt, &c.LastUsedAt); err != nil {
			return nil, fmt.Errorf("passkey_repo: scan failed: %w", err)
		}
		res = append(res, &c)
	}
	return res, rows.Err()
}

func (r *PasskeyCredentialRepository) UpdateSignCount(ctx context.Context, id uuid.UUID, newCount uint32, lastUsedAt time.Time) error {
	exec := database.GetExecutor(ctx, r.pool)
	query := `UPDATE passkey_credentials SET sign_count = $1, last_used_at = $2 WHERE id = $3`
	cmd, err := exec.Exec(ctx, query, newCount, lastUsedAt, id)
	if err != nil {
		return fmt.Errorf("passkey_repo: update sign count failed: %w", err)
	}
	if cmd.RowsAffected() == 0 {
		return passkey.ErrCredentialNotFound
	}
	return nil
}

func (r *PasskeyCredentialRepository) DeleteByID(ctx context.Context, id uuid.UUID) error {
	exec := database.GetExecutor(ctx, r.pool)
	query := `DELETE FROM passkey_credentials WHERE id = $1`
	cmd, err := exec.Exec(ctx, query, id)
	if err != nil {
		return fmt.Errorf("passkey_repo: delete by id failed: %w", err)
	}
	if cmd.RowsAffected() == 0 {
		return passkey.ErrCredentialNotFound
	}
	return nil
}

type ChallengeRepository struct {
	pool *pgxpool.Pool
}

func NewChallengeRepository(pool *pgxpool.Pool) *ChallengeRepository {
	return &ChallengeRepository{pool: pool}
}

func (r *ChallengeRepository) Create(ctx context.Context, ch *passkey.Challenge) error {
	exec := database.GetExecutor(ctx, r.pool)
	query := `
		INSERT INTO challenges (id, user_id, type, session_data, expires_at)
		VALUES ($1, $2, $3, $4, $5)
	`
	_, err := exec.Exec(ctx, query, ch.ID, ch.UserID, string(ch.Type), ch.SessionData, ch.ExpiresAt)
	if err != nil {
		return fmt.Errorf("passkey_repo: create challenge failed: %w", err)
	}
	return nil
}

func (r *ChallengeRepository) ConsumeByID(ctx context.Context, id uuid.UUID) (*passkey.Challenge, error) {
	exec := database.GetExecutor(ctx, r.pool)
	query := `
		DELETE FROM challenges
		WHERE id = $1
		RETURNING id, user_id, type, session_data, expires_at
	`
	row := exec.QueryRow(ctx, query, id)

	var ch passkey.Challenge
	var typeStr string
	if err := row.Scan(&ch.ID, &ch.UserID, &typeStr, &ch.SessionData, &ch.ExpiresAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, passkey.ErrChallengeNotFound
		}
		return nil, fmt.Errorf("passkey_repo: consume challenge failed: %w", err)
	}
	ch.Type = passkey.ChallengeType(typeStr)

	if time.Now().After(ch.ExpiresAt) {
		return nil, passkey.ErrChallengeExpired
	}

	return &ch, nil
}

func (r *ChallengeRepository) CleanupExpired(ctx context.Context, before time.Time) (int64, error) {
	exec := database.GetExecutor(ctx, r.pool)
	query := `DELETE FROM challenges WHERE expires_at < $1`
	cmd, err := exec.Exec(ctx, query, before)
	if err != nil {
		return 0, fmt.Errorf("passkey_repo: cleanup expired challenges failed: %w", err)
	}
	return cmd.RowsAffected(), nil
}
