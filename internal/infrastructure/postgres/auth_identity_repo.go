package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/airlance/api/internal/domain/account"
	"github.com/airlance/api/internal/domain/authidentity"
)

type AuthIdentityRepository struct {
	db *sql.DB
}

var _ authidentity.Repository = (*AuthIdentityRepository)(nil)

func NewAuthIdentityRepository(db *sql.DB) *AuthIdentityRepository {
	return &AuthIdentityRepository{db: db}
}

func (r *AuthIdentityRepository) Create(ctx context.Context, identity authidentity.AuthIdentity) (authidentity.AuthIdentity, error) {
	metaJSON, err := json.Marshal(identity.Metadata)
	if err != nil {
		return authidentity.AuthIdentity{}, fmt.Errorf("postgres: marshal metadata failed: %w", err)
	}

	query := `
		INSERT INTO auth_identities (account_id, provider, provider_user_id, provider_email, metadata)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id, account_id, provider, provider_user_id, provider_email, metadata, created_at, updated_at
	`
	var res authidentity.AuthIdentity
	var providerStr string
	var metaBytes []byte

	var provEmail sql.NullString
	if identity.ProviderEmail != "" {
		provEmail = sql.NullString{String: identity.ProviderEmail, Valid: true}
	}

	err = r.db.QueryRowContext(ctx, query,
		identity.AccountID,
		string(identity.Provider),
		identity.ProviderUserID,
		provEmail,
		metaJSON,
	).Scan(
		&res.ID,
		&res.AccountID,
		&providerStr,
		&res.ProviderUserID,
		&provEmail,
		&metaBytes,
		&res.CreatedAt,
		&res.UpdatedAt,
	)
	if err != nil {
		return authidentity.AuthIdentity{}, fmt.Errorf("postgres: create auth identity failed: %w", err)
	}

	res.Provider = authidentity.Provider(providerStr)
	if provEmail.Valid {
		res.ProviderEmail = provEmail.String
	}
	if err := json.Unmarshal(metaBytes, &res.Metadata); err != nil {
		return authidentity.AuthIdentity{}, fmt.Errorf("postgres: unmarshal metadata failed: %w", err)
	}

	return res, nil
}

func (r *AuthIdentityRepository) FindByProviderUserID(ctx context.Context, provider authidentity.Provider, providerUserID string) (authidentity.AuthIdentity, error) {
	query := `
		SELECT id, account_id, provider, provider_user_id, provider_email, metadata, created_at, updated_at
		FROM auth_identities
		WHERE provider = $1 AND provider_user_id = $2
	`
	var res authidentity.AuthIdentity
	var providerStr string
	var metaBytes []byte
	var provEmail sql.NullString

	err := r.db.QueryRowContext(ctx, query, string(provider), providerUserID).Scan(
		&res.ID,
		&res.AccountID,
		&providerStr,
		&res.ProviderUserID,
		&provEmail,
		&metaBytes,
		&res.CreatedAt,
		&res.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return authidentity.AuthIdentity{}, authidentity.ErrIdentityNotFound
		}
		return authidentity.AuthIdentity{}, fmt.Errorf("postgres: find auth identity by provider user id failed: %w", err)
	}

	res.Provider = authidentity.Provider(providerStr)
	if provEmail.Valid {
		res.ProviderEmail = provEmail.String
	}
	if err := json.Unmarshal(metaBytes, &res.Metadata); err != nil {
		return authidentity.AuthIdentity{}, fmt.Errorf("postgres: unmarshal metadata failed: %w", err)
	}

	return res, nil
}

func (r *AuthIdentityRepository) FindByAccountAndProvider(ctx context.Context, accountID account.AccountID, provider authidentity.Provider) (authidentity.AuthIdentity, error) {
	query := `
		SELECT id, account_id, provider, provider_user_id, provider_email, metadata, created_at, updated_at
		FROM auth_identities
		WHERE account_id = $1 AND provider = $2
	`
	var res authidentity.AuthIdentity
	var providerStr string
	var metaBytes []byte
	var provEmail sql.NullString

	err := r.db.QueryRowContext(ctx, query, accountID, string(provider)).Scan(
		&res.ID,
		&res.AccountID,
		&providerStr,
		&res.ProviderUserID,
		&provEmail,
		&metaBytes,
		&res.CreatedAt,
		&res.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return authidentity.AuthIdentity{}, authidentity.ErrIdentityNotFound
		}
		return authidentity.AuthIdentity{}, fmt.Errorf("postgres: find auth identity by account and provider failed: %w", err)
	}

	res.Provider = authidentity.Provider(providerStr)
	if provEmail.Valid {
		res.ProviderEmail = provEmail.String
	}
	if err := json.Unmarshal(metaBytes, &res.Metadata); err != nil {
		return authidentity.AuthIdentity{}, fmt.Errorf("postgres: unmarshal metadata failed: %w", err)
	}

	return res, nil
}

func (r *AuthIdentityRepository) ListByAccount(ctx context.Context, accountID account.AccountID) ([]authidentity.AuthIdentity, error) {
	query := `
		SELECT id, account_id, provider, provider_user_id, provider_email, metadata, created_at, updated_at
		FROM auth_identities
		WHERE account_id = $1
	`
	rows, err := r.db.QueryContext(ctx, query, accountID)
	if err != nil {
		return nil, fmt.Errorf("postgres: list auth identities by account failed: %w", err)
	}
	defer rows.Close()

	var list []authidentity.AuthIdentity
	for rows.Next() {
		var res authidentity.AuthIdentity
		var providerStr string
		var metaBytes []byte
		var provEmail sql.NullString
		err := rows.Scan(
			&res.ID,
			&res.AccountID,
			&providerStr,
			&res.ProviderUserID,
			&provEmail,
			&metaBytes,
			&res.CreatedAt,
			&res.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("postgres: scan auth identity failed: %w", err)
		}
		res.Provider = authidentity.Provider(providerStr)
		if provEmail.Valid {
			res.ProviderEmail = provEmail.String
		}
		if err := json.Unmarshal(metaBytes, &res.Metadata); err != nil {
			return nil, fmt.Errorf("postgres: unmarshal metadata failed: %w", err)
		}
		list = append(list, res)
	}

	return list, nil
}
