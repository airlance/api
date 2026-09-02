package identity

import (
	"context"

	"github.com/google/uuid"
)

type Repository interface {
	Create(ctx context.Context, ident *Identity) error
	GetByID(ctx context.Context, id uuid.UUID) (*Identity, error)
	GetByKindAndIdentifier(ctx context.Context, kind Kind, identifier string) (*Identity, error)
	ListByUserID(ctx context.Context, userID uuid.UUID) ([]*Identity, error)
	MarkVerified(ctx context.Context, id uuid.UUID) error
}

type AuthProvider interface {
	Kind() Kind
}
