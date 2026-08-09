package user

import "context"

type Repository interface {
	GetByID(ctx context.Context, id int32) (*User, error)
	GetOrCreateByEmail(ctx context.Context, email string, fullName string) (*User, error)
}
