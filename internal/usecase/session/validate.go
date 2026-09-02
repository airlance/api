package session

import (
	"context"

	"airlance.org/api/internal/domain/crypto"
	"airlance.org/api/internal/domain/session"
)

func (u *Usecase) Validate(ctx context.Context, token string) (*session.Session, error) {
	if token == "" {
		return nil, ErrInvalidToken
	}

	tokenHash := crypto.HashToken(token)
	sess, err := u.sessionRepo.GetValid(ctx, tokenHash)
	if err != nil {
		return nil, err
	}

	return sess, nil
}
