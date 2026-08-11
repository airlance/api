package message

import (
	"context"
)

type Repository interface {
	SaveMessage(ctx context.Context, msg Message) error
	GetByID(ctx context.Context, id MessageID) (Message, error)
	UpdateState(ctx context.Context, id MessageID, state MessageState) error
}
