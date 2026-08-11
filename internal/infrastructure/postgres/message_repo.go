package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/airlance/api/internal/domain/account"
	"github.com/airlance/api/internal/domain/message"
)

type MessageRepository struct {
	db DBTX
}

var _ message.Repository = (*MessageRepository)(nil)

func NewMessageRepository(db DBTX) *MessageRepository {
	return &MessageRepository{db: db}
}

func (r *MessageRepository) SaveMessage(ctx context.Context, msg message.Message) error {
	query := `
		INSERT INTO messages (id, client_msg_id, sender_account_id, recipient_account_id, text, state, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`
	_, err := r.db.ExecContext(ctx, query,
		msg.ID,
		msg.ClientMsgID,
		msg.SenderAccountID,
		msg.RecipientAccountID,
		msg.Text,
		msg.State,
		msg.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("postgres: save message failed: %w", err)
	}
	return nil
}

func (r *MessageRepository) GetByID(ctx context.Context, id message.MessageID) (message.Message, error) {
	query := `
		SELECT id, client_msg_id, sender_account_id, recipient_account_id, text, state, created_at
		FROM messages
		WHERE id = $1
	`
	var (
		msg       message.Message
		senderID  account.AccountID
		recipient account.AccountID
	)
	err := r.db.QueryRowContext(ctx, query, id).Scan(
		&msg.ID,
		&msg.ClientMsgID,
		&senderID,
		&recipient,
		&msg.Text,
		&msg.State,
		&msg.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return message.Message{}, message.ErrMessageNotFound
		}
		return message.Message{}, fmt.Errorf("postgres: get message by id failed: %w", err)
	}
	msg.SenderAccountID = senderID
	msg.RecipientAccountID = recipient
	return msg, nil
}

func (r *MessageRepository) UpdateState(ctx context.Context, id message.MessageID, state message.MessageState) error {
	query := `
		UPDATE messages
		SET state = $1
		WHERE id = $2
	`
	res, err := r.db.ExecContext(ctx, query, state, id)
	if err != nil {
		return fmt.Errorf("postgres: update message state failed: %w", err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("postgres: check rows affected failed: %w", err)
	}
	if affected == 0 {
		return message.ErrMessageNotFound
	}
	return nil
}
