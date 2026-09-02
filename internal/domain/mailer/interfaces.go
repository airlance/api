package mailer

import "context"

// Sender delivers an email message through an external mail transport.
type Sender interface {
	Send(ctx context.Context, message Message) error
}
