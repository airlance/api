package mailer

import (
	"errors"
	"net/mail"
	"strings"
)

var (
	// ErrInvalidRecipient is returned when a message recipient is not a bare valid email address.
	ErrInvalidRecipient = errors.New("mailer: invalid recipient")
	// ErrInvalidMessage is returned when a message cannot be represented safely as an email.
	ErrInvalidMessage = errors.New("mailer: invalid message")
)

// Message is a plaintext email to be delivered to one recipient.
type Message struct {
	To      string
	Subject string
	Text    string
}

// Validate checks message fields before a transport attempts delivery.
func (m Message) Validate() error {
	address, err := mail.ParseAddress(m.To)
	if err != nil || address.Address != m.To {
		return ErrInvalidRecipient
	}
	if strings.TrimSpace(m.Subject) == "" || strings.TrimSpace(m.Text) == "" {
		return ErrInvalidMessage
	}
	if strings.ContainsAny(m.Subject, "\r\n") {
		return ErrInvalidMessage
	}
	return nil
}
