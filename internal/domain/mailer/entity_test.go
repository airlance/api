package mailer

import (
	"errors"
	"testing"
)

func TestMessageValidate(t *testing.T) {
	tests := []struct {
		name    string
		message Message
		wantErr error
	}{
		{name: "valid", message: Message{To: "person@example.test", Subject: "Your code", Text: "123456"}},
		{name: "invalid recipient", message: Message{To: "not-an-email", Subject: "Your code", Text: "123456"}, wantErr: ErrInvalidRecipient},
		{name: "display recipient is rejected", message: Message{To: "Person <person@example.test>", Subject: "Your code", Text: "123456"}, wantErr: ErrInvalidRecipient},
		{name: "empty subject", message: Message{To: "person@example.test", Text: "123456"}, wantErr: ErrInvalidMessage},
		{name: "header injection", message: Message{To: "person@example.test", Subject: "Code\r\nBcc: attacker@example.test", Text: "123456"}, wantErr: ErrInvalidMessage},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.message.Validate()
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("Validate() error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}
