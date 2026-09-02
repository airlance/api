// Package audit defines append-only security audit log entities and repository interfaces.
package audit

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// Standard audit event types.
const (
	EventAuthSignupSuccess = "auth.signup.success"
	EventAuthSignupFailed  = "auth.signup.failed"
	EventAuthLoginSuccess  = "auth.login.success"
	EventAuthLoginFailed   = "auth.login.failed"
	EventPasskeyAdded      = "passkey.added"
	EventPasskeyRemoved    = "passkey.removed"
	EventSessionRevoked    = "session.revoked"
	EventDeviceRevoked     = "device.revoked"
	EventClientCreated     = "apiclient.created"
	EventClientRevoked     = "apiclient.revoked"
)

// Event represents an immutable audit log record for security-relevant operations.
type Event struct {
	ID               uuid.UUID
	OccurredAt       time.Time
	UserID           *uuid.UUID
	ActorType        string
	ActorID          *uuid.UUID
	SubjectType      *string
	SubjectHash      []byte
	SubjectHashKeyID *uint16
	EventType        string
	IP               string
	UserAgent        string
	RequestID        string
	Metadata         map[string]any
	CreatedAt        time.Time
}

// Repository defines storage operations for audit logging (append-only).
type Repository interface {
	Record(ctx context.Context, e *Event) error
}
