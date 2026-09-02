package eventbus

import (
	"time"
)

// Standard topic constants for cross-component security event delivery.
const (
	TopicSessionRevoked      = "session.revoked"
	TopicDeviceRevoked       = "device.revoked"
	TopicUserSessionsRevoked = "user.sessions_revoked"
)

// Event encapsulates a published message.
type Event struct {
	Topic     string
	Payload   any
	Timestamp time.Time
}
