package eventbus

import (
	"time"
)

const (
	TopicSessionRevoked      = "session.revoked"
	TopicDeviceRevoked       = "device.revoked"
	TopicUserSessionsRevoked = "user.sessions_revoked"
)

type Event struct {
	Topic     string
	Payload   any
	Timestamp time.Time
}
