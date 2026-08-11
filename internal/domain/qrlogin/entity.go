package qrlogin

import (
	"errors"
	"time"

	"github.com/airlance/api/internal/domain/account"
	"github.com/airlance/api/internal/domain/device"
)

type TicketID string

type Status string

const (
	StatusPending   Status = "pending"
	StatusScanned   Status = "scanned"
	StatusConfirmed Status = "confirmed"
	StatusExpired   Status = "expired"
	StatusDenied    Status = "denied"
)

type Ticket struct {
	ID               TicketID           `json:"id"`
	Status           Status             `json:"status"`
	DesktopPublicKey []byte             `json:"desktop_public_key"`
	NodeID           string             `json:"node_id"`
	AccountID        *account.AccountID `json:"account_id,omitempty"`
	DeviceID         *device.DeviceID   `json:"device_id,omitempty"`
	CreatedAt        time.Time          `json:"created_at"`
	ExpiresAt        time.Time          `json:"expires_at"`
}

type EventType string

const (
	EventScanned   EventType = "scanned"
	EventConfirmed EventType = "confirmed"
	EventDenied    EventType = "denied"
)

type Event struct {
	TicketID  TicketID  `json:"ticket_id"`
	Type      EventType `json:"type"`
	AccountID uint64    `json:"account_id,omitempty"`
	DeviceID  uint64    `json:"device_id,omitempty"`
}

var (
	ErrTicketNotFound = errors.New("qr login ticket not found")
	ErrTicketExpired  = errors.New("qr login ticket expired")
	ErrAlreadyScanned = errors.New("qr login ticket already scanned")
)
