package qrlogin

import (
	"context"

	"github.com/airlance/api/internal/domain/account"
	"github.com/airlance/api/internal/domain/device"
)

type Repository interface {
	Create(ctx context.Context, t Ticket) (Ticket, error)
	Find(ctx context.Context, id TicketID) (Ticket, error)
	MarkScanned(ctx context.Context, id TicketID) error
	Confirm(ctx context.Context, id TicketID, accountID account.AccountID, deviceID device.DeviceID) error
	Deny(ctx context.Context, id TicketID) error
	Delete(ctx context.Context, id TicketID) error
}

type EventPublisher interface {
	Publish(ctx context.Context, nodeID string, event Event) error
}
