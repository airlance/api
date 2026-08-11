package usecase

import (
	"context"
	"fmt"

	"github.com/airlance/api/internal/domain/account"
	"github.com/airlance/api/internal/domain/device"
	"github.com/airlance/api/internal/domain/qrlogin"
	"github.com/airlance/api/internal/domain/session"
	"github.com/airlance/api/internal/infrastructure/logger"
)

type QRLoginUseCase struct {
	tickets  qrlogin.Repository
	devices  device.Repository
	sessions session.Repository
	accounts account.Repository
	events   qrlogin.EventPublisher
	notifier device.NewDeviceNotifier
}

func NewQRLoginUseCase(
	tickets qrlogin.Repository,
	devices device.Repository,
	sessions session.Repository,
	accounts account.Repository,
	events qrlogin.EventPublisher,
	notifier device.NewDeviceNotifier,
) *QRLoginUseCase {
	return &QRLoginUseCase{
		tickets:  tickets,
		devices:  devices,
		sessions: sessions,
		accounts: accounts,
		events:   events,
		notifier: notifier,
	}
}

func (uc *QRLoginUseCase) CreateTicket(ctx context.Context, nodeID string, desktopPubKey []byte) (qrlogin.Ticket, error) {
	ticket := qrlogin.Ticket{
		DesktopPublicKey: desktopPubKey,
		NodeID:           nodeID,
	}

	created, err := uc.tickets.Create(ctx, ticket)
	if err != nil {
		return qrlogin.Ticket{}, fmt.Errorf("qrlogin usecase: create ticket failed: %w", err)
	}

	return created, nil
}

func (uc *QRLoginUseCase) Scan(ctx context.Context, ticketID qrlogin.TicketID) error {
	if err := uc.tickets.MarkScanned(ctx, ticketID); err != nil {
		return fmt.Errorf("qrlogin usecase: mark scanned failed: %w", err)
	}

	t, err := uc.tickets.Find(ctx, ticketID)
	if err != nil {
		return fmt.Errorf("qrlogin usecase: find ticket failed: %w", err)
	}

	if uc.events != nil {
		err := uc.events.Publish(ctx, t.NodeID, qrlogin.Event{
			TicketID: ticketID,
			Type:     qrlogin.EventScanned,
		})
		if err != nil {
			logger.FromContext(ctx).WithField("error", err).Warn("failed to publish scan event")
		}
	}

	return nil
}

func (uc *QRLoginUseCase) Confirm(ctx context.Context, ticketID qrlogin.TicketID, accountID account.AccountID, phoneDeviceID device.DeviceID) error {
	if err := uc.tickets.Confirm(ctx, ticketID, accountID, phoneDeviceID); err != nil {
		return fmt.Errorf("qrlogin usecase: confirm ticket failed: %w", err)
	}

	t, err := uc.tickets.Find(ctx, ticketID)
	if err != nil {
		return fmt.Errorf("qrlogin usecase: find ticket failed: %w", err)
	}

	if uc.events != nil {
		err := uc.events.Publish(ctx, t.NodeID, qrlogin.Event{
			TicketID:  ticketID,
			Type:      qrlogin.EventConfirmed,
			AccountID: uint64(accountID),
			DeviceID:  uint64(phoneDeviceID),
		})
		if err != nil {
			logger.FromContext(ctx).WithField("error", err).Warn("failed to publish confirm event")
		}
	}

	return nil
}

func (uc *QRLoginUseCase) Deny(ctx context.Context, ticketID qrlogin.TicketID) error {
	t, err := uc.tickets.Find(ctx, ticketID)
	if err != nil {
		return fmt.Errorf("qrlogin usecase: find ticket failed: %w", err)
	}

	if err := uc.tickets.Deny(ctx, ticketID); err != nil {
		return fmt.Errorf("qrlogin usecase: deny ticket failed: %w", err)
	}

	if uc.events != nil {
		err := uc.events.Publish(ctx, t.NodeID, qrlogin.Event{
			TicketID: ticketID,
			Type:     qrlogin.EventDenied,
		})
		if err != nil {
			logger.FromContext(ctx).WithField("error", err).Warn("failed to publish deny event")
		}
	}

	return nil
}

func (uc *QRLoginUseCase) Complete(ctx context.Context, ticketID qrlogin.TicketID, desktopInfo DeviceInfo) (session.Session, error) {
	t, err := uc.tickets.Find(ctx, ticketID)
	if err != nil {
		return session.Session{}, fmt.Errorf("qrlogin usecase: find ticket failed: %w", err)
	}

	if t.Status != qrlogin.StatusConfirmed || t.AccountID == nil {
		return session.Session{}, fmt.Errorf("qrlogin usecase: ticket is not confirmed")
	}

	accountID := *t.AccountID
	desktopInfo.PublicKey = t.DesktopPublicKey

	dev, wasCreated, err := upsertDevice(ctx, uc.devices, accountID, desktopInfo)
	if err != nil {
		return session.Session{}, fmt.Errorf("qrlogin usecase: upsert device failed: %w", err)
	}

	if wasCreated && uc.notifier != nil {
		acc, err := uc.accounts.FindByID(ctx, accountID)
		if err == nil && acc.Email != "" {
			bgCtx := context.Background()
			go func() {
				if err := uc.notifier.NotifyNewDevice(bgCtx, acc.Email, dev); err != nil {
					logger.FromContext(ctx).WithField("error", err).Warn("failed to send new device notification")
				}
			}()
		}
	}

	sess, err := uc.sessions.CreateSession(ctx, dev.ID, accountID)
	if err != nil {
		return session.Session{}, fmt.Errorf("qrlogin usecase: create session failed: %w", err)
	}

	_ = uc.tickets.Delete(ctx, ticketID)

	return sess, nil
}
