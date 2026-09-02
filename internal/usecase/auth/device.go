package auth

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"airlance.org/api/internal/domain/audit"
	"airlance.org/api/internal/domain/crypto"
	"airlance.org/api/internal/domain/device"
	"airlance.org/api/internal/domain/eventbus"
)

func (u *Usecase) RevokeDevice(ctx context.Context, userID, deviceID uuid.UUID, ip, userAgent, requestID string) error {
	dev, err := u.deviceRepo.GetByID(ctx, deviceID)
	if err != nil {
		return err
	}
	if dev.UserID != userID {
		return ErrDeviceForbidden
	}

	now := time.Now()
	err = u.txManager.WithTx(ctx, func(txCtx context.Context) error {
		if err := u.deviceRepo.Revoke(txCtx, deviceID); err != nil {
			return err
		}

		auditEv := &audit.Event{
			ID:         uuid.New(),
			OccurredAt: now,
			UserID:     &userID,
			ActorType:  "user",
			ActorID:    &userID,
			EventType:  audit.EventDeviceRevoked,
			IP:         ip,
			UserAgent:  userAgent,
			RequestID:  requestID,
			Metadata: map[string]any{
				"device_id": deviceID.String(),
			},
			CreatedAt: now,
		}
		return u.auditRepo.Record(txCtx, auditEv)
	})

	if err != nil {
		return fmt.Errorf("auth: revoke device tx failed: %w", err)
	}

	if u.eventBus != nil {
		_ = u.eventBus.Publish(ctx, eventbus.TopicDeviceRevoked, eventbus.Event{
			Topic:     eventbus.TopicDeviceRevoked,
			Payload:   deviceID,
			Timestamp: now,
		})
	}

	return nil
}

func (u *Usecase) ListDevices(ctx context.Context, userID uuid.UUID) ([]*device.Device, error) {
	return u.deviceRepo.ListByUserID(ctx, userID)
}

func (u *Usecase) resolveOrCreateDevice(ctx context.Context, userID uuid.UUID, rawDeviceID, platform string, appVersion *string) (uuid.UUID, error) {
	data := []byte(rawDeviceID)
	ring := u.deviceHMACKeyRing

	var matchedDevice *device.Device
	var needsRotation bool

	for _, key := range ring.Keys {
		h := crypto.ComputeHMAC(data, key)
		dev, err := u.deviceRepo.GetByHash(ctx, h)
		if err == nil && dev != nil && dev.UserID == userID && dev.IsValid() {
			matchedDevice = dev
			currentKey := ring.Keys[ring.CurrentKeyID]
			if !crypto.ConstantTimeCompareBytes(h, crypto.ComputeHMAC(data, currentKey)) {
				needsRotation = true
			}
			break
		}
	}

	now := time.Now()
	if matchedDevice != nil {
		_ = u.deviceRepo.Touch(ctx, matchedDevice.ID, appVersion, now)
		if needsRotation {
			newHash, _, _ := crypto.ComputeKeyRingHMAC(data, ring)
			_ = u.deviceRepo.UpdateHash(ctx, matchedDevice.ID, newHash)
		}
		return matchedDevice.ID, nil
	}

	currentHash, _, err := crypto.ComputeKeyRingHMAC(data, ring)
	if err != nil {
		return uuid.Nil, err
	}

	newDev := &device.Device{
		ID:                   uuid.New(),
		UserID:               userID,
		DeviceIdentifierHash: currentHash,
		Platform:             platform,
		CreatedAt:            now,
		LastSeenAt:           now,
		LastAppVersion:       appVersion,
		RevokedAt:            nil,
	}

	if err := u.deviceRepo.Create(ctx, newDev); err != nil {
		return uuid.Nil, err
	}

	return newDev.ID, nil
}
