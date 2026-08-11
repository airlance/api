package email

import (
	"context"
	"fmt"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/airlance/api/internal/domain/device"
	"github.com/airlance/api/internal/infrastructure/logger"
)

type SMTPNewDeviceNotifier struct {
	client *SMTPClient
}

var _ device.NewDeviceNotifier = (*SMTPNewDeviceNotifier)(nil)

func NewSMTPNewDeviceNotifier(client *SMTPClient) *SMTPNewDeviceNotifier {
	return &SMTPNewDeviceNotifier{client: client}
}

func (n *SMTPNewDeviceNotifier) NotifyNewDevice(ctx context.Context, toEmail string, dev device.Device) error {
	subject := "Airlance Security Alert: New Device Signed In"

	deviceName := dev.DeviceName
	if deviceName == "" {
		deviceName = "Unknown Device"
	}

	platform := dev.Platform
	if platform == "" {
		platform = "Unknown Platform"
	}

	timeStr := time.Now().Format(time.RFC1123)

	body := fmt.Sprintf(
		"Hello,\n\nA new device has just signed in to your Airlance account.\n\n"+
			"Device Name: %s\n"+
			"Platform: %s\n"+
			"OS Version: %s\n"+
			"App Version: %s\n"+
			"Time: %s\n\n"+
			"If this was you, you can safely ignore this email.\n"+
			"If you did not perform this action, please revoke this session immediately in your account security settings.\n\n"+
			"Best regards,\nAirlance Security Team",
		deviceName, platform, dev.OSVersion, dev.AppVersion, timeStr,
	)

	if n.client == nil || n.client.Config().Host == "" {
		logger.FromContext(ctx).WithFields(logrus.Fields{
			"to_email":    toEmail,
			"device_name": deviceName,
			"platform":    platform,
		}).Info("[DEV NOTIFIER] new device email notification logged")
		return nil
	}

	if err := n.client.SendMail(ctx, toEmail, subject, body); err != nil {
		logger.FromContext(ctx).WithField("error", err).Warn("failed to send new device email notification")
		return err
	}

	return nil
}
