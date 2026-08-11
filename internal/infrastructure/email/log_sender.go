package email

import (
	"context"

	"github.com/airlance/api/internal/domain/account"
	"github.com/airlance/api/internal/infrastructure/logger"
	"github.com/sirupsen/logrus"
)

type LogEmailSender struct{}

var _ account.EmailSender = (*LogEmailSender)(nil)

func NewLogEmailSender() *LogEmailSender {
	return &LogEmailSender{}
}

func (s *LogEmailSender) SendConfirmationCode(ctx context.Context, toEmail, code string) error {
	logger.FromContext(ctx).WithFields(logrus.Fields{
		"to_email": toEmail,
		"code":     code,
	}).Info("[DEV EMAIL SENDER] confirmation code sent")
	return nil
}
