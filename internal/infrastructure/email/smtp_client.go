package email

import (
	"context"
	"fmt"
	"net/smtp"

	"github.com/airlance/api/internal/config"
)

type SMTPClient struct {
	cfg config.SMTP
}

func NewSMTPClient(cfg config.SMTP) *SMTPClient {
	return &SMTPClient{cfg: cfg}
}

func (c *SMTPClient) Config() config.SMTP {
	return c.cfg
}

func (c *SMTPClient) SendMail(ctx context.Context, toEmail, subject, body string) error {
	if c.cfg.Host == "" {
		return fmt.Errorf("smtp: host not configured")
	}

	addr := fmt.Sprintf("%s:%d", c.cfg.Host, c.cfg.Port)

	var auth smtp.Auth
	if c.cfg.Username != "" {
		auth = smtp.PlainAuth("", c.cfg.Username, c.cfg.Password, c.cfg.Host)
	}

	msg := []byte(fmt.Sprintf("From: %s\r\n"+
		"To: %s\r\n"+
		"Subject: %s\r\n"+
		"Content-Type: text/plain; charset=UTF-8\r\n"+
		"\r\n"+
		"%s\r\n", c.cfg.From, toEmail, subject, body))

	if err := smtp.SendMail(addr, auth, c.cfg.From, []string{toEmail}, msg); err != nil {
		return fmt.Errorf("smtp: send mail failed: %w", err)
	}

	return nil
}
