package mailer

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	stdmail "net/mail"
	"net/smtp"
	"strings"
	"time"

	"airlance.org/api/internal/config"
	domain "airlance.org/api/internal/domain/mailer"
)

// SMTPClient delivers plaintext messages through an SMTP server.
type SMTPClient struct {
	host     string
	address  string
	from     string
	username string
	password string
	startTLS bool
	timeout  time.Duration
	dialer   net.Dialer
}

// NewSMTPClient builds an SMTP client from validated application configuration.
func NewSMTPClient(cfg *config.Config) (*SMTPClient, error) {
	if cfg == nil {
		return nil, errors.New("mailer: config is required")
	}
	if !cfg.SMTPEnabled {
		return nil, errors.New("mailer: SMTP is disabled")
	}
	from, err := stdmail.ParseAddress(cfg.SMTPFrom)
	if cfg.SMTPHost == "" || err != nil || from.Address != cfg.SMTPFrom || cfg.SMTPPort < 1 || cfg.SMTPPort > 65535 || cfg.SMTPTimeout <= 0 {
		return nil, errors.New("mailer: invalid SMTP configuration")
	}
	if (cfg.SMTPUsername == "") != (cfg.SMTPPassword == "") {
		return nil, errors.New("mailer: incomplete SMTP credentials")
	}
	if cfg.Env != "development" && cfg.Env != "test" && !cfg.SMTPStartTLS {
		return nil, errors.New("mailer: SMTP STARTTLS is required outside development/test")
	}
	return &SMTPClient{
		host:     cfg.SMTPHost,
		address:  net.JoinHostPort(cfg.SMTPHost, fmt.Sprintf("%d", cfg.SMTPPort)),
		from:     cfg.SMTPFrom,
		username: cfg.SMTPUsername,
		password: cfg.SMTPPassword,
		startTLS: cfg.SMTPStartTLS,
		timeout:  cfg.SMTPTimeout,
	}, nil
}

// Send validates and delivers one message. It never includes the recipient or body in returned errors.
func (c *SMTPClient) Send(ctx context.Context, message domain.Message) error {
	if err := message.Validate(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("mailer: send cancelled: %w", err)
	}

	sendCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	conn, err := c.dialer.DialContext(sendCtx, "tcp", c.address)
	if err != nil {
		return fmt.Errorf("mailer: SMTP dial failed: %w", err)
	}
	defer func() { _ = conn.Close() }()
	if deadline, ok := sendCtx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			return fmt.Errorf("mailer: set SMTP deadline failed: %w", err)
		}
	}

	client, err := smtp.NewClient(conn, c.host)
	if err != nil {
		return fmt.Errorf("mailer: SMTP client failed: %w", err)
	}
	defer func() { _ = client.Quit() }()

	if c.startTLS {
		hasStartTLS, _ := client.Extension("STARTTLS")
		if !hasStartTLS {
			return errors.New("mailer: SMTP server does not support STARTTLS")
		}
		if err := client.StartTLS(&tls.Config{MinVersion: tls.VersionTLS12, ServerName: c.host}); err != nil {
			return fmt.Errorf("mailer: SMTP STARTTLS failed: %w", err)
		}
	}
	if c.username != "" {
		if err := client.Auth(smtp.PlainAuth("", c.username, c.password, c.host)); err != nil {
			return fmt.Errorf("mailer: SMTP authentication failed: %w", err)
		}
	}
	if err := client.Mail(c.from); err != nil {
		return fmt.Errorf("mailer: SMTP sender rejected: %w", err)
	}
	if err := client.Rcpt(message.To); err != nil {
		return fmt.Errorf("mailer: SMTP recipient rejected: %w", err)
	}
	writer, err := client.Data()
	if err != nil {
		return fmt.Errorf("mailer: SMTP data failed: %w", err)
	}
	if _, err := io.WriteString(writer, renderMessage(c.from, message)); err != nil {
		_ = writer.Close()
		return fmt.Errorf("mailer: SMTP write failed: %w", err)
	}
	if err := writer.Close(); err != nil {
		return fmt.Errorf("mailer: SMTP data close failed: %w", err)
	}
	return nil
}

func renderMessage(from string, message domain.Message) string {
	body := strings.ReplaceAll(message.Text, "\n", "\r\n")
	body = strings.ReplaceAll(body, "\r\r\n", "\r\n")
	return "From: " + from + "\r\n" +
		"To: " + message.To + "\r\n" +
		"Subject: " + message.Subject + "\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: text/plain; charset=UTF-8\r\n" +
		"\r\n" + body
}
