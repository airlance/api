package mailer

import (
	"bufio"
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"airlance.org/api/internal/config"
	domain "airlance.org/api/internal/domain/mailer"
)

func TestNewSMTPClient(t *testing.T) {
	client, err := NewSMTPClient(&config.Config{
		Env:         "test",
		SMTPEnabled: true,
		SMTPHost:    "smtp.example.test",
		SMTPPort:    587,
		SMTPFrom:    "no-reply@example.test",
		SMTPTimeout: 1,
	})
	if err != nil {
		t.Fatalf("NewSMTPClient() error = %v", err)
	}
	if client.address != "smtp.example.test:587" {
		t.Fatalf("address = %q", client.address)
	}
}

func TestRenderMessageUsesCRLFHeaders(t *testing.T) {
	raw := renderMessage("no-reply@example.test", domain.Message{To: "person@example.test", Subject: "Code", Text: "123456\nsecond line"})
	if !strings.Contains(raw, "Subject: Code\r\n") || !strings.Contains(raw, "\r\n\r\n123456\r\nsecond line") {
		t.Fatalf("unexpected RFC 5322 message: %q", raw)
	}
}

func TestSMTPClientSend(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = listener.Close() }()

	messageData := make(chan string, 1)
	serverErr := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer func() { _ = conn.Close() }()
		reader := bufio.NewReader(conn)
		writer := bufio.NewWriter(conn)
		defer func() { _ = writer.Flush() }()

		if _, err := writer.WriteString("220 test SMTP\r\n"); err != nil {
			serverErr <- err
			return
		}
		if err := writer.Flush(); err != nil {
			serverErr <- err
			return
		}
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				serverErr <- err
				return
			}
			switch {
			case strings.HasPrefix(line, "EHLO "):
				_, err = writer.WriteString("250 test SMTP\r\n")
			case strings.HasPrefix(line, "MAIL FROM:"), strings.HasPrefix(line, "RCPT TO:"):
				_, err = writer.WriteString("250 accepted\r\n")
			case line == "DATA\r\n":
				if _, err = writer.WriteString("354 end with <CRLF>.<CRLF>\r\n"); err == nil {
					err = writer.Flush()
				}
				if err != nil {
					serverErr <- err
					return
				}
				var body strings.Builder
				for {
					dataLine, readErr := reader.ReadString('\n')
					if readErr != nil {
						serverErr <- readErr
						return
					}
					if dataLine == ".\r\n" {
						break
					}
					body.WriteString(dataLine)
				}
				messageData <- body.String()
				_, err = writer.WriteString("250 queued\r\n")
			case line == "QUIT\r\n":
				_, err = writer.WriteString("221 bye\r\n")
			default:
				err = nil
			}
			if err != nil {
				serverErr <- err
				return
			}
			if err := writer.Flush(); err != nil {
				serverErr <- err
				return
			}
			if line == "QUIT\r\n" {
				serverErr <- nil
				return
			}
		}
	}()

	host, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatalf("split listener address: %v", err)
	}
	client, err := NewSMTPClient(&config.Config{
		Env:         "test",
		SMTPEnabled: true,
		SMTPHost:    host,
		SMTPPort:    mustPort(t, port),
		SMTPFrom:    "no-reply@example.test",
		SMTPTimeout: time.Second,
	})
	if err != nil {
		t.Fatalf("NewSMTPClient() error = %v", err)
	}
	if err := client.Send(context.Background(), domain.Message{To: "person@example.test", Subject: "Your code", Text: "123456"}); err != nil {
		t.Fatalf("Send() error = %v", err)
	}
	select {
	case err := <-serverErr:
		if err != nil {
			t.Fatalf("SMTP server error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("SMTP server did not finish")
	}
	select {
	case body := <-messageData:
		if !strings.Contains(body, "Subject: Your code\r\n") || !strings.Contains(body, "\r\n123456") {
			t.Fatalf("unexpected delivered message: %q", body)
		}
	default:
		t.Fatal("SMTP server did not receive message data")
	}
}

func mustPort(t *testing.T, raw string) int {
	t.Helper()
	addr, err := net.ResolveTCPAddr("tcp", net.JoinHostPort("127.0.0.1", raw))
	if err != nil {
		t.Fatalf("resolve port: %v", err)
	}
	return addr.Port
}
