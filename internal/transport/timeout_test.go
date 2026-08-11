package transport

import (
	"net"
	"testing"
	"time"
)

func TestConnection_ReadDeadlineTimeout(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	conn := NewConnection(server)
	_ = conn.SetReadDeadline(time.Now().Add(50 * time.Millisecond))

	_, err := conn.ReadFrame()
	if err == nil {
		t.Fatal("expected read timeout error, got nil")
	}

	netErr, ok := err.(net.Error)
	if !ok || !netErr.Timeout() {
		t.Fatalf("expected net.Error with Timeout() == true, got %v", err)
	}
}
