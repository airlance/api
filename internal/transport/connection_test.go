package transport

import (
	"bytes"
	"net"
	"testing"
)

func TestConnection_ReadWriteFrame_RoundtripOverPipe(t *testing.T) {
	clientRaw, serverRaw := net.Pipe()
	defer clientRaw.Close()
	defer serverRaw.Close()

	client := NewConnection(clientRaw)
	server := NewConnection(serverRaw)

	payload := []byte("ping over net.Pipe")

	writeErr := make(chan error, 1)
	go func() {
		writeErr <- client.WriteFrame(payload)
	}()

	got, err := server.ReadFrame()
	if err != nil {
		t.Fatalf("server.ReadFrame failed: %v", err)
	}
	if err := <-writeErr; err != nil {
		t.Fatalf("client.WriteFrame failed: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload mismatch: got %q, want %q", got, payload)
	}
}

func TestConnection_ReadFrame_ReturnsErrorAfterClose(t *testing.T) {
	clientRaw, serverRaw := net.Pipe()
	client := NewConnection(clientRaw)
	server := NewConnection(serverRaw)

	if err := client.Close(); err != nil {
		t.Fatalf("client.Close failed: %v", err)
	}

	if _, err := server.ReadFrame(); err == nil {
		t.Fatal("expected error reading from closed connection, got nil")
	}
}
