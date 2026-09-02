package ws

import (
	"context"
	"testing"
	"time"

	flatbuffers "github.com/google/flatbuffers/go"

	"airlance.org/api/internal/config"
	fbWS "airlance.org/api/internal/transport/ws/airlance/ws"
)

func TestRouter_PingPong(t *testing.T) {
	router := NewRouter(1, 1)

	b := flatbuffers.NewBuilder(128)
	fbWS.PingStart(b)
	fbWS.PingAddTimestamp(b, uint64(time.Now().UnixMilli()))
	pingOffset := fbWS.PingEnd(b)

	fbWS.EnvelopeStart(b)
	fbWS.EnvelopeAddProtocolVersion(b, 1)
	fbWS.EnvelopeAddMessageId(b, 42)
	fbWS.EnvelopeAddPayloadType(b, fbWS.PayloadPing)
	fbWS.EnvelopeAddPayload(b, pingOffset)
	envOffset := fbWS.EnvelopeEnd(b)
	b.Finish(envOffset)

	packet := b.FinishedBytes()

	s := &Session{
		send:              make(chan []byte, 10),
		serverToClientKey: make([]byte, 32),
		cfg:               &config.Config{CurrentProtocol: 1},
	}

	err := router.Dispatch(context.Background(), s, packet)
	if err != nil {
		t.Fatalf("unexpected dispatch error: %v", err)
	}

	if len(s.send) != 1 {
		t.Errorf("expected 1 response packet in send queue, got %d", len(s.send))
	}
}

func TestRouter_UnsupportedProtocol(t *testing.T) {
	router := NewRouter(2, 2) // Min protocol is 2

	b := flatbuffers.NewBuilder(128)
	fbWS.EmptyStart(b)
	emptyOffset := fbWS.EmptyEnd(b)

	fbWS.EnvelopeStart(b)
	fbWS.EnvelopeAddProtocolVersion(b, 1) // Client is on protocol 1
	fbWS.EnvelopeAddMessageId(b, 1)
	fbWS.EnvelopeAddPayloadType(b, fbWS.PayloadEmpty)
	fbWS.EnvelopeAddPayload(b, emptyOffset)
	envOffset := fbWS.EnvelopeEnd(b)
	b.Finish(envOffset)

	packet := b.FinishedBytes()

	s := &Session{
		send:              make(chan []byte, 10),
		serverToClientKey: make([]byte, 32),
		cfg:               &config.Config{CurrentProtocol: 2},
		cancel:            func() {},
	}

	err := router.Dispatch(context.Background(), s, packet)
	if err != ErrUnsupportedProtocol {
		t.Errorf("expected ErrUnsupportedProtocol, got %v", err)
	}
}
