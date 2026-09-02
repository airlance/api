package ws

import (
	"context"
	"testing"
	"time"

	flatbuffers "github.com/google/flatbuffers/go"

	"airlance.org/api/internal/config"
	fbWS "airlance.org/api/internal/transport/ws/airlance/ws"
)

func buildTestRequestEnvelope(b *flatbuffers.Builder, protocol uint32, msgID uint64, payloadType fbWS.Payload, payloadOffset flatbuffers.UOffsetT) []byte {
	fbWS.EnvelopeStart(b)
	fbWS.EnvelopeAddProtocolVersion(b, protocol)
	fbWS.EnvelopeAddMessageId(b, msgID)
	fbWS.EnvelopeAddPayloadType(b, payloadType)
	fbWS.EnvelopeAddPayload(b, payloadOffset)
	envOffset := fbWS.EnvelopeEnd(b)
	b.Finish(envOffset)
	return b.FinishedBytes()
}

func TestRouter_PingPong(t *testing.T) {
	router := NewRouter(1, 1)

	b := flatbuffers.NewBuilder(128)
	fbWS.PingStart(b)
	fbWS.PingAddTimestamp(b, uint64(time.Now().UnixMilli()))
	pingOffset := fbWS.PingEnd(b)

	packet := buildTestRequestEnvelope(b, 1, 42, fbWS.PayloadPing, pingOffset)

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

	packet := buildTestRequestEnvelope(b, 1, 1, fbWS.PayloadEmpty, emptyOffset)

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
