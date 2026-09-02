package ws

import (
	"context"
	"errors"
	"fmt"
	"time"

	flatbuffers "github.com/google/flatbuffers/go"

	fbWS "airlance.org/api/internal/transport/ws/airlance/ws"
)

var (
	ErrUnsupportedProtocol = errors.New("ws: unsupported protocol version")
)

type Handler func(ctx context.Context, s *Session, env *fbWS.Envelope) error

type Router struct {
	handlers             map[fbWS.Payload]Handler
	minSupportedProtocol uint32
	currentProtocol      uint32
}

func NewRouter(minProtocol, currentProtocol uint32) *Router {
	r := &Router{
		handlers:             make(map[fbWS.Payload]Handler),
		minSupportedProtocol: minProtocol,
		currentProtocol:      currentProtocol,
	}

	r.Register(fbWS.PayloadPing, r.handlePing)
	r.Register(fbWS.PayloadTestEcho, r.handleTestEcho)

	return r
}

func (r *Router) Register(payloadType fbWS.Payload, handler Handler) {
	r.handlers[payloadType] = handler
}

func (r *Router) Dispatch(ctx context.Context, s *Session, rawEnvelope []byte) error {
	if len(rawEnvelope) < 4 {
		return errors.New("ws: invalid envelope length")
	}

	env := fbWS.GetRootAsEnvelope(rawEnvelope, 0)
	clientProto := env.ClientVersion()
	if clientProto == 0 {
		clientProto = env.ProtocolVersion()
	}

	if clientProto < r.minSupportedProtocol {
		_ = s.SendError(env.MessageId(), fbWS.ErrorCodeUNSUPPORTED_PROTOCOL, "Protocol version no longer supported", false, 0)
		s.Close("unsupported_protocol_version")
		return ErrUnsupportedProtocol
	}

	handler, ok := r.handlers[env.PayloadType()]
	if !ok {
		return s.SendError(env.MessageId(), fbWS.ErrorCodeINVALID_REQUEST, fmt.Sprintf("unhandled payload type %d", env.PayloadType()), false, 0)
	}

	return handler(ctx, s, env)
}

func (r *Router) handlePing(ctx context.Context, s *Session, env *fbWS.Envelope) error {
	var ping fbWS.Ping
	table := new(flatbuffers.Table)
	if env.Payload(table) {
		ping.Init(table.Bytes, table.Pos)
	}

	b := flatbuffers.NewBuilder(128)
	fbWS.PongStart(b)
	fbWS.PongAddTimestamp(b, uint64(time.Now().UnixMilli()))
	pongOffset := fbWS.PongEnd(b)

	fbWS.EnvelopeStart(b)
	fbWS.EnvelopeAddProtocolVersion(b, r.currentProtocol)
	fbWS.EnvelopeAddMessageId(b, s.NextMessageID())
	fbWS.EnvelopeAddCorrelationId(b, env.MessageId())
	fbWS.EnvelopeAddPayloadType(b, fbWS.PayloadPong)
	fbWS.EnvelopeAddPayload(b, pongOffset)
	envOffset := fbWS.EnvelopeEnd(b)

	b.Finish(envOffset)
	return s.Send(b.FinishedBytes())
}

func (r *Router) handleTestEcho(ctx context.Context, s *Session, env *fbWS.Envelope) error {
	var echo fbWS.TestEcho
	table := new(flatbuffers.Table)
	var dataStr string
	if env.Payload(table) {
		echo.Init(table.Bytes, table.Pos)
		dataStr = string(echo.Data())
	}

	b := flatbuffers.NewBuilder(256)
	dataOffset := b.CreateString(dataStr)
	fbWS.TestEchoStart(b)
	fbWS.TestEchoAddData(b, dataOffset)
	echoOffset := fbWS.TestEchoEnd(b)

	fbWS.EnvelopeStart(b)
	fbWS.EnvelopeAddProtocolVersion(b, r.currentProtocol)
	fbWS.EnvelopeAddMessageId(b, s.NextMessageID())
	fbWS.EnvelopeAddCorrelationId(b, env.MessageId())
	fbWS.EnvelopeAddPayloadType(b, fbWS.PayloadTestEcho)
	fbWS.EnvelopeAddPayload(b, echoOffset)
	envOffset := fbWS.EnvelopeEnd(b)

	b.Finish(envOffset)
	return s.Send(b.FinishedBytes())
}

func BuildErrorEnvelope(currentProtocol uint32, msgID, corrID uint64, code fbWS.ErrorCode, msg string, retryable bool, retryAfterMs uint32) []byte {
	b := flatbuffers.NewBuilder(256)
	msgOffset := b.CreateString(msg)

	fbWS.ErrorStart(b)
	fbWS.ErrorAddCode(b, code)
	fbWS.ErrorAddMessage(b, msgOffset)
	fbWS.ErrorAddRetryable(b, retryable)
	fbWS.ErrorAddRetryAfterMs(b, retryAfterMs)
	errOffset := fbWS.ErrorEnd(b)

	fbWS.EnvelopeStart(b)
	fbWS.EnvelopeAddProtocolVersion(b, currentProtocol)
	fbWS.EnvelopeAddMessageId(b, msgID)
	fbWS.EnvelopeAddCorrelationId(b, corrID)
	fbWS.EnvelopeAddPayloadType(b, fbWS.PayloadError)
	fbWS.EnvelopeAddPayload(b, errOffset)
	envOffset := fbWS.EnvelopeEnd(b)

	b.Finish(envOffset)
	return b.FinishedBytes()
}
