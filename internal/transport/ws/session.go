package ws

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/resoul/wireauth/v2"

	"airlance.org/api/internal/config"
	"airlance.org/api/internal/infrastructure/logger"
	fbWS "airlance.org/api/internal/transport/ws/airlance/ws"
)

var (
	ErrSendQueueFull    = errors.New("ws: send queue full, slow consumer")
	ErrSequenceMismatch = errors.New("ws: sequence counter mismatch or replay")
)

type Session struct {
	UserID    uuid.UUID
	SessionID uuid.UUID
	DeviceID  *uuid.UUID
	ClientIP  string

	conn              *websocket.Conn
	clientToServerKey []byte
	serverToClientKey []byte

	inSeq     uint64
	outSeq    uint64
	nextMsgID uint64

	send     chan []byte
	ctx      context.Context
	cancel   context.CancelFunc
	registry ConnectionRegistry
	router   *Router
	cfg      *config.Config
	log      *logger.Logger

	closeOnce sync.Once
}

func NewSession(
	parentCtx context.Context,
	conn *websocket.Conn,
	userID, sessionID uuid.UUID,
	deviceID *uuid.UUID,
	clientIP string,
	c2sKey, s2cKey []byte,
	registry ConnectionRegistry,
	router *Router,
	cfg *config.Config,
	log *logger.Logger,
) *Session {
	ctx, cancel := context.WithCancel(parentCtx)
	sendCap := cfg.MaxWSSendQueue
	if sendCap <= 0 {
		sendCap = 256
	}

	return &Session{
		UserID:            userID,
		SessionID:         sessionID,
		DeviceID:          deviceID,
		ClientIP:          clientIP,
		conn:              conn,
		clientToServerKey: c2sKey,
		serverToClientKey: s2cKey,
		send:              make(chan []byte, sendCap),
		ctx:               ctx,
		cancel:            cancel,
		registry:          registry,
		router:            router,
		cfg:               cfg,
		log:               log.Named(logger.CategoryWS),
	}
}

func (s *Session) NextMessageID() uint64 {
	return atomic.AddUint64(&s.nextMsgID, 1)
}

func (s *Session) Send(envelopeBytes []byte) error {
	seq := atomic.AddUint64(&s.outSeq, 1)
	encryptedPacket, err := wireauth.EncryptAESGCM(s.serverToClientKey, envelopeBytes, seq)
	if err != nil {
		return fmt.Errorf("ws session: encrypt error: %w", err)
	}

	select {
	case s.send <- encryptedPacket:
		return nil
	default:
		s.log.Warn("Disconnecting slow consumer due to full send queue", "user_id", s.UserID.String(), "session_id", s.SessionID.String())
		s.Close("slow_consumer")
		return ErrSendQueueFull
	}
}

func (s *Session) SendError(corrID uint64, code fbWS.ErrorCode, msg string, retryable bool, retryAfterMs uint32) error {
	envelopeBytes := BuildErrorEnvelope(s.cfg.CurrentProtocol, s.NextMessageID(), corrID, code, msg, retryable, retryAfterMs)
	return s.Send(envelopeBytes)
}

func (s *Session) StartLifecycle() {
	defer s.registry.Remove(s)
	defer s.Close("lifecycle_terminated")

	go s.writeLoop()
	s.readLoop()
}

func (s *Session) readLoop() {
	defer s.cancel()

	idleTimeout := s.cfg.WSIdleTimeout
	if idleTimeout <= 0 {
		idleTimeout = 60 * time.Second
	}

	s.conn.SetReadLimit(s.cfg.MaxWSFrameBytes)
	_ = s.conn.SetReadDeadline(time.Now().Add(idleTimeout))

	s.conn.SetPongHandler(func(string) error {
		_ = s.conn.SetReadDeadline(time.Now().Add(idleTimeout))
		return nil
	})

	for {
		msgType, packet, err := s.conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseNormalClosure) {
				s.log.Debug("WS read error", "err", err)
			}
			break
		}

		if msgType != websocket.BinaryMessage {
			s.log.Warn("Rejecting non-binary WebSocket message", "type", msgType)
			break
		}

		_ = s.conn.SetReadDeadline(time.Now().Add(idleTimeout))

		plaintext, err := s.decryptAndValidatePacket(packet)
		if err != nil {
			s.log.Warn("Frame processing failed", "err", err)
			break
		}

		if err := s.router.Dispatch(s.ctx, s, plaintext); err != nil {
			if errors.Is(err, ErrUnsupportedProtocol) {
				break
			}
			s.log.Debug("Handler error", "err", err)
		}
	}
}

func (s *Session) writeLoop() {
	idleInterval := s.cfg.WSIdleTimeout / 2
	if idleInterval <= 0 {
		idleInterval = 30 * time.Second
	}
	writeTimeout := s.cfg.HTTPWriteTimeout
	if writeTimeout <= 0 {
		writeTimeout = 5 * time.Second
	}

	ticker := time.NewTicker(idleInterval)
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			return
		case packet, ok := <-s.send:
			if !ok {
				return
			}
			_ = s.conn.SetWriteDeadline(time.Now().Add(writeTimeout))
			if err := s.conn.WriteMessage(websocket.BinaryMessage, packet); err != nil {
				return
			}
		case <-ticker.C:
			_ = s.conn.SetWriteDeadline(time.Now().Add(writeTimeout))
			if err := s.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

func (s *Session) Close(reason string) {
	s.closeOnce.Do(func() {
		if s.cancel != nil {
			s.cancel()
		}
		if s.conn != nil {
			_ = s.conn.WriteControl(
				websocket.CloseMessage,
				websocket.FormatCloseMessage(websocket.CloseNormalClosure, reason),
				time.Now().Add(1*time.Second),
			)
			_ = s.conn.Close()
		}
	})
}

// ValidateSequence checks that the incoming sequence counter matches expectedSeq exactly.
// Any replay or out-of-order sequence counter fails with ErrSequenceMismatch.
func ValidateSequence(expectedSeq, actualSeq uint64) error {
	if actualSeq != expectedSeq {
		return ErrSequenceMismatch
	}
	return nil
}

func (s *Session) decryptAndValidatePacket(packet []byte) ([]byte, error) {
	plaintext, seq, err := wireauth.DecryptAESGCM(s.clientToServerKey, packet)
	if err != nil {
		return nil, fmt.Errorf("decrypt error: %w", err)
	}

	expectedSeq := atomic.AddUint64(&s.inSeq, 1)
	if err := ValidateSequence(expectedSeq, seq); err != nil {
		return nil, fmt.Errorf("%w: expected %d, actual %d", err, expectedSeq, seq)
	}

	return plaintext, nil
}
