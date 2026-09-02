package ws

import (
	"context"
	"fmt"
	"testing"
	"time"

	flatbuffers "github.com/google/flatbuffers/go"
	"github.com/google/uuid"
	"github.com/resoul/wireauth/v2"

	"airlance.org/api/internal/config"
	"airlance.org/api/internal/domain/crypto"
	"airlance.org/api/internal/domain/identity"
	"airlance.org/api/internal/domain/session"
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

func decryptTestResponse(t *testing.T, s *Session) *fbWS.Envelope {
	t.Helper()
	select {
	case packet := <-s.send:
		plaintext, _, err := wireauth.DecryptAESGCM(s.serverToClientKey, packet)
		if err != nil {
			t.Fatalf("failed to decrypt response packet: %v", err)
		}
		return fbWS.GetRootAsEnvelope(plaintext, 0)
	default:
		t.Fatalf("no packet received in send queue")
		return nil
	}
}

func newTestSession(userID, sessionID uuid.UUID) (*Session, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	s := &Session{
		UserID:            userID,
		SessionID:         sessionID,
		ClientIP:          "127.0.0.1",
		send:              make(chan []byte, 10),
		serverToClientKey: make([]byte, 32),
		cfg:               &config.Config{CurrentProtocol: 2},
		ctx:               ctx,
		cancel:            cancel,
	}
	return s, cancel
}

func TestRouter_PingPong(t *testing.T) {
	router := NewRouter(1, 1, nil, nil)

	b := flatbuffers.NewBuilder(128)
	fbWS.PingStart(b)
	fbWS.PingAddTimestamp(b, uint64(time.Now().UnixMilli()))
	pingOffset := fbWS.PingEnd(b)

	packet := buildTestRequestEnvelope(b, 1, 42, fbWS.PayloadPing, pingOffset)

	s, cancel := newTestSession(uuid.New(), uuid.New())
	defer cancel()
	s.cfg.CurrentProtocol = 1

	err := router.Dispatch(context.Background(), s, packet)
	if err != nil {
		t.Fatalf("unexpected dispatch error: %v", err)
	}

	env := decryptTestResponse(t, s)
	if env.PayloadType() != fbWS.PayloadPong {
		t.Errorf("expected Pong payload type, got %v", env.PayloadType())
	}
}

func TestRouter_UnsupportedProtocol(t *testing.T) {
	router := NewRouter(2, 2, nil, nil)

	b := flatbuffers.NewBuilder(128)
	fbWS.EmptyStart(b)
	emptyOffset := fbWS.EmptyEnd(b)

	packet := buildTestRequestEnvelope(b, 1, 1, fbWS.PayloadEmpty, emptyOffset)

	s, cancel := newTestSession(uuid.New(), uuid.New())
	defer cancel()

	err := router.Dispatch(context.Background(), s, packet)
	if err != ErrUnsupportedProtocol {
		t.Errorf("expected ErrUnsupportedProtocol, got %v", err)
	}
}

func TestRouter_OtpLinkEmail_Flow(t *testing.T) {
	router, _, _, otpRepo, _, identRepo, limiter, keyRing := buildTestRouter(t)

	userID := uuid.New()
	sessionID := uuid.New()
	s, cancel := newTestSession(userID, sessionID)
	defer cancel()

	// 1. Send OtpLinkEmailRequest
	b := flatbuffers.NewBuilder(128)
	emailOffset := b.CreateString("alice@example.com")
	fbWS.OtpLinkEmailRequestStart(b)
	fbWS.OtpLinkEmailRequestAddEmail(b, emailOffset)
	reqOffset := fbWS.OtpLinkEmailRequestEnd(b)

	packet := buildTestRequestEnvelope(b, 2, 100, fbWS.PayloadOtpLinkEmailRequest, reqOffset)
	if err := router.Dispatch(context.Background(), s, packet); err != nil {
		t.Fatalf("dispatch error: %v", err)
	}

	env := decryptTestResponse(t, s)
	if env.PayloadType() != fbWS.PayloadOtpLinkEmailAck {
		t.Fatalf("expected OtpLinkEmailAck payload, got %v", env.PayloadType())
	}
	if env.CorrelationId() != 100 {
		t.Errorf("expected correlation ID 100, got %d", env.CorrelationId())
	}

	var ack fbWS.OtpLinkEmailAck
	table := new(flatbuffers.Table)
	if !env.Payload(table) {
		t.Fatalf("missing ack payload")
	}
	ack.Init(table.Bytes, table.Pos)
	reqIDStr := string(ack.RequestId())
	reqID, err := uuid.Parse(reqIDStr)
	if err != nil {
		t.Fatalf("invalid request_id in ack: %v", err)
	}
	if ack.ExpiresAtMs() == 0 {
		t.Errorf("expected non-zero expires_at_ms")
	}

	// 2. Find the active code
	activeCode, ok := otpRepo.codes[reqID]
	if !ok {
		t.Fatalf("active code not stored in otpRepo")
	}
	var correctCode string
	for c := 0; c < 1000000; c++ {
		testCode := fmt.Sprintf("%06d", c)
		if crypto.VerifyNumericCode(testCode, activeCode.CodeHash, activeCode.KeyID, keyRing) {
			correctCode = testCode
			break
		}
	}
	if correctCode == "" {
		t.Fatalf("could not compute correct numeric code")
	}

	// 3. Verify with wrong code -> returns INVALID_REQUEST error
	b = flatbuffers.NewBuilder(128)
	idOff := b.CreateString(reqIDStr)
	wrongCodeOff := b.CreateString("000000")
	fbWS.OtpLinkEmailVerifyStart(b)
	fbWS.OtpLinkEmailVerifyAddRequestId(b, idOff)
	fbWS.OtpLinkEmailVerifyAddCode(b, wrongCodeOff)
	verifyOff := fbWS.OtpLinkEmailVerifyEnd(b)

	packet = buildTestRequestEnvelope(b, 2, 101, fbWS.PayloadOtpLinkEmailVerify, verifyOff)
	if err := router.Dispatch(context.Background(), s, packet); err != nil {
		t.Fatalf("dispatch error: %v", err)
	}

	env = decryptTestResponse(t, s)
	if env.PayloadType() != fbWS.PayloadError {
		t.Fatalf("expected Error payload, got %v", env.PayloadType())
	}
	var errTable fbWS.Error
	table = new(flatbuffers.Table)
	env.Payload(table)
	errTable.Init(table.Bytes, table.Pos)
	if errTable.Code() != fbWS.ErrorCodeINVALID_REQUEST {
		t.Errorf("expected ErrorCodeINVALID_REQUEST, got %v", errTable.Code())
	}

	// 4. Verify with correct code -> returns OtpLinkEmailVerified
	b = flatbuffers.NewBuilder(128)
	idOff = b.CreateString(reqIDStr)
	codeOff := b.CreateString(correctCode)
	fbWS.OtpLinkEmailVerifyStart(b)
	fbWS.OtpLinkEmailVerifyAddRequestId(b, idOff)
	fbWS.OtpLinkEmailVerifyAddCode(b, codeOff)
	verifyOff = fbWS.OtpLinkEmailVerifyEnd(b)

	packet = buildTestRequestEnvelope(b, 2, 102, fbWS.PayloadOtpLinkEmailVerify, verifyOff)
	if err := router.Dispatch(context.Background(), s, packet); err != nil {
		t.Fatalf("dispatch error: %v", err)
	}

	env = decryptTestResponse(t, s)
	if env.PayloadType() != fbWS.PayloadOtpLinkEmailVerified {
		t.Fatalf("expected OtpLinkEmailVerified payload, got %v", env.PayloadType())
	}
	var verified fbWS.OtpLinkEmailVerified
	table = new(flatbuffers.Table)
	env.Payload(table)
	verified.Init(table.Bytes, table.Pos)
	if string(verified.Email()) != "alice@example.com" {
		t.Errorf("expected email alice@example.com, got %s", string(verified.Email()))
	}
	if _, err := uuid.Parse(string(verified.IdentityId())); err != nil {
		t.Errorf("expected valid identity UUID, got %s", string(verified.IdentityId()))
	}

	// 5. Test Rate Limiting
	limiter.exceeded = true
	b = flatbuffers.NewBuilder(128)
	emailOffset = b.CreateString("bob@example.com")
	fbWS.OtpLinkEmailRequestStart(b)
	fbWS.OtpLinkEmailRequestAddEmail(b, emailOffset)
	reqOffset = fbWS.OtpLinkEmailRequestEnd(b)

	packet = buildTestRequestEnvelope(b, 2, 103, fbWS.PayloadOtpLinkEmailRequest, reqOffset)
	if err := router.Dispatch(context.Background(), s, packet); err != nil {
		t.Fatalf("dispatch error: %v", err)
	}

	env = decryptTestResponse(t, s)
	if env.PayloadType() != fbWS.PayloadError {
		t.Fatalf("expected Error payload for rate limited, got %v", env.PayloadType())
	}
	table = new(flatbuffers.Table)
	env.Payload(table)
	errTable.Init(table.Bytes, table.Pos)
	if errTable.Code() != fbWS.ErrorCodeRATE_LIMITED {
		t.Errorf("expected ErrorCodeRATE_LIMITED, got %v", errTable.Code())
	}
	limiter.exceeded = false

	// 6. Test Already Linked (conflict)
	otherUser := uuid.New()
	_ = identRepo.Create(context.Background(), &identity.Identity{
		ID:         uuid.New(),
		UserID:     otherUser,
		Kind:       identity.KindEmailOTP,
		Identifier: "charlie@example.com",
		Verified:   true,
		CreatedAt:  time.Now(),
	})

	b = flatbuffers.NewBuilder(128)
	emailOffset = b.CreateString("charlie@example.com")
	fbWS.OtpLinkEmailRequestStart(b)
	fbWS.OtpLinkEmailRequestAddEmail(b, emailOffset)
	reqOffset = fbWS.OtpLinkEmailRequestEnd(b)

	packet = buildTestRequestEnvelope(b, 2, 104, fbWS.PayloadOtpLinkEmailRequest, reqOffset)
	if err := router.Dispatch(context.Background(), s, packet); err != nil {
		t.Fatalf("dispatch error: %v", err)
	}

	env = decryptTestResponse(t, s)
	if env.PayloadType() != fbWS.PayloadError {
		t.Fatalf("expected Error payload for conflict, got %v", env.PayloadType())
	}
	table = new(flatbuffers.Table)
	env.Payload(table)
	errTable.Init(table.Bytes, table.Pos)
	if errTable.Code() != fbWS.ErrorCodeCONFLICT {
		t.Errorf("expected ErrorCodeCONFLICT, got %v", errTable.Code())
	}
}

func TestRouter_SessionList(t *testing.T) {
	router, _, _, _, sessionRepo, _, _, _ := buildTestRouter(t)

	userID := uuid.New()
	currentSessionID := uuid.New()
	otherSessionID := uuid.New()

	now := time.Now()
	_ = sessionRepo.Create(context.Background(), &session.Session{
		ID:        currentSessionID,
		UserID:    userID,
		Platform:  "macos",
		CreatedAt: now.Add(-10 * time.Minute),
		ExpiresAt: now.Add(24 * time.Hour),
	})
	_ = sessionRepo.Create(context.Background(), &session.Session{
		ID:        otherSessionID,
		UserID:    userID,
		Platform:  "ios",
		CreatedAt: now.Add(-5 * time.Minute),
		ExpiresAt: now.Add(24 * time.Hour),
	})

	s, cancel := newTestSession(userID, currentSessionID)
	defer cancel()

	b := flatbuffers.NewBuilder(64)
	fbWS.SessionListRequestStart(b)
	reqOff := fbWS.SessionListRequestEnd(b)

	packet := buildTestRequestEnvelope(b, 2, 200, fbWS.PayloadSessionListRequest, reqOff)
	if err := router.Dispatch(context.Background(), s, packet); err != nil {
		t.Fatalf("dispatch error: %v", err)
	}

	env := decryptTestResponse(t, s)
	if env.PayloadType() != fbWS.PayloadSessionListResponse {
		t.Fatalf("expected PayloadSessionListResponse, got %v", env.PayloadType())
	}

	var resp fbWS.SessionListResponse
	table := new(flatbuffers.Table)
	env.Payload(table)
	resp.Init(table.Bytes, table.Pos)

	if resp.SessionsLength() != 2 {
		t.Fatalf("expected 2 sessions, got %d", resp.SessionsLength())
	}

	foundCurrent := false
	for i := 0; i < resp.SessionsLength(); i++ {
		var info fbWS.SessionInfo
		if !resp.Sessions(&info, i) {
			t.Fatalf("failed to read session at %d", i)
		}
		if string(info.SessionId()) == currentSessionID.String() {
			if !info.IsCurrent() {
				t.Errorf("expected current session to have is_current = true")
			}
			foundCurrent = true
		} else if string(info.SessionId()) == otherSessionID.String() {
			if info.IsCurrent() {
				t.Errorf("expected other session to have is_current = false")
			}
		}
	}
	if !foundCurrent {
		t.Errorf("current session was not found in response")
	}
}

func TestRouter_Logout(t *testing.T) {
	router, _, _, _, sessionRepo, _, _, _ := buildTestRouter(t)

	userID := uuid.New()
	sessionID := uuid.New()

	now := time.Now()
	_ = sessionRepo.Create(context.Background(), &session.Session{
		ID:        sessionID,
		UserID:    userID,
		CreatedAt: now,
		ExpiresAt: now.Add(24 * time.Hour),
	})

	s, cancel := newTestSession(userID, sessionID)
	defer cancel()

	b := flatbuffers.NewBuilder(64)
	fbWS.LogoutRequestStart(b)
	reqOff := fbWS.LogoutRequestEnd(b)

	packet := buildTestRequestEnvelope(b, 2, 300, fbWS.PayloadLogoutRequest, reqOff)
	if err := router.Dispatch(context.Background(), s, packet); err != nil {
		t.Fatalf("dispatch error: %v", err)
	}

	env := decryptTestResponse(t, s)
	if env.PayloadType() != fbWS.PayloadLogoutResponse {
		t.Fatalf("expected PayloadLogoutResponse, got %v", env.PayloadType())
	}

	var logoutResp fbWS.LogoutResponse
	table := new(flatbuffers.Table)
	env.Payload(table)
	logoutResp.Init(table.Bytes, table.Pos)

	if string(logoutResp.SessionId()) != sessionID.String() {
		t.Errorf("expected session_id %s, got %s", sessionID.String(), string(logoutResp.SessionId()))
	}

	// Socket was closed -> context is cancelled
	if s.ctx.Err() == nil {
		t.Errorf("expected session context to be cancelled upon logout")
	}

	// Session in repo was revoked
	sess, err := sessionRepo.GetByID(context.Background(), sessionID)
	if err != nil {
		t.Fatalf("failed to fetch session: %v", err)
	}
	if sess.RevokedAt == nil {
		t.Errorf("expected session to be revoked in repository")
	}
}
