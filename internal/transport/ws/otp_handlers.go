package ws

import (
	"context"
	"errors"
	"time"

	flatbuffers "github.com/google/flatbuffers/go"
	"github.com/google/uuid"

	"airlance.org/api/internal/domain/otp"
	"airlance.org/api/internal/domain/ratelimit"
	fbWS "airlance.org/api/internal/transport/ws/airlance/ws"
)

func (r *Router) handleOTPLinkEmailRequest(ctx context.Context, s *Session, env *fbWS.Envelope) error {
	if r.authUC == nil {
		return s.SendError(env.MessageId(), fbWS.ErrorCodeINTERNAL, "auth service unavailable", false, 0)
	}

	var req fbWS.OtpLinkEmailRequest
	table := new(flatbuffers.Table)
	if !env.Payload(table) {
		return s.SendError(env.MessageId(), fbWS.ErrorCodeINVALID_REQUEST, "missing payload", false, 0)
	}
	req.Init(table.Bytes, table.Pos)
	email := string(req.Email())

	result, err := r.authUC.RequestLinkEmail(ctx, s.UserID, email, s.ClientIP)
	if err != nil {
		return sendOTPError(s, env.MessageId(), err)
	}

	b := flatbuffers.NewBuilder(128)
	idOffset := b.CreateString(result.RequestID.String())
	fbWS.OtpLinkEmailAckStart(b)
	fbWS.OtpLinkEmailAckAddRequestId(b, idOffset)
	fbWS.OtpLinkEmailAckAddExpiresAtMs(b, uint64(result.ExpiresAt.UnixMilli()))
	ackOffset := fbWS.OtpLinkEmailAckEnd(b)

	return s.Send(buildResponseEnvelope(b, r.currentProtocol, s.NextMessageID(), env.MessageId(), fbWS.PayloadOtpLinkEmailAck, ackOffset))
}

func (r *Router) handleOTPLinkEmailVerify(ctx context.Context, s *Session, env *fbWS.Envelope) error {
	if r.authUC == nil {
		return s.SendError(env.MessageId(), fbWS.ErrorCodeINTERNAL, "auth service unavailable", false, 0)
	}

	var req fbWS.OtpLinkEmailVerify
	table := new(flatbuffers.Table)
	if !env.Payload(table) {
		return s.SendError(env.MessageId(), fbWS.ErrorCodeINVALID_REQUEST, "missing payload", false, 0)
	}
	req.Init(table.Bytes, table.Pos)

	requestID, err := uuid.Parse(string(req.RequestId()))
	if err != nil {
		return s.SendError(env.MessageId(), fbWS.ErrorCodeINVALID_REQUEST, "invalid request_id", false, 0)
	}

	ident, err := r.authUC.VerifyLinkEmail(ctx, s.UserID, requestID, string(req.Code()), s.ClientIP)
	if err != nil {
		return sendOTPError(s, env.MessageId(), err)
	}

	b := flatbuffers.NewBuilder(128)
	idOffset := b.CreateString(ident.ID.String())
	emailOffset := b.CreateString(ident.Identifier)
	fbWS.OtpLinkEmailVerifiedStart(b)
	fbWS.OtpLinkEmailVerifiedAddIdentityId(b, idOffset)
	fbWS.OtpLinkEmailVerifiedAddEmail(b, emailOffset)
	fbWS.OtpLinkEmailVerifiedAddLinkedAtMs(b, uint64(time.Now().UnixMilli()))
	verifiedOffset := fbWS.OtpLinkEmailVerifiedEnd(b)

	return s.Send(buildResponseEnvelope(b, r.currentProtocol, s.NextMessageID(), env.MessageId(), fbWS.PayloadOtpLinkEmailVerified, verifiedOffset))
}

func sendOTPError(s *Session, corrID uint64, err error) error {
	switch {
	case errors.Is(err, ratelimit.ErrRateLimitExceeded):
		return s.SendError(corrID, fbWS.ErrorCodeRATE_LIMITED, "too many attempts, try later", true, 60000)
	case errors.Is(err, otp.ErrAlreadyLinked):
		return s.SendError(corrID, fbWS.ErrorCodeCONFLICT, "email already linked to another account", false, 0)
	case errors.Is(err, otp.ErrExpired), errors.Is(err, otp.ErrNotFound):
		return s.SendError(corrID, fbWS.ErrorCodeNOT_FOUND, "code expired or not found", false, 0)
	case errors.Is(err, otp.ErrTooManyAttempts):
		return s.SendError(corrID, fbWS.ErrorCodeRATE_LIMITED, "too many attempts", false, 0)
	case errors.Is(err, otp.ErrInvalidCode):
		return s.SendError(corrID, fbWS.ErrorCodeINVALID_REQUEST, "invalid code", false, 0)
	default:
		return s.SendError(corrID, fbWS.ErrorCodeINTERNAL, "internal error", false, 0)
	}
}
