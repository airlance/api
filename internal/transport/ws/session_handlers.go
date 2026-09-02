package ws

import (
	"context"

	flatbuffers "github.com/google/flatbuffers/go"
	"github.com/google/uuid"

	fbWS "airlance.org/api/internal/transport/ws/airlance/ws"
)

func deviceIDString(devID *uuid.UUID) string {
	if devID == nil {
		return ""
	}
	return devID.String()
}

func (r *Router) handleSessionList(ctx context.Context, s *Session, env *fbWS.Envelope) error {
	if r.sessionUC == nil {
		return s.SendError(env.MessageId(), fbWS.ErrorCodeINTERNAL, "session service unavailable", false, 0)
	}

	sessions, err := r.sessionUC.ListActiveForUser(ctx, s.UserID)
	if err != nil {
		return s.SendError(env.MessageId(), fbWS.ErrorCodeINTERNAL, "failed to list sessions", false, 0)
	}

	b := flatbuffers.NewBuilder(512)
	infoOffsets := make([]flatbuffers.UOffsetT, len(sessions))
	for i, sess := range sessions {
		sidOff := b.CreateString(sess.ID.String())
		devIDOff := b.CreateString(deviceIDString(sess.DeviceID))
		platOff := b.CreateString(sess.Platform)
		ipOff := b.CreateString("")
		fbWS.SessionInfoStart(b)
		fbWS.SessionInfoAddSessionId(b, sidOff)
		fbWS.SessionInfoAddDeviceId(b, devIDOff)
		fbWS.SessionInfoAddPlatform(b, platOff)
		fbWS.SessionInfoAddIp(b, ipOff)
		fbWS.SessionInfoAddCreatedAtMs(b, uint64(sess.CreatedAt.UnixMilli()))
		fbWS.SessionInfoAddExpiresAtMs(b, uint64(sess.ExpiresAt.UnixMilli()))
		fbWS.SessionInfoAddIsCurrent(b, sess.ID == s.SessionID)
		infoOffsets[i] = fbWS.SessionInfoEnd(b)
	}

	fbWS.SessionListResponseStartSessionsVector(b, len(infoOffsets))
	for i := len(infoOffsets) - 1; i >= 0; i-- {
		b.PrependUOffsetT(infoOffsets[i])
	}
	sessionsVec := b.EndVector(len(infoOffsets))

	fbWS.SessionListResponseStart(b)
	fbWS.SessionListResponseAddSessions(b, sessionsVec)
	respOffset := fbWS.SessionListResponseEnd(b)

	return s.Send(buildResponseEnvelope(b, r.currentProtocol, s.NextMessageID(), env.MessageId(), fbWS.PayloadSessionListResponse, respOffset))
}

func (r *Router) handleLogout(ctx context.Context, s *Session, env *fbWS.Envelope) error {
	if r.sessionUC == nil {
		return s.SendError(env.MessageId(), fbWS.ErrorCodeINTERNAL, "session service unavailable", false, 0)
	}

	if err := r.sessionUC.RevokeByID(ctx, s.SessionID, s.UserID, s.ClientIP, "", ""); err != nil {
		return s.SendError(env.MessageId(), fbWS.ErrorCodeINTERNAL, "logout failed", false, 0)
	}

	b := flatbuffers.NewBuilder(64)
	sidOff := b.CreateString(s.SessionID.String())
	fbWS.LogoutResponseStart(b)
	fbWS.LogoutResponseAddSessionId(b, sidOff)
	respOffset := fbWS.LogoutResponseEnd(b)

	if err := s.Send(buildResponseEnvelope(b, r.currentProtocol, s.NextMessageID(), env.MessageId(), fbWS.PayloadLogoutResponse, respOffset)); err != nil {
		return err
	}

	s.Close("logged_out")
	return nil
}
