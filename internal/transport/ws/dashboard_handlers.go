package ws

import (
	"context"
	"encoding/json"

	flatbuffers "github.com/google/flatbuffers/go"
	"github.com/google/uuid"

	fbWS "airlance.org/api/internal/transport/ws/airlance/ws"
)

func (r *Router) handleUserProfile(ctx context.Context, s *Session, env *fbWS.Envelope) error {
	b := flatbuffers.NewBuilder(256)
	uIDOff := b.CreateString(s.UserID.String())
	sIDOff := b.CreateString(s.SessionID.String())
	dIDOff := b.CreateString(deviceIDString(s.DeviceID))

	fbWS.UserProfileResponseStart(b)
	fbWS.UserProfileResponseAddUserId(b, uIDOff)
	fbWS.UserProfileResponseAddSessionId(b, sIDOff)
	fbWS.UserProfileResponseAddDeviceId(b, dIDOff)
	respOffset := fbWS.UserProfileResponseEnd(b)

	return s.Send(buildResponseEnvelope(b, r.currentProtocol, s.NextMessageID(), env.MessageId(), fbWS.PayloadUserProfileResponse, respOffset))
}

func (r *Router) handleSessionRevoke(ctx context.Context, s *Session, env *fbWS.Envelope) error {
	if r.sessionUC == nil {
		return s.SendError(env.MessageId(), fbWS.ErrorCodeINTERNAL, "session service unavailable", false, 0)
	}

	var req fbWS.SessionRevokeRequest
	table := new(flatbuffers.Table)
	if !env.Payload(table) {
		return s.SendError(env.MessageId(), fbWS.ErrorCodeINVALID_REQUEST, "invalid payload", false, 0)
	}
	req.Init(table.Bytes, table.Pos)

	targetSessionIDStr := string(req.SessionId())
	targetSessionID, err := uuid.Parse(targetSessionIDStr)
	if err != nil {
		return s.SendError(env.MessageId(), fbWS.ErrorCodeINVALID_REQUEST, "invalid session_id UUID", false, 0)
	}

	if err := r.sessionUC.RevokeByID(ctx, targetSessionID, s.UserID, s.ClientIP, "dashboard-ws", ""); err != nil {
		return s.SendError(env.MessageId(), fbWS.ErrorCodeINTERNAL, "failed to revoke session", false, 0)
	}

	b := flatbuffers.NewBuilder(64)
	sidOff := b.CreateString(targetSessionIDStr)
	fbWS.SessionRevokeResponseStart(b)
	fbWS.SessionRevokeResponseAddSessionId(b, sidOff)
	respOffset := fbWS.SessionRevokeResponseEnd(b)

	if err := s.Send(buildResponseEnvelope(b, r.currentProtocol, s.NextMessageID(), env.MessageId(), fbWS.PayloadSessionRevokeResponse, respOffset)); err != nil {
		return err
	}

	if targetSessionID == s.SessionID {
		s.Close("current_session_revoked")
	}

	return nil
}

func (r *Router) handleSessionRevokeAll(ctx context.Context, s *Session, env *fbWS.Envelope) error {
	if r.sessionUC == nil {
		return s.SendError(env.MessageId(), fbWS.ErrorCodeINTERNAL, "session service unavailable", false, 0)
	}

	if err := r.sessionUC.RevokeAllForUser(ctx, s.UserID, s.ClientIP, "dashboard-ws", ""); err != nil {
		return s.SendError(env.MessageId(), fbWS.ErrorCodeINTERNAL, "failed to revoke all sessions", false, 0)
	}

	b := flatbuffers.NewBuilder(64)
	statusOff := b.CreateString("all_sessions_revoked")
	fbWS.SessionRevokeAllResponseStart(b)
	fbWS.SessionRevokeAllResponseAddStatus(b, statusOff)
	respOffset := fbWS.SessionRevokeAllResponseEnd(b)

	if err := s.Send(buildResponseEnvelope(b, r.currentProtocol, s.NextMessageID(), env.MessageId(), fbWS.PayloadSessionRevokeAllResponse, respOffset)); err != nil {
		return err
	}

	s.Close("all_sessions_revoked")
	return nil
}

func (r *Router) handleDeviceList(ctx context.Context, s *Session, env *fbWS.Envelope) error {
	if r.authUC == nil {
		return s.SendError(env.MessageId(), fbWS.ErrorCodeINTERNAL, "auth service unavailable", false, 0)
	}

	devices, err := r.authUC.ListDevices(ctx, s.UserID)
	if err != nil {
		return s.SendError(env.MessageId(), fbWS.ErrorCodeINTERNAL, "failed to list devices", false, 0)
	}

	b := flatbuffers.NewBuilder(1024)
	devOffsets := make([]flatbuffers.UOffsetT, len(devices))
	for i, d := range devices {
		didOff := b.CreateString(d.ID.String())
		platOff := b.CreateString(d.Platform)
		var appVerOff flatbuffers.UOffsetT
		if d.LastAppVersion != nil {
			appVerOff = b.CreateString(*d.LastAppVersion)
		} else {
			appVerOff = b.CreateString("")
		}

		var lastSeen uint64
		if !d.LastSeenAt.IsZero() {
			lastSeen = uint64(d.LastSeenAt.UnixMilli())
		}
		var revokedAt uint64
		if d.RevokedAt != nil {
			revokedAt = uint64(d.RevokedAt.UnixMilli())
		}

		isCurrent := s.DeviceID != nil && *s.DeviceID == d.ID

		fbWS.DeviceInfoStart(b)
		fbWS.DeviceInfoAddDeviceId(b, didOff)
		fbWS.DeviceInfoAddPlatform(b, platOff)
		fbWS.DeviceInfoAddCreatedAtMs(b, uint64(d.CreatedAt.UnixMilli()))
		fbWS.DeviceInfoAddLastSeenAtMs(b, lastSeen)
		fbWS.DeviceInfoAddLastAppVersion(b, appVerOff)
		fbWS.DeviceInfoAddRevokedAtMs(b, revokedAt)
		fbWS.DeviceInfoAddIsCurrent(b, isCurrent)
		devOffsets[i] = fbWS.DeviceInfoEnd(b)
	}

	fbWS.DeviceListResponseStartDevicesVector(b, len(devOffsets))
	for i := len(devOffsets) - 1; i >= 0; i-- {
		b.PrependUOffsetT(devOffsets[i])
	}
	devicesVec := b.EndVector(len(devOffsets))

	fbWS.DeviceListResponseStart(b)
	fbWS.DeviceListResponseAddDevices(b, devicesVec)
	respOffset := fbWS.DeviceListResponseEnd(b)

	return s.Send(buildResponseEnvelope(b, r.currentProtocol, s.NextMessageID(), env.MessageId(), fbWS.PayloadDeviceListResponse, respOffset))
}

func (r *Router) handleDeviceRevoke(ctx context.Context, s *Session, env *fbWS.Envelope) error {
	if r.authUC == nil {
		return s.SendError(env.MessageId(), fbWS.ErrorCodeINTERNAL, "auth service unavailable", false, 0)
	}

	var req fbWS.DeviceRevokeRequest
	table := new(flatbuffers.Table)
	if !env.Payload(table) {
		return s.SendError(env.MessageId(), fbWS.ErrorCodeINVALID_REQUEST, "invalid payload", false, 0)
	}
	req.Init(table.Bytes, table.Pos)

	targetDeviceIDStr := string(req.DeviceId())
	targetDeviceID, err := uuid.Parse(targetDeviceIDStr)
	if err != nil {
		return s.SendError(env.MessageId(), fbWS.ErrorCodeINVALID_REQUEST, "invalid device_id UUID", false, 0)
	}

	if err := r.authUC.RevokeDevice(ctx, s.UserID, targetDeviceID, s.ClientIP, "dashboard-ws", ""); err != nil {
		return s.SendError(env.MessageId(), fbWS.ErrorCodePERMISSION_DENIED, "failed to revoke device", false, 0)
	}

	b := flatbuffers.NewBuilder(64)
	didOff := b.CreateString(targetDeviceIDStr)
	fbWS.DeviceRevokeResponseStart(b)
	fbWS.DeviceRevokeResponseAddDeviceId(b, didOff)
	respOffset := fbWS.DeviceRevokeResponseEnd(b)

	if err := s.Send(buildResponseEnvelope(b, r.currentProtocol, s.NextMessageID(), env.MessageId(), fbWS.PayloadDeviceRevokeResponse, respOffset)); err != nil {
		return err
	}

	if s.DeviceID != nil && *s.DeviceID == targetDeviceID {
		s.Close("device_revoked")
	}

	return nil
}

func (r *Router) handlePasskeyList(ctx context.Context, s *Session, env *fbWS.Envelope) error {
	if r.authUC == nil {
		return s.SendError(env.MessageId(), fbWS.ErrorCodeINTERNAL, "auth service unavailable", false, 0)
	}

	creds, err := r.authUC.ListCredentials(ctx, s.UserID)
	if err != nil {
		return s.SendError(env.MessageId(), fbWS.ErrorCodeINTERNAL, "failed to list passkeys", false, 0)
	}

	b := flatbuffers.NewBuilder(1024)
	credOffsets := make([]flatbuffers.UOffsetT, len(creds))
	for i, c := range creds {
		idOff := b.CreateString(c.ID.String())
		var aaguidOff flatbuffers.UOffsetT
		if c.AAGUID != nil {
			aaguidOff = b.CreateString(c.AAGUID.String())
		} else {
			aaguidOff = b.CreateString("")
		}

		transOffsets := make([]flatbuffers.UOffsetT, len(c.Transports))
		for j, t := range c.Transports {
			transOffsets[j] = b.CreateString(t)
		}
		fbWS.PasskeyInfoStartTransportsVector(b, len(transOffsets))
		for j := len(transOffsets) - 1; j >= 0; j-- {
			b.PrependUOffsetT(transOffsets[j])
		}
		transVec := b.EndVector(len(transOffsets))

		var lastUsed uint64
		if c.LastUsedAt != nil {
			lastUsed = uint64(c.LastUsedAt.UnixMilli())
		}

		fbWS.PasskeyInfoStart(b)
		fbWS.PasskeyInfoAddId(b, idOff)
		fbWS.PasskeyInfoAddAaguid(b, aaguidOff)
		fbWS.PasskeyInfoAddTransports(b, transVec)
		fbWS.PasskeyInfoAddCreatedAtMs(b, uint64(c.CreatedAt.UnixMilli()))
		fbWS.PasskeyInfoAddLastUsedAtMs(b, lastUsed)
		credOffsets[i] = fbWS.PasskeyInfoEnd(b)
	}

	fbWS.PasskeyListResponseStartCredentialsVector(b, len(credOffsets))
	for i := len(credOffsets) - 1; i >= 0; i-- {
		b.PrependUOffsetT(credOffsets[i])
	}
	credsVec := b.EndVector(len(credOffsets))

	fbWS.PasskeyListResponseStart(b)
	fbWS.PasskeyListResponseAddCredentials(b, credsVec)
	respOffset := fbWS.PasskeyListResponseEnd(b)

	return s.Send(buildResponseEnvelope(b, r.currentProtocol, s.NextMessageID(), env.MessageId(), fbWS.PayloadPasskeyListResponse, respOffset))
}

func (r *Router) handlePasskeyRegisterOptions(ctx context.Context, s *Session, env *fbWS.Envelope) error {
	if r.authUC == nil {
		return s.SendError(env.MessageId(), fbWS.ErrorCodeINTERNAL, "auth service unavailable", false, 0)
	}

	opts, err := r.authUC.BeginRegisterCredential(ctx, s.UserID, s.ClientIP)
	if err != nil {
		return s.SendError(env.MessageId(), fbWS.ErrorCodeINTERNAL, "failed to begin passkey registration", false, 0)
	}

	optsJSON, err := json.Marshal(opts.Creation)
	if err != nil {
		return s.SendError(env.MessageId(), fbWS.ErrorCodeINTERNAL, "failed to marshal creation options", false, 0)
	}

	b := flatbuffers.NewBuilder(1024)
	cidOff := b.CreateString(opts.ChallengeID.String())
	jsonOff := b.CreateString(string(optsJSON))

	fbWS.PasskeyRegisterOptionsResponseStart(b)
	fbWS.PasskeyRegisterOptionsResponseAddChallengeId(b, cidOff)
	fbWS.PasskeyRegisterOptionsResponseAddOptionsJson(b, jsonOff)
	respOffset := fbWS.PasskeyRegisterOptionsResponseEnd(b)

	return s.Send(buildResponseEnvelope(b, r.currentProtocol, s.NextMessageID(), env.MessageId(), fbWS.PayloadPasskeyRegisterOptionsResponse, respOffset))
}

func (r *Router) handlePasskeyRegisterVerify(ctx context.Context, s *Session, env *fbWS.Envelope) error {
	if r.authUC == nil {
		return s.SendError(env.MessageId(), fbWS.ErrorCodeINTERNAL, "auth service unavailable", false, 0)
	}

	var req fbWS.PasskeyRegisterVerifyRequest
	table := new(flatbuffers.Table)
	if !env.Payload(table) {
		return s.SendError(env.MessageId(), fbWS.ErrorCodeINVALID_REQUEST, "invalid payload", false, 0)
	}
	req.Init(table.Bytes, table.Pos)

	challengeIDStr := string(req.ChallengeId())
	challengeID, err := uuid.Parse(challengeIDStr)
	if err != nil {
		return s.SendError(env.MessageId(), fbWS.ErrorCodeINVALID_REQUEST, "invalid challenge_id UUID", false, 0)
	}

	responseJSON := req.ResponseJson()
	if len(responseJSON) == 0 {
		return s.SendError(env.MessageId(), fbWS.ErrorCodeINVALID_REQUEST, "response_json required", false, 0)
	}

	cred, err := r.authUC.FinishRegisterCredential(ctx, s.UserID, challengeID, responseJSON, s.ClientIP, "dashboard-ws", "")
	if err != nil {
		return s.SendError(env.MessageId(), fbWS.ErrorCodeINVALID_REQUEST, "failed to verify credential registration", false, 0)
	}

	b := flatbuffers.NewBuilder(128)
	idOff := b.CreateString(cred.ID.String())
	fbWS.PasskeyRegisterVerifyResponseStart(b)
	fbWS.PasskeyRegisterVerifyResponseAddId(b, idOff)
	fbWS.PasskeyRegisterVerifyResponseAddCreatedAtMs(b, uint64(cred.CreatedAt.UnixMilli()))
	respOffset := fbWS.PasskeyRegisterVerifyResponseEnd(b)

	return s.Send(buildResponseEnvelope(b, r.currentProtocol, s.NextMessageID(), env.MessageId(), fbWS.PayloadPasskeyRegisterVerifyResponse, respOffset))
}

func (r *Router) handlePasskeyDelete(ctx context.Context, s *Session, env *fbWS.Envelope) error {
	if r.authUC == nil {
		return s.SendError(env.MessageId(), fbWS.ErrorCodeINTERNAL, "auth service unavailable", false, 0)
	}

	var req fbWS.PasskeyDeleteRequest
	table := new(flatbuffers.Table)
	if !env.Payload(table) {
		return s.SendError(env.MessageId(), fbWS.ErrorCodeINVALID_REQUEST, "invalid payload", false, 0)
	}
	req.Init(table.Bytes, table.Pos)

	credIDStr := string(req.Id())
	credID, err := uuid.Parse(credIDStr)
	if err != nil {
		return s.SendError(env.MessageId(), fbWS.ErrorCodeINVALID_REQUEST, "invalid passkey UUID", false, 0)
	}

	if err := r.authUC.DeleteCredential(ctx, s.UserID, credID, s.ClientIP, "dashboard-ws", ""); err != nil {
		return s.SendError(env.MessageId(), fbWS.ErrorCodePERMISSION_DENIED, "failed to delete passkey", false, 0)
	}

	b := flatbuffers.NewBuilder(64)
	idOff := b.CreateString(credIDStr)
	fbWS.PasskeyDeleteResponseStart(b)
	fbWS.PasskeyDeleteResponseAddId(b, idOff)
	respOffset := fbWS.PasskeyDeleteResponseEnd(b)

	return s.Send(buildResponseEnvelope(b, r.currentProtocol, s.NextMessageID(), env.MessageId(), fbWS.PayloadPasskeyDeleteResponse, respOffset))
}
