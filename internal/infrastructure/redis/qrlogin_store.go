package redis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/airlance/api/internal/domain/clientcontext"
	"github.com/airlance/api/internal/domain/qrlogin"
	"github.com/redis/go-redis/v9"
)

func qrLoginKey(token string) string {
	return "qrlogin:" + token
}

type qrLoginPayload struct {
	Status           string `json:"status"`
	IPAddress        string `json:"ip_address"`
	UserAgent        string `json:"user_agent"`
	Platform         string `json:"platform"`
	OS               string `json:"os"`
	WaiterAuthKeyID  string `json:"waiter_auth_key_id"`
	ServerInstanceID string `json:"server_instance_id"`
	UserID           int32  `json:"user_id"`
	CreatedAt        int64  `json:"created_at_unix_ms"`
}

func toPayload(s *qrlogin.Session) qrLoginPayload {
	return qrLoginPayload{
		Status:           string(s.Status),
		IPAddress:        s.WaiterClientCtx.IPAddress,
		UserAgent:        s.WaiterClientCtx.UserAgent,
		Platform:         string(s.WaiterClientCtx.Platform),
		OS:               s.WaiterClientCtx.OS,
		WaiterAuthKeyID:  strconv.FormatUint(s.WaiterAuthKeyID, 10),
		ServerInstanceID: s.ServerInstanceID,
		UserID:           s.UserID,
		CreatedAt:        s.CreatedAt.UnixMilli(),
	}
}

func fromPayload(token string, p qrLoginPayload) *qrlogin.Session {
	waiterAuthKeyID, err := strconv.ParseUint(p.WaiterAuthKeyID, 10, 64)
	if err != nil {
		// Should be unreachable given toPayload always writes a valid
		// uint64 string, but fail safe rather than panic on bad data.
		waiterAuthKeyID = 0
	}
	return &qrlogin.Session{
		Token:  token,
		Status: qrlogin.Status(p.Status),
		WaiterClientCtx: clientcontext.ClientContext{
			IPAddress: p.IPAddress,
			UserAgent: p.UserAgent,
			Platform:  clientcontext.Platform(p.Platform),
			OS:        p.OS,
		},
		WaiterAuthKeyID:  waiterAuthKeyID,
		ServerInstanceID: p.ServerInstanceID,
		UserID:           p.UserID,
		CreatedAt:        time.UnixMilli(p.CreatedAt),
	}
}

type QRLoginStore struct {
	client *redis.Client
}

var _ qrlogin.Store = (*QRLoginStore)(nil)

func NewQRLoginStore(client *redis.Client) *QRLoginStore {
	return &QRLoginStore{client: client}
}

func (s *QRLoginStore) Create(ctx context.Context, sess *qrlogin.Session) error {
	raw, err := json.Marshal(toPayload(sess))
	if err != nil {
		return fmt.Errorf("redis: marshal qrlogin session: %w", err)
	}

	ok, err := s.client.SetNX(ctx, qrLoginKey(sess.Token), raw, qrlogin.TTL).Result()
	if err != nil {
		return fmt.Errorf("redis: create qrlogin session: %w", err)
	}
	if !ok {
		// Token collision — vanishingly unlikely given the token is a
		// cryptographically random value, but surfaced as an error rather
		// than silently overwriting an existing session.
		return fmt.Errorf("redis: qrlogin token already exists")
	}
	return nil
}

func (s *QRLoginStore) Get(ctx context.Context, token string) (*qrlogin.Session, error) {
	raw, err := s.client.Get(ctx, qrLoginKey(token)).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, qrlogin.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("redis: get qrlogin session: %w", err)
	}

	var p qrLoginPayload
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, fmt.Errorf("redis: unmarshal qrlogin session: %w", err)
	}
	return fromPayload(token, p), nil
}

// transitionScript atomically checks that the stored status matches one of
// the allowed "from" statuses, and if so mutates the stored JSON in place
// (setting the new status and, optionally, user_id) while preserving the
// key's remaining TTL (KEEPTTL) — a token's total lifetime is fixed from
// creation; a scan/confirm doesn't extend it.
//
// KEYS[1] = the qrlogin key
// ARGV[1] = comma-separated list of allowed current statuses
// ARGV[2] = new status to set
// ARGV[3] = user_id to set, or "" to leave user_id unchanged
//
// Returns:
//
//	nil        if the key doesn't exist (=> ErrNotFound)
//	"CONFLICT" if the key exists but its status isn't in the allowed list (=> ErrAlreadyUsed)
//	<json>     the full updated payload on successful transition
var transitionScript = redis.NewScript(`
local raw = redis.call("GET", KEYS[1])
if raw == false then
  return false
end
local current = cjson.decode(raw)
local allowed = {}
for status in string.gmatch(ARGV[1], "[^,]+") do
  allowed[status] = true
end
if not allowed[current.status] then
  return "CONFLICT"
end
current.status = ARGV[2]
if ARGV[3] ~= "" then
  current.user_id = tonumber(ARGV[3])
end
local updated = cjson.encode(current)
redis.call("SET", KEYS[1], updated, "KEEPTTL")
return updated
`)

func (s *QRLoginStore) transition(ctx context.Context, token string, allowedFrom []string, newStatus qrlogin.Status, userID *int32) (*qrlogin.Session, error) {
	allowed := ""
	for i, st := range allowedFrom {
		if i > 0 {
			allowed += ","
		}
		allowed += st
	}

	userIDArg := ""
	if userID != nil {
		userIDArg = fmt.Sprintf("%d", *userID)
	}

	result, err := transitionScript.Run(ctx, s.client, []string{qrLoginKey(token)}, allowed, string(newStatus), userIDArg).Result()
	if errors.Is(err, redis.Nil) || result == nil {
		return nil, qrlogin.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("redis: qrlogin transition: %w", err)
	}

	str, ok := result.(string)
	if !ok {
		return nil, fmt.Errorf("redis: qrlogin transition: unexpected result type %T", result)
	}
	if str == "CONFLICT" {
		return nil, qrlogin.ErrAlreadyUsed
	}

	var p qrLoginPayload
	if err := json.Unmarshal([]byte(str), &p); err != nil {
		return nil, fmt.Errorf("redis: unmarshal qrlogin session after transition: %w", err)
	}
	return fromPayload(token, p), nil
}

func (s *QRLoginStore) MarkScanned(ctx context.Context, token string) (*qrlogin.Session, error) {
	return s.transition(ctx, token, []string{string(qrlogin.StatusPending)}, qrlogin.StatusScanned, nil)
}

func (s *QRLoginStore) MarkConfirmed(ctx context.Context, token string, userID int32) (*qrlogin.Session, error) {
	return s.transition(ctx, token, []string{string(qrlogin.StatusScanned)}, qrlogin.StatusConfirmed, &userID)
}

func (s *QRLoginStore) MarkRejected(ctx context.Context, token string) (*qrlogin.Session, error) {
	return s.transition(ctx, token, []string{string(qrlogin.StatusScanned)}, qrlogin.StatusRejected, nil)
}

func (s *QRLoginStore) Delete(ctx context.Context, token string) error {
	if err := s.client.Del(ctx, qrLoginKey(token)).Err(); err != nil {
		return fmt.Errorf("redis: delete qrlogin session: %w", err)
	}
	return nil
}
