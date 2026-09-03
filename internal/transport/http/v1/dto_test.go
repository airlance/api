package v1

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"

	"airlance.org/api/internal/domain/apiclient"
	"airlance.org/api/internal/domain/device"
	"airlance.org/api/internal/domain/passkey"
)

func TestDTO_DeviceResponse(t *testing.T) {
	id := uuid.New()
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	appVer := "1.2.3"
	d := &device.Device{
		ID:                   id,
		UserID:               uuid.New(),
		DeviceIdentifierHash: []byte("secret-hash-do-not-leak"),
		Platform:             "ios",
		CreatedAt:            now,
		LastSeenAt:           now,
		LastAppVersion:       &appVer,
		RevokedAt:            nil,
	}

	dto := ToDeviceResponse(d)
	data, err := json.Marshal(dto)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if m["id"] != id.String() {
		t.Errorf("expected id %s, got %v", id.String(), m["id"])
	}
	if m["platform"] != "ios" {
		t.Errorf("expected platform ios, got %v", m["platform"])
	}
	if m["last_app_version"] != "1.2.3" {
		t.Errorf("expected last_app_version 1.2.3, got %v", m["last_app_version"])
	}

	if _, ok := m["device_identifier_hash"]; ok {
		t.Errorf("device_identifier_hash should not be present in json output")
	}

	listDTO := ToDeviceListResponse([]*device.Device{d})
	listData, err := json.Marshal(listDTO)
	if err != nil {
		t.Fatalf("marshal list failed: %v", err)
	}
	var listMap map[string]any
	_ = json.Unmarshal(listData, &listMap)
	devices, ok := listMap["devices"].([]any)
	if !ok || len(devices) != 1 {
		t.Fatalf("expected devices array of len 1")
	}
}

func TestDTO_ClientResponse(t *testing.T) {
	id := uuid.New()
	userID := uuid.New()
	tierID := uuid.New()
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)

	c := &apiclient.APIClient{
		ID:         id,
		UserID:     userID,
		TierID:     tierID,
		Name:       "TestClient",
		SecretHash: []byte("secret-hash-hidden"),
		CreatedAt:  now,
		RevokedAt:  nil,
	}

	dto := ToClientResponse(c)
	data, err := json.Marshal(dto)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if m["id"] != id.String() {
		t.Errorf("expected id %s, got %v", id.String(), m["id"])
	}
	if m["name"] != "TestClient" {
		t.Errorf("expected name TestClient, got %v", m["name"])
	}

	if _, ok := m["secret_hash"]; ok {
		t.Errorf("secret_hash should not be present in json")
	}
	if _, ok := m["key_id"]; ok {
		t.Errorf("key_id should not be present in json")
	}
}

func TestDTO_WSTicketResponse(t *testing.T) {
	resp := WSTicketResponse{
		Ticket:    "ticket-12345",
		ExpiresAt: "2026-09-02T12:00:00Z",
		TTLSec:    60,
	}
	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	var m map[string]any
	_ = json.Unmarshal(data, &m)
	if m["ticket"] != "ticket-12345" || m["ttl_sec"] != float64(60) {
		t.Errorf("unexpected ticket json: %v", m)
	}
}

func TestDTO_MeResponse(t *testing.T) {
	resp := MeResponse{
		UserID:   "u-1",
		ClientID: "c-1",
		RateLimits: map[string]RateLimitUsageDTO{
			"per_minute": {
				Limit:     60,
				Remaining: 59,
				ResetAt:   "2026-09-02T12:01:00Z",
				WindowSec: 60,
			},
		},
	}
	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	var m map[string]any
	_ = json.Unmarshal(data, &m)
	if m["user_id"] != "u-1" || m["client_id"] != "c-1" {
		t.Errorf("unexpected me json: %v", m)
	}
	rl, ok := m["rate_limits"].(map[string]any)
	if !ok || rl["per_minute"] == nil {
		t.Errorf("expected rate_limits.per_minute, got: %v", m["rate_limits"])
	}
}

func TestDTO_CredentialResponse(t *testing.T) {
	id := uuid.New()
	aaguid := uuid.New()
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	cred := &passkey.Credential{
		ID:           id,
		IdentityID:   uuid.New(),
		CredentialID: []byte("raw-cred-id"),
		PublicKey:    []byte("raw-pubkey"),
		SignCount:    10,
		Transports:   []string{"usb", "internal"},
		AAGUID:       &aaguid,
		CreatedAt:    now,
		LastUsedAt:   &now,
	}

	dto := ToCredentialResponse(cred)
	data, err := json.Marshal(dto)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if m["id"] != id.String() {
		t.Errorf("expected id %s, got %v", id.String(), m["id"])
	}
	if m["aaguid"] != aaguid.String() {
		t.Errorf("expected aaguid %s, got %v", aaguid.String(), m["aaguid"])
	}

	if _, ok := m["credential_id"]; ok {
		t.Errorf("credential_id raw bytes should not be exposed")
	}
	if _, ok := m["public_key"]; ok {
		t.Errorf("public_key raw bytes should not be exposed")
	}
}
