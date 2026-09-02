package integration

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"airlance.org/api/internal/config"
	transportHTTP "airlance.org/api/internal/transport/http"
)

func TestReadiness_UnreadyWhenSchemaLookupFailsInProduction(t *testing.T) {
	cfg := &config.Config{
		Env:              "production",
		DatabaseDSN:      "postgres://invalid:invalid@localhost:9999/invalid",
		MinSchemaVersion: 1,
		MaxSchemaVersion: 10,
	}

	handlers := transportHTTP.NewHealthHandlers(nil, nil, cfg)

	req := httptest.NewRequest("GET", "/readyz", nil)
	rec := httptest.NewRecorder()

	handlers.Readyz(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503 Service Unavailable when schema lookup fails in production, got %d", rec.Code)
	}

	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err == nil {
		if body["status"] != "unready" {
			t.Errorf("expected status 'unready', got %v", body["status"])
		}
	}
}
