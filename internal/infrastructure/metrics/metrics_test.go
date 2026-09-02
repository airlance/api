package metrics

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMetricsRegistry(t *testing.T) {
	reg := NewRegistry()

	reg.IncHTTPRequests("GET", "/api/v1/me", 200)
	reg.IncAuthEvents("signup", "success")
	reg.IncRateLimitHits("ip")
	reg.IncWSHandshakeErrors()
	reg.SetWSConnections(42)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/metrics", nil)
	reg.Handler().ServeHTTP(rec, req)

	body := rec.Body.String()
	if !strings.Contains(body, `http_requests_total{method="GET",path="/api/v1/me",status="200"} 1`) {
		t.Errorf("missing or incorrect http_requests_total metric: %s", body)
	}
	if !strings.Contains(body, `auth_events_total{ceremony="signup",result="success"} 1`) {
		t.Errorf("missing or incorrect auth_events_total metric: %s", body)
	}
	if !strings.Contains(body, `ws_active_connections 42`) {
		t.Errorf("missing or incorrect ws_active_connections metric: %s", body)
	}
	if !strings.Contains(body, `ws_handshake_errors_total 1`) {
		t.Errorf("missing or incorrect ws_handshake_errors_total metric: %s", body)
	}
}
