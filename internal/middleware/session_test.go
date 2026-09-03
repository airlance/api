package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"airlance.org/api/internal/domain/audit"
	"airlance.org/api/internal/domain/session"
	sessionUC "airlance.org/api/internal/usecase/session"
)

func TestValidateCSRF_OriginAndSecFetchSite(t *testing.T) {
	allowedOrigins := []string{"https://app.example.com", "http://localhost:3000"}

	tests := []struct {
		name         string
		origin       string
		secFetchSite string
		expected     bool
	}{
		{
			name:         "valid dashboard origin",
			origin:       "https://app.example.com",
			secFetchSite: "same-origin",
			expected:     true,
		},
		{
			name:         "valid dev origin same-site",
			origin:       "http://localhost:3000",
			secFetchSite: "same-site",
			expected:     true,
		},
		{
			name:         "cross-site Sec-Fetch-Site even with valid origin",
			origin:       "https://app.example.com",
			secFetchSite: "cross-site",
			expected:     false,
		},
		{
			name:         "wrong origin",
			origin:       "https://attacker.com",
			secFetchSite: "cross-site",
			expected:     false,
		},
		{
			name:         "missing origin signal",
			origin:       "",
			secFetchSite: "none",
			expected:     false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/api/v1/ws/ticket", nil)
			if tc.origin != "" {
				req.Header.Set("Origin", tc.origin)
			}
			if tc.secFetchSite != "" {
				req.Header.Set("Sec-Fetch-Site", tc.secFetchSite)
			}
			result := validateCSRF(req, allowedOrigins)
			if result != tc.expected {
				t.Fatalf("expected %v, got %v", tc.expected, result)
			}
		})
	}
}

type testTxManager struct{}

func (m *testTxManager) WithTx(ctx context.Context, fn func(ctx context.Context) error) error {
	return fn(ctx)
}

type testSessionRepo struct {
	sessions map[string]*session.Session
}

func (m *testSessionRepo) Create(ctx context.Context, s *session.Session) error {
	m.sessions[string(s.TokenHash)] = s
	return nil
}
func (m *testSessionRepo) GetValid(ctx context.Context, tokenHash []byte) (*session.Session, error) {
	s, ok := m.sessions[string(tokenHash)]
	if !ok {
		return nil, session.ErrNotFound
	}
	if s.RevokedAt != nil {
		return nil, session.ErrRevoked
	}
	return s, nil
}
func (m *testSessionRepo) GetByID(ctx context.Context, id uuid.UUID) (*session.Session, error) {
	return nil, nil
}
func (m *testSessionRepo) ListByUserID(ctx context.Context, userID uuid.UUID) ([]*session.Session, error) {
	return nil, nil
}
func (m *testSessionRepo) Revoke(ctx context.Context, tokenHash []byte) error { return nil }
func (m *testSessionRepo) RevokeByID(ctx context.Context, id uuid.UUID) error { return nil }
func (m *testSessionRepo) RevokeAllForUser(ctx context.Context, userID uuid.UUID) error {
	return nil
}
func (m *testSessionRepo) RevokeAllForDevice(ctx context.Context, deviceID uuid.UUID) error {
	return nil
}
func (m *testSessionRepo) CleanupExpired(ctx context.Context, before time.Time) (int64, error) {
	return 0, nil
}

type testAuditRepo struct{}

func (m *testAuditRepo) Record(ctx context.Context, e *audit.Event) error { return nil }

func TestSessionMiddleware_BearerAuth(t *testing.T) {
	repo := &testSessionRepo{sessions: make(map[string]*session.Session)}
	uc := sessionUC.NewUsecase(repo, &testAuditRepo{}, &testTxManager{}, nil, 1*time.Hour)

	userID := uuid.New()
	identID := uuid.New()
	token, sess, err := uc.CreateSession(context.Background(), userID, identID, nil, "127.0.0.1", "test", "req-1")
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}

	mw := SessionMiddleware(uc, []string{"http://localhost:3000"})

	var capturedUID uuid.UUID
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedUID = GetUserID(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}
	if capturedUID != sess.UserID {
		t.Errorf("expected user ID %v, got %v", sess.UserID, capturedUID)
	}

	unauthReq := httptest.NewRequest("GET", "/protected", nil)
	unauthRec := httptest.NewRecorder()
	handler.ServeHTTP(unauthRec, unauthReq)

	if unauthRec.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401, got %d", unauthRec.Code)
	}
}

func TestBootstrapSessionMiddleware_ClearsCookieOnInvalidSession(t *testing.T) {
	repo := &testSessionRepo{sessions: make(map[string]*session.Session)}
	uc := sessionUC.NewUsecase(repo, &testAuditRepo{}, &testTxManager{}, nil, 1*time.Hour)

	var cookieCleared bool
	clearFn := func(w http.ResponseWriter, r *http.Request) {
		cookieCleared = true
	}

	mw := BootstrapSessionMiddleware(uc, []string{"http://localhost:3000"}, clearFn)
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/ws/ticket", nil)
	req.Header.Set("Origin", "http://localhost:3000")
	req.AddCookie(&http.Cookie{Name: "__Host-session_token", Value: "stale-invalid-token"})
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401, got %d", rec.Code)
	}
	if !cookieCleared {
		t.Errorf("expected onInvalidCookie callback to be invoked")
	}
}

func TestNativeBearerSessionMiddleware_RejectsCookies(t *testing.T) {
	repo := &testSessionRepo{sessions: make(map[string]*session.Session)}
	uc := sessionUC.NewUsecase(repo, &testAuditRepo{}, &testTxManager{}, nil, 1*time.Hour)

	userID := uuid.New()
	identID := uuid.New()
	token, _, err := uc.CreateSession(context.Background(), userID, identID, nil, "127.0.0.1", "test", "req-1")
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}

	mw := NativeBearerSessionMiddleware(uc)
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	cookieReq := httptest.NewRequest(http.MethodGet, "/api/v1/clients", nil)
	cookieReq.AddCookie(&http.Cookie{Name: "__Host-session_token", Value: token})
	cookieRec := httptest.NewRecorder()
	handler.ServeHTTP(cookieRec, cookieReq)

	if cookieRec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 on cookie authentication for native endpoint, got %d", cookieRec.Code)
	}

	bearerReq := httptest.NewRequest(http.MethodGet, "/api/v1/clients", nil)
	bearerReq.Header.Set("Authorization", "Bearer "+token)
	bearerRec := httptest.NewRecorder()
	handler.ServeHTTP(bearerRec, bearerReq)

	if bearerRec.Code != http.StatusOK {
		t.Errorf("expected 200 on Bearer token, got %d", bearerRec.Code)
	}
}
