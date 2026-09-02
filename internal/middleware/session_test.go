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

func TestValidateCSRF_RequiresDoubleSubmitWhenOriginIsAbsent(t *testing.T) {
	allowedOrigins := []string{"https://app.example.com"}

	missing := httptest.NewRequest(http.MethodPost, "/protected", nil)
	if validateCSRF(missing, allowedOrigins) {
		t.Fatal("expected a request without Origin or double-submit token to be rejected")
	}

	mismatch := httptest.NewRequest(http.MethodPost, "/protected", nil)
	mismatch.Header.Set("X-CSRF-Token", "header-token")
	mismatch.AddCookie(&http.Cookie{Name: "csrf_token", Value: "cookie-token"})
	if validateCSRF(mismatch, allowedOrigins) {
		t.Fatal("expected mismatched double-submit tokens to be rejected")
	}

	valid := httptest.NewRequest(http.MethodPost, "/protected", nil)
	valid.Header.Set("X-CSRF-Token", "token")
	valid.AddCookie(&http.Cookie{Name: "csrf_token", Value: "token"})
	if !validateCSRF(valid, allowedOrigins) {
		t.Fatal("expected matching double-submit tokens to be accepted")
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

	// 1. Request with Bearer token
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

	// 2. Request without token
	unauthReq := httptest.NewRequest("GET", "/protected", nil)
	unauthRec := httptest.NewRecorder()
	handler.ServeHTTP(unauthRec, unauthReq)

	if unauthRec.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401, got %d", unauthRec.Code)
	}
}
