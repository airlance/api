package middleware

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/google/uuid"

	"airlance.org/api/internal/domain/session"
	sessionUC "airlance.org/api/internal/usecase/session"
)

type (
	sessionCtxKey struct{}
	userIDCtxKey  struct{}
	sessIDCtxKey  struct{}
)

// SessionMiddleware enforces session authentication on protected HTTP routes.
func SessionMiddleware(sessionUC *sessionUC.Usecase, allowedOrigins []string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token, isCookie := extractSessionToken(r)
			if token == "" {
				writeJSONError(w, http.StatusUnauthorized, "UNAUTHENTICATED", "Authentication required")
				return
			}

			// CSRF Protection for Cookie Mode on state-mutating methods
			if isCookie && isStateMutating(r.Method) {
				if !validateCSRF(r, allowedOrigins) {
					writeJSONError(w, http.StatusForbidden, "CSRF_FAILED", "CSRF verification failed")
					return
				}
			}

			sess, err := sessionUC.Validate(r.Context(), token)
			if err != nil {
				writeJSONError(w, http.StatusUnauthorized, "UNAUTHENTICATED", "Invalid or expired session")
				return
			}

			ctx := r.Context()
			ctx = context.WithValue(ctx, sessionCtxKey{}, sess)
			ctx = context.WithValue(ctx, userIDCtxKey{}, sess.UserID)
			ctx = context.WithValue(ctx, sessIDCtxKey{}, sess.ID)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// GetSession extracts the authenticated Session from request context.
func GetSession(ctx context.Context) *session.Session {
	if s, ok := ctx.Value(sessionCtxKey{}).(*session.Session); ok {
		return s
	}
	return nil
}

// GetUserID extracts the authenticated user ID from context.
func GetUserID(ctx context.Context) uuid.UUID {
	if uid, ok := ctx.Value(userIDCtxKey{}).(uuid.UUID); ok {
		return uid
	}
	return uuid.Nil
}

// GetSessionID extracts the active session ID from context.
func GetSessionID(ctx context.Context) uuid.UUID {
	if sid, ok := ctx.Value(sessIDCtxKey{}).(uuid.UUID); ok {
		return sid
	}
	return uuid.Nil
}

func extractSessionToken(r *http.Request) (token string, isCookie bool) {
	// 1. Check Authorization header
	authHeader := r.Header.Get("Authorization")
	if strings.HasPrefix(authHeader, "Bearer ") {
		return strings.TrimPrefix(authHeader, "Bearer "), false
	}

	// 2. Check Cookie
	if cookie, err := r.Cookie("session_token"); err == nil && cookie.Value != "" {
		return cookie.Value, true
	}

	return "", false
}

func isStateMutating(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch:
		return true
	default:
		return false
	}
}

func validateCSRF(r *http.Request, allowedOrigins []string) bool {
	// Check Sec-Fetch-Site if present
	if sfs := r.Header.Get("Sec-Fetch-Site"); sfs != "" {
		if sfs == "cross-site" {
			return false
		}
	}

	// Check Origin header
	origin := r.Header.Get("Origin")
	if origin != "" {
		for _, allowed := range allowedOrigins {
			if strings.EqualFold(origin, allowed) {
				return true
			}
		}
		return false
	}

	// Double-submit CSRF cookie & header check
	csrfHeader := r.Header.Get("X-CSRF-Token")
	csrfCookie, err := r.Cookie("csrf_token")
	if err == nil && csrfHeader != "" && csrfHeader == csrfCookie.Value {
		return true
	}

	return true // If Origin not set (e.g. native or same-origin direct), allow
}

func writeJSONError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]any{
			"code":    code,
			"message": message,
		},
	})
}
