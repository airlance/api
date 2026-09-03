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

func BootstrapSessionMiddleware(
	sessionUC *sessionUC.Usecase,
	allowedOrigins []string,
	onInvalidCookie func(w http.ResponseWriter, r *http.Request),
) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token, isCookie := extractSessionToken(r)
			if token == "" {
				writeJSONError(w, http.StatusUnauthorized, "UNAUTHENTICATED", "Authentication required")
				return
			}

			if isCookie && isStateMutating(r.Method) {
				if !validateCSRF(r, allowedOrigins) {
					writeJSONError(w, http.StatusForbidden, "CSRF_FAILED", "CSRF verification failed")
					return
				}
			}

			sess, err := sessionUC.Validate(r.Context(), token)
			if err != nil {
				if isCookie && onInvalidCookie != nil {
					onInvalidCookie(w, r)
				}
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

func NativeBearerSessionMiddleware(sessionUC *sessionUC.Usecase) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if !strings.HasPrefix(authHeader, "Bearer ") {
				writeJSONError(w, http.StatusUnauthorized, "UNAUTHENTICATED", "Bearer token authentication required")
				return
			}
			token := strings.TrimPrefix(authHeader, "Bearer ")
			if token == "" {
				writeJSONError(w, http.StatusUnauthorized, "UNAUTHENTICATED", "Bearer token required")
				return
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

func SessionMiddleware(sessionUC *sessionUC.Usecase, allowedOrigins []string) func(http.Handler) http.Handler {
	return BootstrapSessionMiddleware(sessionUC, allowedOrigins, nil)
}

func GetSession(ctx context.Context) *session.Session {
	if s, ok := ctx.Value(sessionCtxKey{}).(*session.Session); ok {
		return s
	}
	return nil
}

func GetUserID(ctx context.Context) uuid.UUID {
	if uid, ok := ctx.Value(userIDCtxKey{}).(uuid.UUID); ok {
		return uid
	}
	return uuid.Nil
}

func GetSessionID(ctx context.Context) uuid.UUID {
	if sid, ok := ctx.Value(sessIDCtxKey{}).(uuid.UUID); ok {
		return sid
	}
	return uuid.Nil
}

func extractSessionToken(r *http.Request) (token string, isCookie bool) {
	if cookie, err := r.Cookie("__Host-session_token"); err == nil && cookie.Value != "" {
		return cookie.Value, true
	}
	if cookie, err := r.Cookie("session_token"); err == nil && cookie.Value != "" {
		return cookie.Value, true
	}

	authHeader := r.Header.Get("Authorization")
	if strings.HasPrefix(authHeader, "Bearer ") {
		return strings.TrimPrefix(authHeader, "Bearer "), false
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
	if sfs := r.Header.Get("Sec-Fetch-Site"); sfs != "" {
		if sfs == "cross-site" {
			return false
		}
	}

	origin := r.Header.Get("Origin")
	if origin != "" {
		for _, allowed := range allowedOrigins {
			if strings.EqualFold(origin, allowed) {
				return true
			}
		}
		return false
	}

	return false
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
