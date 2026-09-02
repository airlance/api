package v1

import (
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/google/uuid"

	"airlance.org/api/internal/config"
	"airlance.org/api/internal/domain/ratelimit"
	"airlance.org/api/internal/middleware"
	"airlance.org/api/internal/usecase/auth"
	sessionUC "airlance.org/api/internal/usecase/session"
)

type AuthHandlers struct {
	authUC    *auth.Usecase
	sessionUC *sessionUC.Usecase
	cfg       *config.Config
}

func NewAuthHandlers(authUC *auth.Usecase, sessionUC *sessionUC.Usecase, cfg *config.Config) *AuthHandlers {
	return &AuthHandlers{
		authUC:    authUC,
		sessionUC: sessionUC,
		cfg:       cfg,
	}
}

func (h *AuthHandlers) PasskeySignupOptions(w http.ResponseWriter, r *http.Request) {
	ip := middleware.GetClientIP(r.Context())
	opts, err := h.authUC.BeginSignup(r.Context(), ip)
	if err != nil {
		if errors.Is(err, ratelimit.ErrRateLimitExceeded) {
			writeError(w, http.StatusTooManyRequests, "RATE_LIMITED", "Too many requests. Please try again later.")
			return
		}
		writeOperationError(w, r, http.StatusInternalServerError, "INTERNAL", "Unable to start signup", err)
		return
	}
	writeJSON(w, http.StatusOK, opts)
}

func (h *AuthHandlers) PasskeySignupVerify(w http.ResponseWriter, r *http.Request) {
	challengeIDStr := r.URL.Query().Get("challenge_id")
	if challengeIDStr == "" {
		challengeIDStr = r.Header.Get("X-Challenge-ID")
	}
	challengeID, err := uuid.Parse(challengeIDStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "Valid challenge_id required")
		return
	}

	payload, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "Failed to read request body")
		return
	}

	ip := middleware.GetClientIP(r.Context())
	ua := r.UserAgent()
	reqID := r.Header.Get("X-Request-ID")
	rawDeviceID := r.Header.Get("X-Device-ID")
	platform := r.Header.Get("X-Platform")
	var appVer *string
	if v := r.Header.Get("X-App-Version"); v != "" {
		appVer = &v
	}

	res, err := h.authUC.FinishSignup(r.Context(), challengeID, payload, rawDeviceID, platform, appVer, ip, ua, reqID)
	if err != nil {
		if errors.Is(err, ratelimit.ErrRateLimitExceeded) {
			writeError(w, http.StatusTooManyRequests, "RATE_LIMITED", "Too many requests. Please try again later.")
			return
		}
		writeOperationError(w, r, http.StatusUnauthorized, "AUTH_FAILED", "Signup verification failed", err)
		return
	}

	h.applySessionCookie(w, r, res.Token)
	writeJSON(w, http.StatusOK, res)
}

func (h *AuthHandlers) PasskeyLoginOptions(w http.ResponseWriter, r *http.Request) {
	ip := middleware.GetClientIP(r.Context())
	opts, err := h.authUC.BeginLogin(r.Context(), ip)
	if err != nil {
		if errors.Is(err, ratelimit.ErrRateLimitExceeded) {
			writeError(w, http.StatusTooManyRequests, "RATE_LIMITED", "Too many requests. Please try again later.")
			return
		}
		writeOperationError(w, r, http.StatusInternalServerError, "INTERNAL", "Unable to start login", err)
		return
	}
	writeJSON(w, http.StatusOK, opts)
}

func (h *AuthHandlers) PasskeyLoginVerify(w http.ResponseWriter, r *http.Request) {
	challengeIDStr := r.URL.Query().Get("challenge_id")
	if challengeIDStr == "" {
		challengeIDStr = r.Header.Get("X-Challenge-ID")
	}
	challengeID, err := uuid.Parse(challengeIDStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "Valid challenge_id required")
		return
	}

	payload, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "Failed to read request body")
		return
	}

	ip := middleware.GetClientIP(r.Context())
	ua := r.UserAgent()
	reqID := r.Header.Get("X-Request-ID")
	rawDeviceID := r.Header.Get("X-Device-ID")
	platform := r.Header.Get("X-Platform")
	var appVer *string
	if v := r.Header.Get("X-App-Version"); v != "" {
		appVer = &v
	}

	res, err := h.authUC.FinishLogin(r.Context(), challengeID, payload, rawDeviceID, platform, appVer, ip, ua, reqID)
	if err != nil {
		if errors.Is(err, ratelimit.ErrRateLimitExceeded) {
			writeError(w, http.StatusTooManyRequests, "RATE_LIMITED", "Too many requests. Please try again later.")
			return
		}
		writeOperationError(w, r, http.StatusUnauthorized, "AUTH_FAILED", "Login verification failed", err)
		return
	}

	h.applySessionCookie(w, r, res.Token)
	writeJSON(w, http.StatusOK, res)
}

func (h *AuthHandlers) PasskeyRegisterOptions(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserID(r.Context())
	if userID == uuid.Nil {
		writeError(w, http.StatusUnauthorized, "UNAUTHENTICATED", "Active session required")
		return
	}

	ip := middleware.GetClientIP(r.Context())
	opts, err := h.authUC.BeginRegisterCredential(r.Context(), userID, ip)
	if err != nil {
		if errors.Is(err, ratelimit.ErrRateLimitExceeded) {
			writeError(w, http.StatusTooManyRequests, "RATE_LIMITED", "Too many requests. Please try again later.")
			return
		}
		writeOperationError(w, r, http.StatusInternalServerError, "INTERNAL", "Unable to start credential registration", err)
		return
	}
	writeJSON(w, http.StatusOK, opts)
}

func (h *AuthHandlers) PasskeyRegisterVerify(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserID(r.Context())
	if userID == uuid.Nil {
		writeError(w, http.StatusUnauthorized, "UNAUTHENTICATED", "Active session required")
		return
	}

	challengeIDStr := r.URL.Query().Get("challenge_id")
	if challengeIDStr == "" {
		challengeIDStr = r.Header.Get("X-Challenge-ID")
	}
	challengeID, err := uuid.Parse(challengeIDStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "Valid challenge_id required")
		return
	}

	payload, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "Failed to read request body")
		return
	}

	ip := middleware.GetClientIP(r.Context())
	ua := r.UserAgent()
	reqID := r.Header.Get("X-Request-ID")

	cred, err := h.authUC.FinishRegisterCredential(r.Context(), userID, challengeID, payload, ip, ua, reqID)
	if err != nil {
		if errors.Is(err, ratelimit.ErrRateLimitExceeded) {
			writeError(w, http.StatusTooManyRequests, "RATE_LIMITED", "Too many requests. Please try again later.")
			return
		}
		writeOperationError(w, r, http.StatusBadRequest, "REGISTRATION_FAILED", "Credential registration failed", err)
		return
	}
	writeJSON(w, http.StatusOK, ToCredentialResponse(cred))
}

func (h *AuthHandlers) DeletePasskeyCredential(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserID(r.Context())
	if userID == uuid.Nil {
		writeError(w, http.StatusUnauthorized, "UNAUTHENTICATED", "Active session required")
		return
	}

	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) == 0 {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "Credential ID required")
		return
	}
	credIDStr := parts[len(parts)-1]
	credID, err := uuid.Parse(credIDStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "Invalid UUID credential ID")
		return
	}

	ip := middleware.GetClientIP(r.Context())
	ua := r.UserAgent()
	reqID := r.Header.Get("X-Request-ID")

	if err := h.authUC.DeleteCredential(r.Context(), userID, credID, ip, ua, reqID); err != nil {
		if errors.Is(err, ratelimit.ErrRateLimitExceeded) {
			writeError(w, http.StatusTooManyRequests, "RATE_LIMITED", "Too many requests. Please try again later.")
			return
		}
		writeOperationError(w, r, http.StatusBadRequest, "DELETE_FAILED", "Credential deletion failed", err)
		return
	}

	writeJSON(w, http.StatusOK, DeleteCredentialResponse{
		Status:       "deleted",
		CredentialID: credID.String(),
	})
}

func (h *AuthHandlers) RevokeSession(w http.ResponseWriter, r *http.Request) {
	var token string
	if cookie, err := r.Cookie("session_token"); err == nil && cookie.Value != "" {
		token = cookie.Value
	}
	if token == "" {
		authHeader := r.Header.Get("Authorization")
		if strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
			token = strings.TrimSpace(authHeader[7:])
		}
	}

	if token == "" {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "Session token required")
		return
	}

	ip := middleware.GetClientIP(r.Context())
	ua := r.UserAgent()
	reqID := r.Header.Get("X-Request-ID")

	if err := h.sessionUC.Revoke(r.Context(), token, ip, ua, reqID); err != nil {
		writeOperationError(w, r, http.StatusInternalServerError, "REVOKE_FAILED", "Session revocation failed", err)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	})

	writeJSON(w, http.StatusOK, StatusResponse{Status: "revoked"})
}

func (h *AuthHandlers) RevokeAllSessions(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserID(r.Context())
	if userID == uuid.Nil {
		writeError(w, http.StatusUnauthorized, "UNAUTHENTICATED", "Active session required")
		return
	}

	ip := middleware.GetClientIP(r.Context())
	ua := r.UserAgent()
	reqID := r.Header.Get("X-Request-ID")

	if err := h.sessionUC.RevokeAllForUser(r.Context(), userID, ip, ua, reqID); err != nil {
		writeOperationError(w, r, http.StatusInternalServerError, "REVOKE_ALL_FAILED", "Session revocation failed", err)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	})

	writeJSON(w, http.StatusOK, StatusResponse{Status: "all_sessions_revoked"})
}

func (h *AuthHandlers) applySessionCookie(w http.ResponseWriter, r *http.Request, token string) {
	isTLS := r.TLS != nil
	if !isTLS && h.cfg != nil && h.cfg.TLSTerminationIngress {
		if middleware.IsTrustedProxy(r.RemoteAddr, h.cfg.TrustedProxies) {
			forwardedProto := r.Header.Get("X-Forwarded-Proto")
			if strings.EqualFold(forwardedProto, "https") {
				isTLS = true
			}
		}
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    token,
		Path:     "/",
		MaxAge:   30 * 86400,
		HttpOnly: true,
		Secure:   isTLS,
		SameSite: http.SameSiteLaxMode,
	})
}
