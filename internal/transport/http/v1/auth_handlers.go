// Package v1 provides API version 1 HTTP handlers.
package v1

import (
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/google/uuid"

	"airlance.org/api/internal/config"
	"airlance.org/api/internal/middleware"
	"airlance.org/api/internal/usecase/auth"
	sessionUC "airlance.org/api/internal/usecase/session"
)

// AuthHandlers provides passkey authentication and session management HTTP endpoints.
type AuthHandlers struct {
	authUC    *auth.Usecase
	sessionUC *sessionUC.Usecase
	cfg       *config.Config
}

// NewAuthHandlers constructs AuthHandlers.
func NewAuthHandlers(authUC *auth.Usecase, sessionUC *sessionUC.Usecase, cfg *config.Config) *AuthHandlers {
	return &AuthHandlers{
		authUC:    authUC,
		sessionUC: sessionUC,
		cfg:       cfg,
	}
}

// PasskeySignupOptions handles POST /api/v1/auth/passkey/signup/options.
func (h *AuthHandlers) PasskeySignupOptions(w http.ResponseWriter, r *http.Request) {
	ip := middleware.GetClientIP(r.Context())
	opts, err := h.authUC.BeginSignup(r.Context(), ip)
	if err != nil {
		if errors.Is(err, auth.ErrRateLimitExceeded) {
			writeError(w, http.StatusTooManyRequests, "RATE_LIMITED", "Too many requests. Please try again later.")
			return
		}
		writeError(w, http.StatusInternalServerError, "INTERNAL", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, opts)
}

// PasskeySignupVerify handles POST /api/v1/auth/passkey/signup/verify.
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
		if errors.Is(err, auth.ErrRateLimitExceeded) {
			writeError(w, http.StatusTooManyRequests, "RATE_LIMITED", "Too many requests. Please try again later.")
			return
		}
		writeError(w, http.StatusUnauthorized, "AUTH_FAILED", err.Error())
		return
	}

	// Set cookie if requested or from browser
	h.applySessionCookie(w, r, res.Token)
	writeJSON(w, http.StatusOK, res)
}

// PasskeyLoginOptions handles POST /api/v1/auth/passkey/login/options.
func (h *AuthHandlers) PasskeyLoginOptions(w http.ResponseWriter, r *http.Request) {
	ip := middleware.GetClientIP(r.Context())
	opts, err := h.authUC.BeginLogin(r.Context(), ip)
	if err != nil {
		if errors.Is(err, auth.ErrRateLimitExceeded) {
			writeError(w, http.StatusTooManyRequests, "RATE_LIMITED", "Too many requests. Please try again later.")
			return
		}
		writeError(w, http.StatusInternalServerError, "INTERNAL", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, opts)
}

// PasskeyLoginVerify handles POST /api/v1/auth/passkey/login/verify.
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
		if errors.Is(err, auth.ErrRateLimitExceeded) {
			writeError(w, http.StatusTooManyRequests, "RATE_LIMITED", "Too many requests. Please try again later.")
			return
		}
		writeError(w, http.StatusUnauthorized, "AUTH_FAILED", err.Error())
		return
	}

	h.applySessionCookie(w, r, res.Token)
	writeJSON(w, http.StatusOK, res)
}

// PasskeyRegisterOptions handles POST /api/v1/auth/passkey/register/options (session-protected).
func (h *AuthHandlers) PasskeyRegisterOptions(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserID(r.Context())
	if userID == uuid.Nil {
		writeError(w, http.StatusUnauthorized, "UNAUTHENTICATED", "Active session required")
		return
	}

	ip := middleware.GetClientIP(r.Context())
	opts, err := h.authUC.BeginRegisterCredential(r.Context(), userID, ip)
	if err != nil {
		if errors.Is(err, auth.ErrRateLimitExceeded) {
			writeError(w, http.StatusTooManyRequests, "RATE_LIMITED", "Too many requests. Please try again later.")
			return
		}
		writeError(w, http.StatusInternalServerError, "INTERNAL", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, opts)
}

// PasskeyRegisterVerify handles POST /api/v1/auth/passkey/register/verify (session-protected).
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
		if errors.Is(err, auth.ErrRateLimitExceeded) {
			writeError(w, http.StatusTooManyRequests, "RATE_LIMITED", "Too many requests. Please try again later.")
			return
		}
		writeError(w, http.StatusBadRequest, "REGISTRATION_FAILED", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, cred)
}

// DeletePasskeyCredential handles DELETE /api/v1/auth/passkey/{credentialID} (session-protected).
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
		if errors.Is(err, auth.ErrRateLimitExceeded) {
			writeError(w, http.StatusTooManyRequests, "RATE_LIMITED", "Too many requests. Please try again later.")
			return
		}
		writeError(w, http.StatusBadRequest, "DELETE_FAILED", err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"status": "deleted", "credential_id": credID.String()})
}

// RevokeSession handles POST /api/v1/auth/session/revoke (session-protected).
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
		writeError(w, http.StatusInternalServerError, "REVOKE_FAILED", err.Error())
		return
	}

	// Clear session cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	})

	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}

// RevokeAllSessions handles POST /api/v1/auth/sessions/revoke-all (session-protected).
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
		writeError(w, http.StatusInternalServerError, "REVOKE_ALL_FAILED", err.Error())
		return
	}

	// Clear session cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	})

	writeJSON(w, http.StatusOK, map[string]string{"status": "all_sessions_revoked"})
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
