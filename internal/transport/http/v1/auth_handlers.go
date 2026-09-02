// Package v1 provides API version 1 HTTP handlers.
package v1

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/google/uuid"

	"airlance.org/api/internal/middleware"
	"airlance.org/api/internal/usecase/auth"
)

// AuthHandlers provides passkey authentication HTTP endpoints.
type AuthHandlers struct {
	authUC *auth.Usecase
}

// NewAuthHandlers constructs AuthHandlers.
func NewAuthHandlers(authUC *auth.Usecase) *AuthHandlers {
	return &AuthHandlers{authUC: authUC}
}

// PasskeySignupOptions handles POST /api/v1/auth/passkey/signup/options.
func (h *AuthHandlers) PasskeySignupOptions(w http.ResponseWriter, r *http.Request) {
	opts, err := h.authUC.BeginSignup(r.Context())
	if err != nil {
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

	ip := middleware.GetClientIP(r.Context())
	ua := r.UserAgent()
	reqID := r.Header.Get("X-Request-ID")
	rawDeviceID := r.Header.Get("X-Device-ID")
	platform := r.Header.Get("X-Platform")
	var appVer *string
	if v := r.Header.Get("X-App-Version"); v != "" {
		appVer = &v
	}

	res, err := h.authUC.FinishSignup(r.Context(), challengeID, r, rawDeviceID, platform, appVer, ip, ua, reqID)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "AUTH_FAILED", err.Error())
		return
	}

	// Set cookie if requested or from browser
	applySessionCookie(w, r, res.Token)
	writeJSON(w, http.StatusOK, res)
}

// PasskeyLoginOptions handles POST /api/v1/auth/passkey/login/options.
func (h *AuthHandlers) PasskeyLoginOptions(w http.ResponseWriter, r *http.Request) {
	opts, err := h.authUC.BeginLogin(r.Context())
	if err != nil {
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

	ip := middleware.GetClientIP(r.Context())
	ua := r.UserAgent()
	reqID := r.Header.Get("X-Request-ID")
	rawDeviceID := r.Header.Get("X-Device-ID")
	platform := r.Header.Get("X-Platform")
	var appVer *string
	if v := r.Header.Get("X-App-Version"); v != "" {
		appVer = &v
	}

	res, err := h.authUC.FinishLogin(r.Context(), challengeID, r, rawDeviceID, platform, appVer, ip, ua, reqID)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "AUTH_FAILED", err.Error())
		return
	}

	applySessionCookie(w, r, res.Token)
	writeJSON(w, http.StatusOK, res)
}

// PasskeyRegisterOptions handles POST /api/v1/auth/passkey/register/options (session-protected).
func (h *AuthHandlers) PasskeyRegisterOptions(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserID(r.Context())
	if userID == uuid.Nil {
		writeError(w, http.StatusUnauthorized, "UNAUTHENTICATED", "Active session required")
		return
	}

	opts, err := h.authUC.BeginRegisterCredential(r.Context(), userID)
	if err != nil {
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

	ip := middleware.GetClientIP(r.Context())
	ua := r.UserAgent()
	reqID := r.Header.Get("X-Request-ID")

	cred, err := h.authUC.FinishRegisterCredential(r.Context(), userID, challengeID, r, ip, ua, reqID)
	if err != nil {
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
		writeError(w, http.StatusBadRequest, "DELETE_FAILED", err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"status": "deleted", "credential_id": credID.String()})
}

func applySessionCookie(w http.ResponseWriter, r *http.Request, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https",
		SameSite: http.SameSiteStrictMode,
		MaxAge:   30 * 24 * 3600,
	})
}

func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func writeError(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]any{
			"code":    code,
			"message": msg,
		},
	})
}
