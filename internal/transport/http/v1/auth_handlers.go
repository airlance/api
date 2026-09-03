package v1

import (
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/google/uuid"

	"airlance.org/api/internal/config"
	"airlance.org/api/internal/domain/ratelimit"
	"airlance.org/api/internal/infrastructure/logger"
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

	if !h.validateBrowserOrigin(w, r) {
		return
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
	writeJSON(w, http.StatusOK, WebAuthSuccessResponse{
		User: WebAuthUserResponse{
			ID: res.User.ID,
		},
		IsNewUser: res.IsNewUser,
	})
}

func (h *AuthHandlers) NativePasskeySignupOptions(w http.ResponseWriter, r *http.Request) {
	if !h.validateNativeContext(w, r, "options") {
		return
	}

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

func (h *AuthHandlers) NativePasskeySignupVerify(w http.ResponseWriter, r *http.Request) {
	challengeIDStr := r.URL.Query().Get("challenge_id")
	if challengeIDStr == "" {
		challengeIDStr = r.Header.Get("X-Challenge-ID")
	}
	challengeID, err := uuid.Parse(challengeIDStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "Valid challenge_id required")
		return
	}

	if !h.validateNativeContext(w, r, challengeID.String()) {
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
	if platform == "" {
		platform = "native"
	}
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

	writeJSON(w, http.StatusOK, NativeAuthSuccessResponse{
		Token: res.Token,
		User: WebAuthUserResponse{
			ID: res.User.ID,
		},
		IsNewUser: res.IsNewUser,
	})
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

	if !h.validateBrowserOrigin(w, r) {
		return
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
	writeJSON(w, http.StatusOK, WebAuthSuccessResponse{
		User: WebAuthUserResponse{
			ID: res.User.ID,
		},
		IsNewUser: res.IsNewUser,
	})
}

func (h *AuthHandlers) NativePasskeyLoginOptions(w http.ResponseWriter, r *http.Request) {
	if !h.validateNativeContext(w, r, "options") {
		return
	}

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

func (h *AuthHandlers) NativePasskeyLoginVerify(w http.ResponseWriter, r *http.Request) {
	challengeIDStr := r.URL.Query().Get("challenge_id")
	if challengeIDStr == "" {
		challengeIDStr = r.Header.Get("X-Challenge-ID")
	}
	challengeID, err := uuid.Parse(challengeIDStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "Valid challenge_id required")
		return
	}

	if !h.validateNativeContext(w, r, challengeID.String()) {
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
	if platform == "" {
		platform = "native"
	}
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

	writeJSON(w, http.StatusOK, NativeAuthSuccessResponse{
		Token: res.Token,
		User: WebAuthUserResponse{
			ID: res.User.ID,
		},
		IsNewUser: res.IsNewUser,
	})
}

func (h *AuthHandlers) validateBrowserOrigin(w http.ResponseWriter, r *http.Request) bool {
	if sfs := r.Header.Get("Sec-Fetch-Site"); sfs == "cross-site" {
		writeError(w, http.StatusForbidden, "CSRF_FAILED", "Cross-site requests rejected")
		return false
	}

	origin := r.Header.Get("Origin")
	if origin == "" {
		writeError(w, http.StatusForbidden, "CSRF_FAILED", "Origin header required for web authentication")
		return false
	}

	if h.cfg != nil && len(h.cfg.WebAuthnRPOrigins) > 0 {
		allowed := false
		for _, o := range h.cfg.WebAuthnRPOrigins {
			if strings.EqualFold(origin, o) {
				allowed = true
				break
			}
		}
		if !allowed {
			writeError(w, http.StatusForbidden, "CSRF_FAILED", "Unauthorized Origin")
			return false
		}
	}

	return true
}

func (h *AuthHandlers) validateNativeContext(w http.ResponseWriter, r *http.Request, challengeID string) bool {
	if r.Header.Get("Origin") != "" || r.Header.Get("Sec-Fetch-Site") != "" {
		writeError(w, http.StatusForbidden, "FORBIDDEN", "Native endpoints cannot be accessed from a browser context")
		return false
	}

	if h.cfg == nil || h.cfg.NativeAppSecretKey == "" || h.cfg.NativeAppID == "" {
		writeError(w, http.StatusServiceUnavailable, "NATIVE_AUTH_UNAVAILABLE", "Native authentication is unavailable")
		return false
	}
	if err := ValidateNativeAttestation(r, h.cfg.NativeAppSecretKey, h.cfg.NativeAppID, challengeID); err != nil {
		logger.FromContext(r.Context()).Warn("Native request signature verification failed", "error", err)
		writeError(w, http.StatusUnauthorized, "ATTESTATION_FAILED", "Native authentication verification failed")
		return false
	}
	return true
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

func (h *AuthHandlers) ListPasskeyCredentials(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserID(r.Context())
	if userID == uuid.Nil {
		writeError(w, http.StatusUnauthorized, "UNAUTHENTICATED", "Active session required")
		return
	}

	creds, err := h.authUC.ListCredentials(r.Context(), userID)
	if err != nil {
		writeOperationError(w, r, http.StatusInternalServerError, "INTERNAL", "Failed to list credentials", err)
		return
	}

	writeJSON(w, http.StatusOK, ToCredentialListResponse(creds))
}

func (h *AuthHandlers) RevokeSession(w http.ResponseWriter, r *http.Request) {
	var token string
	if cookie, err := r.Cookie(HostSessionCookieName); err == nil && cookie.Value != "" {
		token = cookie.Value
	} else if cookie, err := r.Cookie(DevSessionCookieName); err == nil && cookie.Value != "" {
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

	ClearSessionCookie(w, r)
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

	ClearSessionCookie(w, r)
	writeJSON(w, http.StatusOK, StatusResponse{Status: "all_sessions_revoked"})
}

func (h *AuthHandlers) applySessionCookie(w http.ResponseWriter, r *http.Request, token string) {
	SetSessionCookie(w, r, token, h.cfg.SessionTTL, h.cfg)
}
