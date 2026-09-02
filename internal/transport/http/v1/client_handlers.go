package v1

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"airlance.org/api/internal/middleware"
	"airlance.org/api/internal/usecase/apiauth"
)

type ClientHandlers struct {
	apiAuthUC *apiauth.Usecase
}

func NewClientHandlers(apiAuthUC *apiauth.Usecase) *ClientHandlers {
	return &ClientHandlers{apiAuthUC: apiAuthUC}
}

type createClientRequest struct {
	Name string `json:"name"`
}

func (h *ClientHandlers) CreateClient(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserID(r.Context())
	if userID == uuid.Nil {
		writeError(w, http.StatusUnauthorized, "UNAUTHENTICATED", "Active session required")
		return
	}

	var req createClientRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.Name) == "" {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "Valid client name required")
		return
	}

	ip := middleware.GetClientIP(r.Context())
	ua := r.UserAgent()
	reqID := r.Header.Get("X-Request-ID")

	res, err := h.apiAuthUC.CreateClient(r.Context(), userID, req.Name, ip, ua, reqID)
	if err != nil {
		writeOperationError(w, r, http.StatusBadRequest, "CREATE_FAILED", "Client creation failed", err)
		return
	}

	writeJSON(w, http.StatusCreated, res)
}

func (h *ClientHandlers) ListClients(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserID(r.Context())
	if userID == uuid.Nil {
		writeError(w, http.StatusUnauthorized, "UNAUTHENTICATED", "Active session required")
		return
	}

	clients, err := h.apiAuthUC.ListClients(r.Context(), userID)
	if err != nil {
		writeOperationError(w, r, http.StatusInternalServerError, "INTERNAL", "Unable to list clients", err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"clients": clients})
}

func (h *ClientHandlers) RevokeClient(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserID(r.Context())
	if userID == uuid.Nil {
		writeError(w, http.StatusUnauthorized, "UNAUTHENTICATED", "Active session required")
		return
	}

	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) == 0 {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "Client ID required")
		return
	}
	clientID, err := uuid.Parse(parts[len(parts)-1])
	if err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "Invalid UUID client ID")
		return
	}

	ip := middleware.GetClientIP(r.Context())
	ua := r.UserAgent()
	reqID := r.Header.Get("X-Request-ID")

	if err := h.apiAuthUC.RevokeClient(r.Context(), userID, clientID, ip, ua, reqID); err != nil {
		writeOperationError(w, r, http.StatusBadRequest, "REVOKE_FAILED", "Client revocation failed", err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"status": "revoked", "client_id": clientID.String()})
}

type issueTokenRequest struct {
	ClientID string `json:"client_id"`
	Secret   string `json:"secret"`
}

func (h *ClientHandlers) IssueToken(w http.ResponseWriter, r *http.Request) {
	var req issueTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "Malformed JSON body")
		return
	}

	clientID, err := uuid.Parse(req.ClientID)
	if err != nil || req.Secret == "" {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "Valid client_id and secret required")
		return
	}

	tokenStr, exp, err := h.apiAuthUC.IssueToken(r.Context(), clientID, req.Secret)
	if err != nil {
		writeOperationError(w, r, http.StatusUnauthorized, "INVALID_CREDENTIALS", "Invalid client credentials", err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": tokenStr,
		"token_type":   "Bearer",
		"expires_at":   exp.UTC().Format(time.RFC3339),
		"expires_in":   int(time.Until(exp).Seconds()),
	})
}
