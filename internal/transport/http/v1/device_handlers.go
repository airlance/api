package v1

import (
	"net/http"
	"strings"

	"github.com/google/uuid"

	"airlance.org/api/internal/middleware"
	"airlance.org/api/internal/usecase/auth"
)

// DeviceHandlers handles device listing and revocation endpoints.
type DeviceHandlers struct {
	authUC *auth.Usecase
}

// NewDeviceHandlers constructs DeviceHandlers.
func NewDeviceHandlers(authUC *auth.Usecase) *DeviceHandlers {
	return &DeviceHandlers{authUC: authUC}
}

// ListDevices handles GET /api/v1/devices.
func (h *DeviceHandlers) ListDevices(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserID(r.Context())
	if userID == uuid.Nil {
		writeError(w, http.StatusUnauthorized, "UNAUTHENTICATED", "Active session required")
		return
	}

	devices, err := h.authUC.ListDevices(r.Context(), userID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL", err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"devices": devices})
}

// RevokeDevice handles DELETE /api/v1/devices/{id}.
func (h *DeviceHandlers) RevokeDevice(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserID(r.Context())
	if userID == uuid.Nil {
		writeError(w, http.StatusUnauthorized, "UNAUTHENTICATED", "Active session required")
		return
	}

	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) == 0 {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "Device ID required")
		return
	}
	devIDStr := parts[len(parts)-1]
	deviceID, err := uuid.Parse(devIDStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "Invalid UUID device ID")
		return
	}

	ip := middleware.GetClientIP(r.Context())
	ua := r.UserAgent()
	reqID := r.Header.Get("X-Request-ID")

	if err := h.authUC.RevokeDevice(r.Context(), userID, deviceID, ip, ua, reqID); err != nil {
		writeError(w, http.StatusBadRequest, "REVOCATION_FAILED", err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"status":    "revoked",
		"device_id": deviceID.String(),
	})
}
