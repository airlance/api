package v1

import (
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"

	domainRL "airlance.org/api/internal/domain/ratelimit"
	"airlance.org/api/internal/middleware"
)

// MeHandlers provides authenticated profile and rate limit inspection.
type MeHandlers struct {
	limiter domainRL.Limiter
}

// NewMeHandlers constructs MeHandlers.
func NewMeHandlers(limiter domainRL.Limiter) *MeHandlers {
	return &MeHandlers{limiter: limiter}
}

// GetMe handles GET /api/v1/getMe (JWT-authenticated).
func (h *MeHandlers) GetMe(w http.ResponseWriter, r *http.Request) {
	clientID := middleware.GetAPIClientID(r.Context())
	userID := middleware.GetUserID(r.Context())
	claims, hasClaims := middleware.GetAPIClaims(r.Context())

	if clientID == uuid.Nil || userID == uuid.Nil || !hasClaims {
		writeError(w, http.StatusUnauthorized, "UNAUTHENTICATED", "Valid API token required")
		return
	}

	limits := middleware.APIClientLimitsProvider(r)
	rateLimitsMap := make(map[string]any)

	if h.limiter != nil && len(limits) > 0 {
		usageKey := fmt.Sprintf("client:%s", clientID.String())
		results, err := h.limiter.Usage(r.Context(), usageKey, limits)
		if err == nil && len(results) == len(limits) {
			for i, lim := range limits {
				res := results[i]
				rateLimitsMap[lim.Name] = map[string]any{
					"limit":      lim.Max,
					"remaining":  res.Remaining,
					"reset_at":   res.ResetAt.UTC().Format(time.RFC3339),
					"window_sec": int(lim.Window.Seconds()),
				}
			}
		}
	}

	if len(rateLimitsMap) == 0 {
		rateLimitsMap["per_minute"] = map[string]any{
			"limit":     claims.RequestsPerMinute,
			"remaining": claims.RequestsPerMinute,
		}
		rateLimitsMap["per_day"] = map[string]any{
			"limit":     claims.RequestsPerDay,
			"remaining": claims.RequestsPerDay,
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"user_id":     userID.String(),
		"client_id":   clientID.String(),
		"rate_limits": rateLimitsMap,
	})
}
