package v1

import (
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"

	domainRL "airlance.org/api/internal/domain/ratelimit"
	"airlance.org/api/internal/middleware"
)

type MeHandlers struct {
	limiter domainRL.Limiter
}

func NewMeHandlers(limiter domainRL.Limiter) *MeHandlers {
	return &MeHandlers{limiter: limiter}
}

func (h *MeHandlers) GetMe(w http.ResponseWriter, r *http.Request) {
	clientID := middleware.GetAPIClientID(r.Context())
	userID := middleware.GetUserID(r.Context())
	claims, hasClaims := middleware.GetAPIClaims(r.Context())

	if clientID == uuid.Nil || userID == uuid.Nil || !hasClaims {
		writeError(w, http.StatusUnauthorized, "UNAUTHENTICATED", "Valid API token required")
		return
	}

	limits := middleware.APIClientLimitsProvider(r)
	rateLimitsMap := make(map[string]RateLimitUsageDTO)

	if h.limiter != nil && len(limits) > 0 {
		usageKey := fmt.Sprintf("client:%s", clientID.String())
		results, err := h.limiter.Usage(r.Context(), usageKey, limits)
		if err == nil && len(results) == len(limits) {
			for i, lim := range limits {
				res := results[i]
				rateLimitsMap[lim.Name] = RateLimitUsageDTO{
					Limit:     lim.Max,
					Remaining: res.Remaining,
					ResetAt:   res.ResetAt.UTC().Format(time.RFC3339),
					WindowSec: int(lim.Window.Seconds()),
				}
			}
		}
	}

	if len(rateLimitsMap) == 0 {
		rateLimitsMap["per_minute"] = RateLimitUsageDTO{
			Limit:     int64(claims.RequestsPerMinute),
			Remaining: int64(claims.RequestsPerMinute),
		}
		rateLimitsMap["per_day"] = RateLimitUsageDTO{
			Limit:     int64(claims.RequestsPerDay),
			Remaining: int64(claims.RequestsPerDay),
		}
	}

	writeJSON(w, http.StatusOK, MeResponse{
		UserID:     userID.String(),
		ClientID:   clientID.String(),
		RateLimits: rateLimitsMap,
	})
}
