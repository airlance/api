package v1

import (
	"net/http"
	"time"

	"airlance.org/api/internal/config"
	"airlance.org/api/internal/domain/wsticket"
	"airlance.org/api/internal/infrastructure/crypto"
	"airlance.org/api/internal/middleware"
)

// TicketHandlers provides WebSocket ticket issuance endpoints.
type TicketHandlers struct {
	ticketRepo wsticket.Repository
	cfg        *config.Config
}

// NewTicketHandlers constructs TicketHandlers.
func NewTicketHandlers(ticketRepo wsticket.Repository, cfg *config.Config) *TicketHandlers {
	return &TicketHandlers{
		ticketRepo: ticketRepo,
		cfg:        cfg,
	}
}

// IssueTicket handles POST /api/v1/ws/ticket (session-protected).
func (h *TicketHandlers) IssueTicket(w http.ResponseWriter, r *http.Request) {
	sess := middleware.GetSession(r.Context())
	if sess == nil {
		writeError(w, http.StatusUnauthorized, "UNAUTHENTICATED", "Active session required")
		return
	}

	ticketID, _, err := crypto.GenerateOpaqueToken(32)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL", "Failed to generate ticket")
		return
	}

	now := time.Now()
	ticket := &wsticket.Ticket{
		ID:        ticketID,
		UserID:    sess.UserID,
		SessionID: sess.ID,
		DeviceID:  sess.DeviceID,
		ExpiresAt: now.Add(h.cfg.WSTicketTTL),
	}

	if err := h.ticketRepo.Create(r.Context(), ticket, h.cfg.WSTicketTTL); err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL", "Failed to store ticket")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ticket":     ticketID,
		"expires_at": ticket.ExpiresAt.UTC().Format(time.RFC3339),
		"ttl_sec":    int(h.cfg.WSTicketTTL.Seconds()),
	})
}
