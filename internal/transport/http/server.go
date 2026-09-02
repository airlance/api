package http

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"airlance.org/api/internal/config"
	domainRL "airlance.org/api/internal/domain/ratelimit"
	"airlance.org/api/internal/infrastructure/logger"
	"airlance.org/api/internal/middleware"
	v1 "airlance.org/api/internal/transport/http/v1"
	"airlance.org/api/internal/transport/ws"
	sessionUC "airlance.org/api/internal/usecase/session"
)

// Server encapsulates the HTTP multiplexer, middlewares, and server lifecycle.
type Server struct {
	httpServer     *http.Server
	healthHandlers *HealthHandlers
	authHandlers   *v1.AuthHandlers
	ticketHandlers *v1.TicketHandlers
	clientHandlers *v1.ClientHandlers
	meHandlers     *v1.MeHandlers
	wsServer       *ws.Server
	sessionUC      *sessionUC.Usecase
	limiter        domainRL.Limiter
	cfg            *config.Config
	log            *logger.Logger
}

// NewServer constructs the HTTP Server.
func NewServer(
	healthHandlers *HealthHandlers,
	authHandlers *v1.AuthHandlers,
	ticketHandlers *v1.TicketHandlers,
	clientHandlers *v1.ClientHandlers,
	meHandlers *v1.MeHandlers,
	wsServer *ws.Server,
	sessionUC *sessionUC.Usecase,
	limiter domainRL.Limiter,
	cfg *config.Config,
	log *logger.Logger,
) *Server {
	s := &Server{
		healthHandlers: healthHandlers,
		authHandlers:   authHandlers,
		ticketHandlers: ticketHandlers,
		clientHandlers: clientHandlers,
		meHandlers:     meHandlers,
		wsServer:       wsServer,
		sessionUC:      sessionUC,
		limiter:        limiter,
		cfg:            cfg,
		log:            log.Named(logger.CategoryApp),
	}

	handler := s.buildRoutes()
	s.httpServer = &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.HTTPPort),
		Handler:      handler,
		ReadTimeout:  cfg.HTTPReadTimeout,
		WriteTimeout: cfg.HTTPWriteTimeout,
		IdleTimeout:  cfg.HTTPIdleTimeout,
	}

	return s
}

// Handler returns the underlying http.Handler.
func (s *Server) Handler() http.Handler {
	return s.httpServer.Handler
}

// Start begins listening and serving HTTP requests.
func (s *Server) Start() error {
	s.log.Info("Starting HTTP server", "port", s.cfg.HTTPPort)
	if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("http server start error: %w", err)
	}
	return nil
}

// Shutdown gracefully terminates the HTTP server.
func (s *Server) Shutdown(ctx context.Context) error {
	s.log.Info("Shutting down HTTP server")
	return s.httpServer.Shutdown(ctx)
}

func (s *Server) buildRoutes() http.Handler {
	mux := http.NewServeMux()

	// 1. Health Probes
	mux.HandleFunc("GET /healthz", s.healthHandlers.Healthz)
	mux.HandleFunc("GET /livez", s.healthHandlers.Livez)
	mux.HandleFunc("GET /readyz", s.healthHandlers.Readyz)

	// 2. WebSocket endpoint
	if s.wsServer != nil {
		mux.HandleFunc("/ws", s.wsServer.ServeHTTP)
	}

	// 3. Middlewares
	sessionAuth := middleware.SessionMiddleware(s.sessionUC, s.cfg.WebAuthnRPOrigins)
	jwtAuth := middleware.JWTMiddleware(s.cfg.JWTKeyRing)

	// Rate limiters
	authLimiter := middleware.RateLimitMiddleware(middleware.RateLimitConfig{
		Limiter:        s.limiter,
		KeyExtractor:   middleware.IPKeyExtractor("auth_ip"),
		LimitsProvider: middleware.FixedLimits(domainRL.Limit{Name: "auth_minute", Max: 20, Window: time.Minute}),
		FailClosed:     true,
	})

	apiRateLimiter := middleware.RateLimitMiddleware(middleware.RateLimitConfig{
		Limiter:        s.limiter,
		KeyExtractor:   middleware.APIClientKeyExtractor,
		LimitsProvider: middleware.APIClientLimitsProvider,
		FailClosed:     false, // General API traffic fails open on Redis outage
	})

	// 4. Passkey Auth routes
	mux.Handle("POST /api/v1/auth/passkey/signup/options", authLimiter(http.HandlerFunc(s.authHandlers.PasskeySignupOptions)))
	mux.Handle("POST /api/v1/auth/passkey/signup/verify", authLimiter(http.HandlerFunc(s.authHandlers.PasskeySignupVerify)))
	mux.Handle("POST /api/v1/auth/passkey/login/options", authLimiter(http.HandlerFunc(s.authHandlers.PasskeyLoginOptions)))
	mux.Handle("POST /api/v1/auth/passkey/login/verify", authLimiter(http.HandlerFunc(s.authHandlers.PasskeyLoginVerify)))

	// Passkey credential management (session-protected)
	mux.Handle("POST /api/v1/auth/passkey/register/options", sessionAuth(http.HandlerFunc(s.authHandlers.PasskeyRegisterOptions)))
	mux.Handle("POST /api/v1/auth/passkey/register/verify", sessionAuth(http.HandlerFunc(s.authHandlers.PasskeyRegisterVerify)))
	mux.Handle("DELETE /api/v1/auth/passkey/", sessionAuth(http.HandlerFunc(s.authHandlers.DeletePasskeyCredential)))

	// 5. WebSocket Ticket Issuance (session-protected)
	ticketRateLimiter := middleware.RateLimitMiddleware(middleware.RateLimitConfig{
		Limiter: s.limiter,
		KeyExtractor: func(r *http.Request) string {
			return fmt.Sprintf("ws_ticket:user:%s", middleware.GetUserID(r.Context()).String())
		},
		LimitsProvider: middleware.FixedLimits(domainRL.Limit{Name: "ticket_min", Max: 30, Window: time.Minute}),
		FailClosed:     true,
	})
	mux.Handle("POST /api/v1/ws/ticket", sessionAuth(ticketRateLimiter(http.HandlerFunc(s.ticketHandlers.IssueTicket))))

	// 6. External API Clients & Tokens
	mux.Handle("POST /api/v1/clients", sessionAuth(http.HandlerFunc(s.clientHandlers.CreateClient)))
	mux.Handle("GET /api/v1/clients", sessionAuth(http.HandlerFunc(s.clientHandlers.ListClients)))
	mux.Handle("DELETE /api/v1/clients/", sessionAuth(http.HandlerFunc(s.clientHandlers.RevokeClient)))
	mux.Handle("POST /api/v1/auth/token", authLimiter(http.HandlerFunc(s.clientHandlers.IssueToken)))

	// 7. Protected External API: /getMe
	mux.Handle("GET /api/v1/getMe", jwtAuth(apiRateLimiter(http.HandlerFunc(s.meHandlers.GetMe))))

	// Wrap global middleware chain
	var handler http.Handler = mux
	handler = s.requestLoggerMiddleware(handler)
	handler = middleware.ClientIPMiddleware(s.cfg.TrustedProxies)(handler)
	handler = s.maxBodyBytesMiddleware(handler)

	return handler
}

func (s *Server) maxBodyBytesMiddleware(next http.Handler) http.Handler {
	maxBytes := s.cfg.MaxHTTPBodyBytes
	if maxBytes <= 0 {
		maxBytes = 2 * 1024 * 1024
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
		next.ServeHTTP(w, r)
	})
}

func (s *Server) requestLoggerMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqID := r.Header.Get("X-Request-ID")
		if reqID == "" {
			reqID = uuid.New().String()
		}
		w.Header().Set("X-Request-ID", reqID)

		ctx := s.log.WithField("request_id", reqID).WithContext(r.Context())

		// Skip high-frequency health probes logging at info level
		if strings.HasPrefix(r.URL.Path, "/livez") || strings.HasPrefix(r.URL.Path, "/readyz") {
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}

		start := time.Now()
		next.ServeHTTP(w, r.WithContext(ctx))
		duration := time.Since(start)

		s.log.Debug("HTTP request completed",
			"method", r.Method,
			"path", r.URL.Path,
			"duration_ms", duration.Milliseconds(),
			"request_id", reqID,
		)
	})
}
