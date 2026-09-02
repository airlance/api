package http

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"

	"airlance.org/api/internal/config"
	domainRL "airlance.org/api/internal/domain/ratelimit"
	"airlance.org/api/internal/infrastructure/logger"
	"airlance.org/api/internal/infrastructure/metrics"
	"airlance.org/api/internal/middleware"
	v1 "airlance.org/api/internal/transport/http/v1"
	"airlance.org/api/internal/transport/ws"
	sessionUC "airlance.org/api/internal/usecase/session"
)

// Server encapsulates the HTTP multiplexer, middlewares, and server lifecycle.
type Server struct {
	httpServer      *http.Server
	healthHandlers  *HealthHandlers
	authHandlers    *v1.AuthHandlers
	deviceHandlers  *v1.DeviceHandlers
	ticketHandlers  *v1.TicketHandlers
	clientHandlers  *v1.ClientHandlers
	meHandlers      *v1.MeHandlers
	wsServer        *ws.Server
	sessionUC       *sessionUC.Usecase
	limiter         domainRL.Limiter
	metricsRegistry *metrics.Registry
	cfg             *config.Config
	log             *logger.Logger
}

// NewServer constructs the HTTP Server.
func NewServer(
	healthHandlers *HealthHandlers,
	authHandlers *v1.AuthHandlers,
	deviceHandlers *v1.DeviceHandlers,
	ticketHandlers *v1.TicketHandlers,
	clientHandlers *v1.ClientHandlers,
	meHandlers *v1.MeHandlers,
	wsServer *ws.Server,
	sessionUC *sessionUC.Usecase,
	limiter domainRL.Limiter,
	metricsRegistry *metrics.Registry,
	cfg *config.Config,
	log *logger.Logger,
) *Server {
	if metricsRegistry == nil {
		metricsRegistry = metrics.NewRegistry()
	}

	s := &Server{
		healthHandlers:  healthHandlers,
		authHandlers:    authHandlers,
		deviceHandlers:  deviceHandlers,
		ticketHandlers:  ticketHandlers,
		clientHandlers:  clientHandlers,
		meHandlers:      meHandlers,
		wsServer:        wsServer,
		sessionUC:       sessionUC,
		limiter:         limiter,
		metricsRegistry: metricsRegistry,
		cfg:             cfg,
		log:             log.Named(logger.CategoryApp),
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
	s.log.Info("Starting HTTP server", "port", s.cfg.HTTPPort, "tls_enabled", s.cfg.TLSListenerEnabled)

	if s.cfg.RequireTLS {
		hasLocalTLS := s.cfg.TLSListenerEnabled && s.cfg.TLSCertFile != "" && s.cfg.TLSKeyFile != ""
		hasExplicitIngress := s.cfg.TLSTerminationIngress && len(s.cfg.TrustedProxies) > 0
		if !hasLocalTLS && !hasExplicitIngress {
			return fmt.Errorf("http server start error: REQUIRE_TLS=true requires either local TLS cert/key (TLS_LISTENER_ENABLED, TLS_CERT_FILE, TLS_KEY_FILE) or explicit TLS_TERMINATION_INGRESS=true with TRUSTED_PROXIES")
		}
	}

	if s.cfg.TLSListenerEnabled && s.cfg.TLSCertFile != "" && s.cfg.TLSKeyFile != "" {
		if err := s.httpServer.ListenAndServeTLS(s.cfg.TLSCertFile, s.cfg.TLSKeyFile); err != nil && err != http.ErrServerClosed {
			return fmt.Errorf("http server start TLS error: %w", err)
		}
		return nil
	}
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

	// 2. Metrics Probe
	mux.Handle("GET /metrics", s.metricsAccessMiddleware(s.metricsRegistry.Handler()))

	// 3. WebSocket endpoint
	if s.wsServer != nil {
		mux.HandleFunc("/ws", s.wsServer.ServeHTTP)
	}

	// 4. Middlewares
	sessionAuth := middleware.SessionMiddleware(s.sessionUC, s.cfg.WebAuthnRPOrigins)
	jwtAuth := middleware.JWTMiddleware(s.cfg.JWTKeyRing, s.cfg.ServiceName)

	maskSecret := s.cfg.AuditSubjectHMACKeyRing.Keys[s.cfg.AuditSubjectHMACKeyRing.CurrentKeyID]

	// Rate limiters
	authLimiter := middleware.RateLimitMiddleware(middleware.RateLimitConfig{
		Limiter:        s.limiter,
		KeyExtractor:   middleware.IPKeyExtractor("auth_ip"),
		LimitsProvider: middleware.FixedLimits(domainRL.Limit{Name: "auth_minute", Max: 20, Window: time.Minute}),
		MaskSecret:     maskSecret,
		FailClosed:     true,
	})

	apiRateLimiter := middleware.RateLimitMiddleware(middleware.RateLimitConfig{
		Limiter:        s.limiter,
		KeyExtractor:   middleware.APIClientKeyExtractor,
		LimitsProvider: middleware.APIClientLimitsProvider,
		MaskSecret:     maskSecret,
		FailClosed:     false, // General API traffic fails open on Redis outage
	})

	// 5. Passkey Auth routes
	mux.Handle("POST /api/v1/auth/passkey/signup/options", authLimiter(http.HandlerFunc(s.authHandlers.PasskeySignupOptions)))
	mux.Handle("POST /api/v1/auth/passkey/signup/verify", authLimiter(http.HandlerFunc(s.authHandlers.PasskeySignupVerify)))
	mux.Handle("POST /api/v1/auth/passkey/login/options", authLimiter(http.HandlerFunc(s.authHandlers.PasskeyLoginOptions)))
	mux.Handle("POST /api/v1/auth/passkey/login/verify", authLimiter(http.HandlerFunc(s.authHandlers.PasskeyLoginVerify)))

	// Passkey credential management (session-protected)
	mux.Handle("POST /api/v1/auth/passkey/register/options", sessionAuth(http.HandlerFunc(s.authHandlers.PasskeyRegisterOptions)))
	mux.Handle("POST /api/v1/auth/passkey/register/verify", sessionAuth(http.HandlerFunc(s.authHandlers.PasskeyRegisterVerify)))
	mux.Handle("DELETE /api/v1/auth/passkey/", sessionAuth(http.HandlerFunc(s.authHandlers.DeletePasskeyCredential)))

	// Session Revocation routes (session-protected)
	mux.Handle("POST /api/v1/auth/session/revoke", sessionAuth(http.HandlerFunc(s.authHandlers.RevokeSession)))
	mux.Handle("POST /api/v1/auth/sessions/revoke-all", sessionAuth(http.HandlerFunc(s.authHandlers.RevokeAllSessions)))

	// Device Management routes (session-protected)
	if s.deviceHandlers != nil {
		mux.Handle("GET /api/v1/devices", sessionAuth(http.HandlerFunc(s.deviceHandlers.ListDevices)))
		mux.Handle("DELETE /api/v1/devices/", sessionAuth(http.HandlerFunc(s.deviceHandlers.RevokeDevice)))
	}

	// 6. WebSocket Ticket Issuance (session-protected)
	ticketRateLimiter := middleware.RateLimitMiddleware(middleware.RateLimitConfig{
		Limiter: s.limiter,
		KeyExtractor: func(r *http.Request) string {
			return fmt.Sprintf("ws_ticket:user:%s", middleware.GetUserID(r.Context()).String())
		},
		LimitsProvider: middleware.FixedLimits(domainRL.Limit{Name: "ticket_min", Max: 30, Window: time.Minute}),
		MaskSecret:     maskSecret,
		FailClosed:     true,
	})
	mux.Handle("POST /api/v1/ws/ticket", sessionAuth(ticketRateLimiter(http.HandlerFunc(s.ticketHandlers.IssueTicket))))

	// 7. External API Clients & Tokens
	mux.Handle("POST /api/v1/clients", sessionAuth(http.HandlerFunc(s.clientHandlers.CreateClient)))
	mux.Handle("GET /api/v1/clients", sessionAuth(http.HandlerFunc(s.clientHandlers.ListClients)))
	mux.Handle("DELETE /api/v1/clients/", sessionAuth(http.HandlerFunc(s.clientHandlers.RevokeClient)))
	mux.Handle("POST /api/v1/auth/token", authLimiter(http.HandlerFunc(s.clientHandlers.IssueToken)))

	// 8. Protected External API: /getMe
	mux.Handle("GET /api/v1/getMe", jwtAuth(apiRateLimiter(http.HandlerFunc(s.meHandlers.GetMe))))

	// Wrap global middleware chain
	var handler http.Handler = mux
	handler = s.requestLoggerMiddleware(handler)
	handler = middleware.ClientIPMiddleware(s.cfg.TrustedProxies)(handler)
	handler = s.maxBodyBytesMiddleware(handler)

	return handler
}

func (s *Server) metricsAccessMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if middleware.IsIPInCIDRs(middleware.GetClientIP(r.Context()), s.cfg.MetricsAllowedCIDRs) {
			next.ServeHTTP(w, r)
			return
		}
		writeMetricsAccessDenied(w)
	})
}

func writeMetricsAccessDenied(w http.ResponseWriter) {
	http.Error(w, "metrics access denied", http.StatusForbidden)
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

type statusResponseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (w *statusResponseWriter) WriteHeader(code int) {
	w.statusCode = code
	w.ResponseWriter.WriteHeader(code)
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
		if strings.HasPrefix(r.URL.Path, "/livez") || strings.HasPrefix(r.URL.Path, "/readyz") || strings.HasPrefix(r.URL.Path, "/metrics") {
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}

		sw := &statusResponseWriter{ResponseWriter: w, statusCode: http.StatusOK}
		start := time.Now()
		next.ServeHTTP(sw, r.WithContext(ctx))
		duration := time.Since(start)

		sanitizedURL := sanitizeURL(r.URL)

		s.log.Info("HTTP request completed",
			"method", r.Method,
			"path", sanitizedURL,
			"status", sw.statusCode,
			"duration_ms", duration.Milliseconds(),
			"request_id", reqID,
		)

		s.metricsRegistry.IncHTTPRequests(r.Method, r.URL.Path, sw.statusCode)
	})
}

func sanitizeURL(u *url.URL) string {
	if u == nil {
		return ""
	}
	if u.RawQuery == "" {
		return u.Path
	}
	q := u.Query()
	for key := range q {
		lower := strings.ToLower(key)
		if lower == "ticket" || lower == "token" || lower == "secret" || lower == "key" || lower == "challenge_id" {
			q.Set(key, "[REDACTED]")
		}
	}
	return u.Path + "?" + q.Encode()
}
