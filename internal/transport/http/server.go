package http

import (
	"context"
	"net/http"
	"time"

	"github.com/airlance/api/internal/infrastructure/contextx"
	"github.com/airlance/api/internal/infrastructure/logger"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

// Server wraps a chi-based HTTP server.
type Server struct {
	httpServer *http.Server
}

// NewServer builds the HTTP server with routing and middleware. Additional
// route groups (usecases) can be mounted onto the returned chi router
// before Start is called, by extending newRouter.
//
// appCallbackURL is the custom-scheme URL the GitHub OAuth callback
// redirects to (see github_callback.go) — GitHub can only redirect to an
// https:// URL, so this HTTP server is the bridge back to the native app.
func NewServer(addr string, appCallbackURL string) *Server {
	router := newRouter(appCallbackURL)

	return &Server{
		httpServer: &http.Server{
			Addr:              addr,
			Handler:           router,
			ReadHeaderTimeout: 5 * time.Second,
		},
	}
}

func newRouter(appCallbackURL string) http.Handler {
	r := chi.NewRouter()

	r.Use(middleware.RequestID)
	r.Use(requestLogger)
	r.Use(middleware.Recoverer)

	r.Get("/health", healthHandler)
	r.Get("/auth/github/callback", newGithubCallbackHandler(appCallbackURL).ServeHTTP)

	return r
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}

// requestLogger bridges chi's request-scoped request ID into the shared
// logrus-based logger, so HTTP, gRPC and CLI all go through logger.FromContext.
func requestLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqID := middleware.GetReqID(r.Context())
		ctx := contextx.SetRequestID(r.Context(), reqID)
		r = r.WithContext(ctx)

		entry := logger.FromContext(ctx)
		start := time.Now()

		next.ServeHTTP(w, r)

		entry.WithFields(map[string]interface{}{
			"method":   r.Method,
			"path":     r.URL.Path,
			"duration": time.Since(start).String(),
		}).Info("http request handled")
	})
}

// Start begins serving. It blocks until the server stops or errors.
func (s *Server) Start() error {
	err := s.httpServer.ListenAndServe()
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}

// Shutdown gracefully stops the server.
func (s *Server) Shutdown(ctx context.Context) error {
	return s.httpServer.Shutdown(ctx)
}
