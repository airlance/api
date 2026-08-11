package http

import (
	"context"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/airlance/api/internal/config"
	"github.com/airlance/api/internal/usecase"
)

type Server struct {
	server *http.Server
}

func NewServer(cfg *config.Config, githubUC *usecase.GithubAuthUseCase) *Server {
	r := chi.NewRouter()

	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(60 * time.Second))

	handler := NewOAuthHandler(githubUC, cfg.Github)

	r.Route("/auth/github", func(r chi.Router) {
		r.Get("/start", handler.HandleStart)
		r.Get("/callback", handler.HandleCallback)
	})

	srv := &http.Server{
		Addr:         cfg.HTTP.Addr,
		Handler:      r,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	return &Server{server: srv}
}

func (s *Server) Start() error {
	if err := s.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

func (s *Server) Shutdown(ctx context.Context) error {
	return s.server.Shutdown(ctx)
}
