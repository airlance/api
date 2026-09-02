package bootstrap

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"airlance.org/api/internal/config"
	transportHTTP "airlance.org/api/internal/transport/http"
)

// App represents the booted service application.
type App struct {
	Cfg          *config.Config
	Infra        *Infrastructures
	Repositories *Repositories
	Services     *Services
	Handlers     *Handlers
	HTTPServer   *transportHTTP.Server
}

// BuildApp initializes all layers of the application without starting listeners.
func BuildApp(ctx context.Context, cfg *config.Config) (*App, error) {
	infra, err := InitInfrastructures(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("app: init infrastructures failed: %w", err)
	}

	repos := InitRepositories(infra)
	services := InitServices(cfg, infra, repos)
	handlers := InitHandlers(cfg, infra, repos, services)
	httpServer := InitHTTPServer(cfg, infra, services, handlers)

	return &App{
		Cfg:          cfg,
		Infra:        infra,
		Repositories: repos,
		Services:     services,
		Handlers:     handlers,
		HTTPServer:   httpServer,
	}, nil
}

// Run executes the server and blocks until SIGINT or SIGTERM is caught, performing graceful shutdown.
func (a *App) Run() error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start WebSocket EventBus listeners
	if err := a.Handlers.WSServer.StartEventBusListeners(ctx); err != nil {
		a.Infra.Logger.Error(err, "Failed to start WS eventbus listeners")
	}

	// Channel to catch termination signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	serverErr := make(chan error, 1)
	go func() {
		serverErr <- a.HTTPServer.Start()
	}()

	select {
	case err := <-serverErr:
		return err
	case sig := <-sigChan:
		a.Infra.Logger.Info("Received shutdown signal", "signal", sig.String())
	}

	// Perform graceful drain & shutdown
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer shutdownCancel()

	// 1. Drain and close active WebSocket sessions gracefully
	if a.Handlers.WSServer != nil {
		_ = a.Handlers.WSServer.Shutdown(shutdownCtx)
	}

	// 2. Shutdown HTTP server
	if err := a.HTTPServer.Shutdown(shutdownCtx); err != nil {
		a.Infra.Logger.Error(err, "HTTP server graceful shutdown error")
	}

	// 3. Close database and Redis pools
	a.Infra.Close()
	a.Infra.Logger.Info("Application terminated cleanly")

	return nil
}
