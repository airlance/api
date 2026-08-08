package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/airlance/api/internal/config"
	"github.com/airlance/api/internal/infrastructure/database"
	"github.com/airlance/api/internal/infrastructure/logger"
	grpctransport "github.com/airlance/api/internal/transport/grpc"
	httptransport "github.com/airlance/api/internal/transport/http"
	"github.com/jackc/pgx/v5/pgxpool"
)

const shutdownTimeout = 10 * time.Second

// App owns every long-lived dependency (db pool, servers) and coordinates
// startup / graceful shutdown across HTTP and gRPC.
type App struct {
	Config *config.Config

	DB *pgxpool.Pool

	httpServer *httptransport.Server
	grpcServer *grpctransport.Server
}

// NewApplication wires the logger, database pool and transports together.
// It does not start listening — call Run for that.
func NewApplication(cfg *config.Config) (*App, error) {
	if err := logger.Init(cfg); err != nil {
		return nil, fmt.Errorf("failed to initialize logger: %w", err)
	}
	logger.Log.Info("env and logger were loaded successfully")

	ctx := context.Background()

	pool, err := database.NewPostgresPool(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}
	logger.Log.Info("database connection established")

	httpSrv := httptransport.NewServer(fmt.Sprintf(":%s", cfg.Http.Port))

	grpcSrv, err := grpctransport.NewServer(cfg)
	if err != nil {
		pool.Close()
		return nil, fmt.Errorf("failed to initialize gRPC server: %w", err)
	}

	return &App{
		Config:     cfg,
		DB:         pool,
		httpServer: httpSrv,
		grpcServer: grpcSrv,
	}, nil
}

// Run starts HTTP and gRPC servers concurrently and blocks until either
// one fails or the process receives a termination signal, at which point
// everything is shut down gracefully.
func (a *App) Run() error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 2)

	go func() {
		logger.Log.WithField("addr", a.Config.Http.Port).Info("http server starting")
		if err := a.httpServer.Start(); err != nil {
			errCh <- fmt.Errorf("http server: %w", err)
		}
	}()

	go func() {
		logger.Log.WithField("addr", a.Config.Grpc.Port).Info("grpc server starting")
		if err := a.grpcServer.Start(); err != nil {
			errCh <- fmt.Errorf("grpc server: %w", err)
		}
	}()

	var runErr error
	select {
	case <-ctx.Done():
		logger.Log.Info("shutdown signal received")
	case err := <-errCh:
		runErr = err
		logger.Log.WithError(err).Error("server failed, shutting down")
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()

	if err := a.httpServer.Shutdown(shutdownCtx); err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Log.WithError(err).Error("http server shutdown error")
	}
	if err := a.grpcServer.Shutdown(shutdownCtx); err != nil {
		logger.Log.WithError(err).Error("grpc server shutdown error")
	}

	a.DB.Close()
	logger.Log.Info("shutdown complete")

	return runErr
}
