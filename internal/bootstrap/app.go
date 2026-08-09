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
	"github.com/airlance/api/internal/infrastructure/githuboauth"
	"github.com/airlance/api/internal/infrastructure/logger"
	"github.com/airlance/api/internal/infrastructure/persistence/postgres"
	redisinfra "github.com/airlance/api/internal/infrastructure/redis"
	grpctransport "github.com/airlance/api/internal/transport/grpc"
	grpcinterceptor "github.com/airlance/api/internal/transport/grpc/interceptor"
	httptransport "github.com/airlance/api/internal/transport/http"
	authusecase "github.com/airlance/api/internal/usecase/auth"
	qrloginusecase "github.com/airlance/api/internal/usecase/qrlogin"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
)

const shutdownTimeout = 10 * time.Second

type AuthUseCases struct {
	LoginByGithub    *authusecase.LoginByGithubUseCase
	ResumeSession    *authusecase.ResumeSessionUseCase
	TerminateSession *authusecase.TerminateSessionUseCase
	ListSessions     *authusecase.ListSessionsUseCase
	KillSession      *authusecase.KillSessionUseCase

	GenerateQRLogin *qrloginusecase.GenerateQRLoginUseCase
	ScanQRLogin     *qrloginusecase.ScanQRLoginUseCase
	ConfirmQRLogin  *qrloginusecase.ConfirmQRLoginUseCase
	RejectQRLogin   *qrloginusecase.RejectQRLoginUseCase
}

type App struct {
	Config     *config.Config
	DB         *pgxpool.Pool
	Redis      *redis.Client
	Auth       *AuthUseCases
	httpServer *httptransport.Server
	grpcServer *grpctransport.Server
}

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

	redisClient, err := redisinfra.NewClient(ctx, cfg.Redis.Addr)
	if err != nil {
		pool.Close()
		return nil, fmt.Errorf("failed to connect to redis: %w", err)
	}
	logger.Log.Info("redis connection established")

	auth := wireAuthUseCases(cfg, pool, redisClient)

	sessionValidator := grpcinterceptor.NewSessionValidator(
		postgres.NewSessionRepo(pool),
		redisinfra.NewSessionCache(redisClient),
	)

	httpSrv := httptransport.NewServer(fmt.Sprintf(":%s", cfg.Http.Port), cfg.Auth.AppCallbackURL)

	grpcSrv, err := grpctransport.NewServer(cfg, sessionValidator)
	if err != nil {
		pool.Close()
		_ = redisClient.Close()
		return nil, fmt.Errorf("failed to initialize gRPC server: %w", err)
	}

	return &App{
		Config:     cfg,
		DB:         pool,
		Redis:      redisClient,
		Auth:       auth,
		httpServer: httpSrv,
		grpcServer: grpcSrv,
	}, nil
}

func wireAuthUseCases(cfg *config.Config, pool *pgxpool.Pool, redisClient *redis.Client) *AuthUseCases {
	txManager := postgres.NewTxManager(pool)

	users := postgres.NewUserRepo(pool)
	identities := postgres.NewAuthIdentityRepo(pool)
	devices := postgres.NewUserDeviceRepo(pool)
	sessions := postgres.NewSessionRepo(pool)
	sessionCache := redisinfra.NewSessionCache(redisClient)

	qrStore := redisinfra.NewQRLoginStore(redisClient)

	_ = githuboauth.NewClient(githuboauth.Config{
		ClientID:     cfg.Auth.GithubClientID,
		ClientSecret: cfg.Auth.GithubClientSecret,
		RedirectURI:  cfg.Auth.GithubRedirectURI,
	})

	return &AuthUseCases{
		LoginByGithub:    authusecase.NewLoginByGithubUseCase(txManager, users, identities, devices, sessions, sessionCache),
		ResumeSession:    authusecase.NewResumeSessionUseCase(users, sessions, sessionCache),
		TerminateSession: authusecase.NewTerminateSessionUseCase(sessions, sessionCache),
		ListSessions:     authusecase.NewListSessionsUseCase(sessions),
		KillSession:      authusecase.NewKillSessionUseCase(sessions, sessionCache),

		GenerateQRLogin: qrloginusecase.NewGenerateQRLoginUseCase(qrStore, cfg.Auth.ServerInstanceID),
		ScanQRLogin:     qrloginusecase.NewScanQRLoginUseCase(qrStore),
		ConfirmQRLogin:  qrloginusecase.NewConfirmQRLoginUseCase(qrStore, identities, devices, sessions, sessionCache, users, txManager),
		RejectQRLogin:   qrloginusecase.NewRejectQRLoginUseCase(qrStore),
	}
}

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
