// Package bootstrap manages staged dependency wiring, service bootstrap, and graceful shutdown.
package bootstrap

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	goredis "github.com/redis/go-redis/v9"
	"github.com/resoul/wireauth/v2"

	"airlance.org/api/internal/config"
	domainEB "airlance.org/api/internal/domain/eventbus"
	domainRL "airlance.org/api/internal/domain/ratelimit"
	"airlance.org/api/internal/domain/tx"
	"airlance.org/api/internal/infrastructure/database"
	"airlance.org/api/internal/infrastructure/eventbus"
	"airlance.org/api/internal/infrastructure/logger"
	"airlance.org/api/internal/infrastructure/metrics"
	"airlance.org/api/internal/infrastructure/ratelimit"
	"airlance.org/api/internal/infrastructure/webauthn"
)

// Infrastructures holds initialized infrastructure clients and engines.
type Infrastructures struct {
	DBPool         *pgxpool.Pool
	RedisClient    *goredis.Client
	TxManager      tx.TxManager
	Logger         *logger.Logger
	WebAuthnEngine *webauthn.Engine
	EventBus       domainEB.EventBus
	Limiter        domainRL.Limiter
	WireauthServer *wireauth.Server
	Metrics        *metrics.Registry
}

// InitInfrastructures connects to Postgres, Redis, and initializes crypto and event bus.
func InitInfrastructures(ctx context.Context, cfg *config.Config) (*Infrastructures, error) {
	log := logger.New(cfg.LogLevel, cfg.LogFormat)

	// 1. Connect Postgres
	dbPool, err := database.ConnectPostgres(ctx, cfg.DatabaseDSN)
	if err != nil {
		return nil, fmt.Errorf("bootstrap: postgres connection failed: %w", err)
	}

	// 2. Connect Redis
	redisOpts, err := goredis.ParseURL(cfg.RedisURL)
	if err != nil {
		dbPool.Close()
		return nil, fmt.Errorf("bootstrap: redis URL parse failed: %w", err)
	}
	redisClient := goredis.NewClient(redisOpts)

	pingCtx, cancelPing := context.WithTimeout(ctx, 3*time.Second)
	defer cancelPing()
	if err := redisClient.Ping(pingCtx).Err(); err != nil {
		dbPool.Close()
		_ = redisClient.Close()
		return nil, fmt.Errorf("bootstrap: redis ping failed: %w", err)
	}

	// 3. WebAuthn Engine
	wauEngine, err := webauthn.NewEngine(cfg)
	if err != nil {
		dbPool.Close()
		_ = redisClient.Close()
		return nil, fmt.Errorf("bootstrap: webauthn engine init failed: %w", err)
	}

	// 4. Wireauth RSA Server (Generate ephemeral RSA key in dev/test if none provided)
	wireauthKey := cfg.WireauthPrivateKey
	if wireauthKey == nil {
		log.Warn("No Wireauth RSA private key configured; generating ephemeral 2048-bit RSA key")
		ephemeralKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			dbPool.Close()
			_ = redisClient.Close()
			return nil, fmt.Errorf("bootstrap: generate RSA key failed: %w", err)
		}
		wireauthKey = ephemeralKey
		cfg.WireauthPrivateKey = ephemeralKey
	}

	wireauthServer := wireauth.NewServer(
		wireauthKey,
		wireauth.WithTimeout(cfg.WSHandshakeTimeout),
	)

	txManager := database.NewTxManager(dbPool)
	eventBusInstance := eventbus.NewRedisEventBus(redisClient)
	limiter := ratelimit.NewRedisLimiter(redisClient)
	metricsReg := metrics.NewRegistry()

	return &Infrastructures{
		DBPool:         dbPool,
		RedisClient:    redisClient,
		TxManager:      txManager,
		Logger:         log,
		WebAuthnEngine: wauEngine,
		EventBus:       eventBusInstance,
		Limiter:        limiter,
		WireauthServer: wireauthServer,
		Metrics:        metricsReg,
	}, nil
}

// Close gracefully releases infrastructure resources.
func (i *Infrastructures) Close() {
	if i.DBPool != nil {
		i.DBPool.Close()
	}
	if i.RedisClient != nil {
		_ = i.RedisClient.Close()
	}
}
