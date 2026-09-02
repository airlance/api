package cli

import (
	"context"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"airlance.org/api/internal/config"
	"airlance.org/api/internal/data/repository/postgres"
	"airlance.org/api/internal/infrastructure/database"
	"airlance.org/api/internal/infrastructure/logger"
)

func newCleanupCmd() *cobra.Command {
	var maxAge time.Duration

	cmd := &cobra.Command{
		Use:   "cleanup",
		Short: "Purge expired authentication challenges and expired sessions",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.LoadFromEnv()
			if err != nil {
				return fmt.Errorf("load config error: %w", err)
			}

			log := logger.New(cfg.LogLevel, cfg.LogFormat).Named(logger.CategoryApp)
			ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
			defer cancel()

			pool, err := database.ConnectPostgres(ctx, cfg.DatabaseDSN)
			if err != nil {
				return fmt.Errorf("postgres connect error: %w", err)
			}
			defer pool.Close()

			sessionRepo := postgres.NewSessionRepository(pool)
			challengeRepo := postgres.NewChallengeRepository(pool)

			cutoff := time.Now().Add(-maxAge)

			// Clean expired challenges
			cleanedChallenges, err := challengeRepo.CleanupExpired(ctx, cutoff)
			if err != nil {
				log.Error(err, "Failed to cleanup expired passkey challenges")
			} else {
				log.Info("Cleaned up expired challenges", "count", cleanedChallenges)
			}

			// Clean expired sessions
			cleanedSessions, err := sessionRepo.CleanupExpired(ctx, cutoff)
			if err != nil {
				log.Error(err, "Failed to cleanup expired sessions")
			} else {
				log.Info("Cleaned up expired sessions", "count", cleanedSessions)
			}

			fmt.Printf("Cleanup completed: %d challenges, %d sessions purged.\n", cleanedChallenges, cleanedSessions)
			return nil
		},
	}

	cmd.Flags().DurationVar(&maxAge, "max-age", 0, "Grace period before deleting expired records (e.g. 24h)")
	return cmd
}
