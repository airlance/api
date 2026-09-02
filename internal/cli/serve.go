package cli

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"airlance.org/api/internal/bootstrap"
	"airlance.org/api/internal/config"
)

func newServeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "serve",
		Short: "Start the HTTP and WebSocket API server",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.LoadFromEnv()
			if err != nil {
				return fmt.Errorf("config error: %w", err)
			}

			app, err := bootstrap.BuildApp(context.Background(), cfg)
			if err != nil {
				return fmt.Errorf("bootstrap error: %w", err)
			}

			return app.Run()
		},
	}
}
