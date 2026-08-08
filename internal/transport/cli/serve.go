package cli

import (
	"github.com/airlance/api/internal/bootstrap"
	"github.com/airlance/api/internal/config"
	"github.com/spf13/cobra"
)

// serveCmd starts the application: HTTP (chi, incl. /health) and gRPC
// (wireauthgrpc-secured) servers running concurrently against a shared
// database connection, logger, and graceful shutdown.
var serveCmd = &cobra.Command{
	Use:     "serve",
	Aliases: []string{"grpc"}, // kept for backwards compatibility
	Short:   "Start Airlance HTTP + gRPC servers",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load()
		if err != nil {
			return err
		}

		app, err := bootstrap.NewApplication(cfg)
		if err != nil {
			return err
		}

		return app.Run()
	},
}
