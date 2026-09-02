package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

func NewRootCmd() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:   "airlance-api",
		Short: "Airlance core authentication, connection, and API foundation service",
	}

	rootCmd.AddCommand(
		newServeCmd(),
		newVersionCmd(),
		newMigrateCmd(),
		newCleanupCmd(),
		newKeysCmd(),
	)

	return rootCmd
}

func Execute() {
	if err := NewRootCmd().Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
