package cli

import (
	"os"

	"github.com/spf13/cobra"
)

var (
	appVersion   string
	appCommit    string
	appBuildDate string
)

var rootCmd = &cobra.Command{
	Use:   "app",
	Short: "Airlance Application",
}

func init() {
	rootCmd.AddCommand(serveCmd)
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(migrateCmd)
}

func Execute(version, commit, buildDate string) {
	appVersion = version
	appCommit = commit
	appBuildDate = buildDate

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
