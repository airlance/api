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
	Use:   "messenger",
	Short: "Messenger Go Backend",
}

func init() {
	rootCmd.AddCommand(serveCmd)
	rootCmd.AddCommand(keygenCmd)
	rootCmd.AddCommand(migrateCmd)
	rootCmd.AddCommand(versionCmd)
}

func Execute(version, commit, buildDate string) {
	appVersion = version
	appCommit = commit
	appBuildDate = buildDate

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
