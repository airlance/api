package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Show build information",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("Version: %s\n", appVersion)
		fmt.Printf("Commit: %s\n", appCommit)
		fmt.Printf("Build Date: %s\n", appBuildDate)
	},
}
