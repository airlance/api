package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print application version",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("Messenger Version: %s\nCommit: %s\nBuild Date: %s\n", appVersion, appCommit, appBuildDate)
	},
}
