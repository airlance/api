package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

var (
	// Version can be overwritten at build time with -ldflags
	Version = "v1.0.0-dev"
)

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print service binary version",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("Airlance API %s\n", Version)
		},
	}
}
