package main

import (
	"github.com/airlance/api/internal/transport/cli"
)

var (
	Version   = "dev"
	Commit    = "unknown"
	BuildDate = "unknown"
)

func main() {
	cli.Execute(Version, Commit, BuildDate)
}
