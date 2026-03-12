package main

import (
	"os"

	"github.com/praetorian-inc/pius/pkg/runner"
)

// version is set at build time via -ldflags "-X main.version=..."
var version = "dev"

func main() {
	runner.SetVersion(version)
	if err := runner.Execute(); err != nil {
		os.Exit(1)
	}
}
