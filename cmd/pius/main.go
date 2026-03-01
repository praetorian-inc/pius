package main

import (
	"os"

	"github.com/praetorian-inc/pius/pkg/runner"
)

func main() {
	if err := runner.Execute(); err != nil {
		os.Exit(1)
	}
}
