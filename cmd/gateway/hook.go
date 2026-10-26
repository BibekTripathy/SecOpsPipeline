package main

import (
	"fmt"
	"os"

	"github.com/BibekTripathy/SecOpsPipeline/internal/hook"
)

// runHook is the pre-receive hook entry point. git runs this inside the
// quarantine repo with the ref updates on stdin.
func runHook(args []string) int {
	if len(args) != 1 || args[0] != "pre-receive" {
		fmt.Fprintln(os.Stderr, "usage: gateway hook pre-receive")
		return 1
	}
	return hook.RunPreReceive(os.Stdin, os.Stderr)
}
