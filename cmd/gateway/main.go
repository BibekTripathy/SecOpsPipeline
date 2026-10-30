// Command gateway is the Commit Quarantine Gateway.
//
// It runs in two modes. Normally it is the server developers push to. When
// invoked as `gateway hook pre-receive` it is the pre-receive hook inside a
// quarantine repo, asking the running server for a verdict. One binary does
// both so a deployment is a single file.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "hook" {
		os.Exit(runHook(os.Args[2:]))
	}

	cmds := map[string]func([]string) error{
		"serve":  runServe,
		"user":   runUser,
		"token":  runToken,
		"audit":  runAudit,
		"policy": runPolicyCheck,
		"review": runReview,
	}

	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	cmd, ok := cmds[os.Args[1]]
	if !ok {
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
	if err := cmd(os.Args[2:]); err != nil {
		fmt.Fprintf(os.Stderr, "gateway: %v\n", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `commit quarantine gateway

usage: gateway <command> [flags]

commands:
  serve     run the push gateway
  user      manage users
  token     issue and revoke access tokens
  audit     verify or read the audit log
  policy    validate a policy file
  review    list and resolve pushes held for approval
  hook      internal: pre-receive hook mode

run "gateway <command> -h" for a command's flags
`)
}

// signalContext cancels on SIGINT/SIGTERM so a shutdown drains in-flight
// pushes instead of killing them mid-scan.
func signalContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
}

func newLogger(level, format string) *slog.Logger {
	var lvl slog.Level
	switch level {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}
	opts := &slog.HandlerOptions{Level: lvl}
	if format == "json" {
		return slog.New(slog.NewJSONHandler(os.Stderr, opts))
	}
	return slog.New(slog.NewTextHandler(os.Stderr, opts))
}

// flagSet builds a named flag set that prints to stderr.
func flagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	return fs
}
