package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/BibekTripathy/SecOpsPipeline/internal/audit"
	"github.com/BibekTripathy/SecOpsPipeline/internal/config"
	"github.com/BibekTripathy/SecOpsPipeline/internal/gateway"
	"github.com/BibekTripathy/SecOpsPipeline/internal/hook"
	"github.com/BibekTripathy/SecOpsPipeline/internal/policy"
	"github.com/BibekTripathy/SecOpsPipeline/internal/quarantine"
	"github.com/BibekTripathy/SecOpsPipeline/internal/scanner"
	"github.com/BibekTripathy/SecOpsPipeline/internal/scanner/secrets"
	"github.com/BibekTripathy/SecOpsPipeline/internal/scanner/signature"
	"github.com/BibekTripathy/SecOpsPipeline/internal/store"
	"github.com/BibekTripathy/SecOpsPipeline/internal/transport/githttp"
	"github.com/BibekTripathy/SecOpsPipeline/internal/upstream"
)

func runServe(args []string) error {
	fs := flagSet("serve")
	configPath := fs.String("config", "configs/gateway.example.yaml", "configuration file")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	log := newLogger(cfg.Log.Level, cfg.Log.Format)

	pol := policy.Default()
	if cfg.PolicyFile != "" {
		if pol, err = policy.Load(cfg.PolicyFile); err != nil {
			return err
		}
	}

	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return fmt.Errorf("create data dir: %w", err)
	}

	ctx, stop := signalContext()
	defer stop()

	db, err := store.Open(ctx, cfg.DatabasePath())
	if err != nil {
		return err
	}
	defer db.Close()

	qm, err := quarantine.New(cfg.QuarantineDir())
	if err != nil {
		return err
	}

	auditLog, err := audit.Open(cfg.AuditLogPath())
	if err != nil {
		return err
	}
	defer auditLog.Close()

	pusher := &upstream.Pusher{
		SSHKeyPath:     cfg.Upstream.SSHKeyPath,
		KnownHostsPath: cfg.Upstream.KnownHostsPath,
	}
	// A bad deploy key must fail here, not on someone's push.
	if err := pusher.CheckKey(); err != nil {
		return err
	}

	binary, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locate gateway binary for the hook: %w", err)
	}
	if binary, err = filepath.EvalSymlinks(binary); err != nil {
		return fmt.Errorf("resolve gateway binary path: %w", err)
	}

	var verifier secrets.Verifier
	if cfg.Scan.Verify {
		// TODO(verify): wire the per-provider verifiers once they exist.
		log.Warn("verify_secrets is set but no verifiers are implemented yet")
	}

	g := gateway.New(&gateway.Gateway{
		Config:     cfg,
		Policy:     pol,
		Scanners:   scanner.NewRegistry(secrets.New(verifier), signature.New(cfg.Scan.RequireSignedCommits)),
		Quarantine: qm,
		Pusher:     pusher,
		Audit:      auditLog,
		Log:        log,
		BinaryPath: binary,
	})

	hookSrv := hook.NewServer(cfg.SocketPath(), g.Decide, log)
	if err := hookSrv.Listen(); err != nil {
		return err
	}
	defer hookSrv.Close()
	go func() {
		if err := hookSrv.Serve(ctx); err != nil {
			log.Error("hook server stopped", "error", err)
		}
	}()

	httpSrv := &http.Server{
		Addr: cfg.Listen,
		Handler: &githttp.Server{
			Auth:         db,
			Pushes:       g,
			Log:          log,
			MaxBodyBytes: cfg.Scan.MaxPushBytes,
		},
		// No write timeout: a large push legitimately takes a long time, and
		// the scan timeout already bounds the part we control.
		ReadHeaderTimeout: 30 * time.Second,
	}

	go func() {
		<-ctx.Done()
		log.Info("shutting down; waiting for in-flight pushes")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		httpSrv.Shutdown(shutdownCtx)
	}()

	log.Info("gateway listening",
		"addr", cfg.Listen,
		"scanners", g.Scanners.Names(),
		"policy_default", pol.Default,
		"fail_closed", pol.FailClosed)

	if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("serve: %w", err)
	}
	log.Info("gateway stopped")
	return nil
}
