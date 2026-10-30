package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/BibekTripathy/SecOpsPipeline/internal/audit"
	"github.com/BibekTripathy/SecOpsPipeline/internal/baseline"
	"github.com/BibekTripathy/SecOpsPipeline/internal/config"
	"github.com/BibekTripathy/SecOpsPipeline/internal/gateway"
	"github.com/BibekTripathy/SecOpsPipeline/internal/hook"
	"github.com/BibekTripathy/SecOpsPipeline/internal/metrics"
	"github.com/BibekTripathy/SecOpsPipeline/internal/policy"
	"github.com/BibekTripathy/SecOpsPipeline/internal/quarantine"
	"github.com/BibekTripathy/SecOpsPipeline/internal/scanner"
	"github.com/BibekTripathy/SecOpsPipeline/internal/scanner/deps"
	"github.com/BibekTripathy/SecOpsPipeline/internal/scanner/iac"
	"github.com/BibekTripathy/SecOpsPipeline/internal/scanner/secrets"
	"github.com/BibekTripathy/SecOpsPipeline/internal/scanner/signature"
	"github.com/BibekTripathy/SecOpsPipeline/internal/store"
	"github.com/BibekTripathy/SecOpsPipeline/internal/transport/githttp"
	"github.com/BibekTripathy/SecOpsPipeline/internal/upstream"
)

func runServe(args []string) error {
	fs := flagSet("serve")
	configPath := fs.String("config", defaultConfigPath, "configuration file")
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

	// Per-repo policies and baselines are loaded and validated here, at
	// startup. A typo in one team's file must stop the gateway coming
	// up, not surface weeks later as a failed push for that team alone.
	policies := policy.NewSet(pol)
	for name, repo := range cfg.Repos {
		if repo.PolicyFile == "" {
			continue
		}
		if err := policies.LoadFor(name, repo.PolicyFile); err != nil {
			return err
		}
	}

	var globalBaseline *baseline.Baseline
	if cfg.BaselineFile != "" {
		if globalBaseline, err = baseline.Load(cfg.BaselineFile); err != nil {
			return err
		}
	}
	baselines := baseline.NewSet(globalBaseline)
	for name, repo := range cfg.Repos {
		if repo.BaselineFile == "" {
			continue
		}
		if err := baselines.LoadFor(name, repo.BaselineFile); err != nil {
			return err
		}
	}
	// An exception that has lapsed is worth saying out loud: the finding
	// is about to come back and somebody has to decide again.
	for name, b := range baselines.All() {
		for _, e := range b.Expired(time.Now()) {
			log.Warn("baseline entry has expired and no longer applies",
				"repo", name, "rule", e.Rule, "path", e.Path, "reason", e.Reason)
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

	scanners := scanner.NewRegistry(
		secrets.New(verifier),
		signature.New(cfg.Scan.RequireSignedCommits),
	)
	if cfg.Scan.IaC {
		scanners.Register(iac.New())
	}
	if cfg.Scan.Dependencies.Enabled {
		scanners.Register(newDepsScanner(cfg, log))
	}

	reg := metrics.New()
	reg.SetHeldGauge(func() int {
		held, err := db.ListHeldPushes(context.Background(), store.HeldPending)
		if err != nil {
			return -1
		}
		return len(held)
	})

	g := gateway.New(&gateway.Gateway{
		Config:     cfg,
		Policies:   policies,
		Scanners:   scanners,
		Quarantine: qm,
		Pusher:     pusher,
		Audit:      auditLog,
		Held:       db,
		Baselines:  baselines,
		Metrics:    reg,
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

	// Operational endpoints live on their own listener: /metrics
	// describes the organisation's security posture and is not
	// something to hand to everyone holding a push token.
	var adminSrv *http.Server
	if cfg.AdminListen != "" {
		adminSrv = &http.Server{
			Addr: cfg.AdminListen,
			Handler: githttp.AdminMux(reg.Handler(), func() error {
				return db.SQL().PingContext(ctx)
			}, gateway.Version),
			ReadHeaderTimeout: 10 * time.Second,
		}
		go func() {
			if err := adminSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Error("admin listener stopped", "error", err)
			}
		}()
		log.Info("admin endpoints listening", "addr", cfg.AdminListen,
			"paths", []string{"/metrics", "/healthz", "/readyz"})
	}

	// Reclaim quarantine repositories from holds nobody reviews.
	if cfg.HoldExpiry > 0 {
		go runHoldExpiry(ctx, cfg, db, auditLog, pusher, log)
	}

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
		if adminSrv != nil {
			adminSrv.Shutdown(shutdownCtx)
		}
		httpSrv.Shutdown(shutdownCtx)
	}()

	log.Info("gateway listening",
		"addr", cfg.Listen,
		"scanners", g.Scanners.Names(),
		"policy_default", pol.Default,
		"fail_closed", pol.FailClosed,
		"repo_policy_overrides", policies.Overrides())

	if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("serve: %w", err)
	}
	log.Info("gateway stopped")
	return nil
}

// newDepsScanner builds the dependency scanner from configuration.
//
// The cache lives for the life of the process, so a repository's
// dependencies are looked up once rather than on every push.
func newDepsScanner(cfg *config.Config, log *slog.Logger) *deps.Scanner {
	// Prefer a cache that survives a restart; fall back to memory if
	// the directory cannot be created, since a missing cache slows
	// pushes down rather than breaking them.
	var cache deps.Cache
	disk, err := deps.NewDiskCache(cfg.AdvisoryCacheDir(), cfg.Scan.Dependencies.CacheTTL)
	if err != nil {
		log.Warn("advisory disk cache unavailable, using memory", "error", err)
		cache = deps.NewMemoryCache()
	} else {
		cache = disk
	}

	client := deps.NewOSVClient(cache)
	if e := cfg.Scan.Dependencies.Endpoint; e != "" {
		client.Endpoint = e
	}

	s := deps.New(client, deps.GoModParser{}, deps.RequirementsParser{}, deps.NpmLockParser{})
	if t := cfg.Scan.Dependencies.Timeout; t > 0 {
		s.Timeout = t
	}
	return s
}

// runHoldExpiry periodically resolves held pushes nobody reviewed and
// reclaims their quarantine repositories.
//
// Without it, a hold that is never looked at keeps a bare repository on
// disk indefinitely. The interval is a fraction of the expiry window, so
// a push is reclaimed reasonably soon after lapsing without the check
// itself being frequent.
func runHoldExpiry(ctx context.Context, cfg *config.Config, db *store.DB,
	auditLog *audit.Log, pusher *upstream.Pusher, log *slog.Logger) {

	interval := cfg.HoldExpiry / 12
	if interval < time.Minute {
		interval = time.Minute
	}
	if interval > time.Hour {
		interval = time.Hour
	}

	reviewer := &gateway.Reviewer{Config: cfg, DB: db, Audit: auditLog, Pusher: pusher}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			stale, err := reviewer.Expire(ctx, cfg.HoldExpiry)
			if err != nil {
				log.Error("expire held pushes", "error", err)
				continue
			}
			if len(stale) > 0 {
				log.Info("expired held pushes nobody reviewed",
					"count", len(stale), "older_than", cfg.HoldExpiry)
			}
		}
	}
}
