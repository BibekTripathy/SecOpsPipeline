// Package config loads the gateway's configuration file.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the whole gateway configuration.
type Config struct {
	// Listen is the HTTP address developers push to.
	Listen string `yaml:"listen"`
	// DataDir holds the database, quarantine repos, audit log and reports.
	DataDir string `yaml:"data_dir"`
	// PolicyFile is the policy to evaluate. Empty uses the built-in default.
	PolicyFile string `yaml:"policy_file"`

	Scan     ScanConfig      `yaml:"scan"`
	Upstream UpstreamConfig  `yaml:"upstream"`
	Repos    map[string]Repo `yaml:"repos"`
	Log      LogConfig       `yaml:"log"`
}

// ScanConfig tunes the scanning stage.
type ScanConfig struct {
	// Workers caps concurrent scanner plugins. Zero runs all of them at once.
	Workers int `yaml:"workers"`
	// Timeout bounds the whole scan for one push.
	Timeout time.Duration `yaml:"timeout"`
	// MaxPushBytes rejects pushes larger than this before scanning. Zero is
	// unlimited.
	MaxPushBytes int64 `yaml:"max_push_bytes"`
	// Verify enables credential verification against third-party providers.
	// Off by default: it sends the matched secret to the provider.
	Verify bool `yaml:"verify_secrets"`
	// RequireSignedCommits reports every unsigned commit.
	RequireSignedCommits bool `yaml:"require_signed_commits"`
}

// UpstreamConfig holds the credentials the gateway forwards with.
type UpstreamConfig struct {
	SSHKeyPath     string `yaml:"ssh_key_path"`
	KnownHostsPath string `yaml:"known_hosts_path"`
}

// Repo maps a gateway repository name to its real remote.
type Repo struct {
	// URL is the upstream the gateway forwards released pushes to.
	URL string `yaml:"url"`
	// PolicyFile overrides the global policy for this repo.
	PolicyFile string `yaml:"policy_file"`
}

type LogConfig struct {
	// Level is debug, info, warn or error.
	Level string `yaml:"level"`
	// Format is text or json.
	Format string `yaml:"format"`
}

// Default returns a runnable local configuration.
func Default() *Config {
	return &Config{
		Listen:  "127.0.0.1:8080",
		DataDir: "./data",
		Scan: ScanConfig{
			Workers:      4,
			Timeout:      5 * time.Minute,
			MaxPushBytes: 512 << 20,
		},
		Repos: map[string]Repo{},
		Log:   LogConfig{Level: "info", Format: "text"},
	}
}

// Load reads a config file over the defaults.
func Load(filename string) (*Config, error) {
	cfg := Default()

	b, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	dec := yaml.NewDecoder(strings.NewReader(string(b)))
	dec.KnownFields(true)
	if err := dec.Decode(cfg); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", filename, err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config %s: %w", filename, err)
	}
	return cfg, nil
}

// Validate rejects a configuration the gateway cannot run with. Everything
// checkable must fail here, at startup, rather than on someone's push.
func (c *Config) Validate() error {
	if c.Listen == "" {
		return fmt.Errorf("listen is required")
	}
	if c.DataDir == "" {
		return fmt.Errorf("data_dir is required")
	}
	if c.Scan.Workers < 0 {
		return fmt.Errorf("scan.workers must not be negative")
	}
	if c.Scan.Timeout < 0 {
		return fmt.Errorf("scan.timeout must not be negative")
	}
	for name, repo := range c.Repos {
		if repo.URL == "" {
			return fmt.Errorf("repo %q: url is required", name)
		}
	}
	switch c.Log.Level {
	case "", "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("log.level %q is not one of debug, info, warn, error", c.Log.Level)
	}
	switch c.Log.Format {
	case "", "text", "json":
	default:
		return fmt.Errorf("log.format %q is not text or json", c.Log.Format)
	}
	return nil
}

// Paths derived from DataDir, so the layout is stated in exactly one place.
func (c *Config) DatabasePath() string  { return filepath.Join(c.DataDir, "gateway.db") }
func (c *Config) QuarantineDir() string { return filepath.Join(c.DataDir, "quarantine") }
func (c *Config) AuditLogPath() string  { return filepath.Join(c.DataDir, "audit.jsonl") }
func (c *Config) ReportsDir() string    { return filepath.Join(c.DataDir, "reports") }
func (c *Config) SocketPath() string    { return filepath.Join(c.DataDir, "hook.sock") }
