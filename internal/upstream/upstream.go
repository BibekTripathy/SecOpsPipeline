// Package upstream forwards a released push to the real remote.
//
// The gateway pushes with its own credentials, never the developer's. That is
// the property that makes the gateway unbypassable: developers are given write
// access to the gateway, and only the gateway has write access to the remote.
package upstream

import (
	"context"
	"fmt"
	"os"

	"github.com/BibekTripathy/SecOpsPipeline/internal/gitutil"
)

// Pusher forwards refs from a quarantine repo to an upstream remote.
type Pusher struct {
	// SSHKeyPath is the gateway's own deploy key. Empty uses the ambient git
	// credential configuration, which is useful in a lab but not in
	// production.
	SSHKeyPath string
	// KnownHostsPath pins the upstream host key. Empty disables pinning.
	KnownHostsPath string
}

// Push forwards a single ref update from quarantinePath to upstreamURL.
//
// It is deliberately not a force push: the gateway must never be the reason
// upstream history is rewritten.
func (p *Pusher) Push(ctx context.Context, quarantinePath, upstreamURL, ref, newRev string) error {
	args := []string{"push", upstreamURL, fmt.Sprintf("%s:%s", newRev, ref)}
	if env := p.sshCommand(); env != "" {
		// gitutil.Run does not take env, so configure the transport through
		// repo-local config instead of the process environment.
		if _, err := gitutil.Run(ctx, quarantinePath, "config", "core.sshCommand", env); err != nil {
			return fmt.Errorf("configure ssh command: %w", err)
		}
	}
	if _, err := gitutil.Run(ctx, quarantinePath, args...); err != nil {
		return fmt.Errorf("forward %s to upstream: %w", ref, err)
	}
	return nil
}

func (p *Pusher) sshCommand() string {
	if p.SSHKeyPath == "" {
		return ""
	}
	cmd := fmt.Sprintf("ssh -i %q -o IdentitiesOnly=yes", p.SSHKeyPath)
	if p.KnownHostsPath != "" {
		cmd += fmt.Sprintf(" -o UserKnownHostsFile=%q -o StrictHostKeyChecking=yes", p.KnownHostsPath)
	}
	return cmd
}

// CheckKey verifies the configured deploy key exists and is not world
// readable, so a misconfiguration fails at startup rather than at push time.
func (p *Pusher) CheckKey() error {
	if p.SSHKeyPath == "" {
		return nil
	}
	info, err := os.Stat(p.SSHKeyPath)
	if err != nil {
		return fmt.Errorf("deploy key: %w", err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("deploy key %s is group/world readable (mode %o)", p.SSHKeyPath, info.Mode().Perm())
	}
	return nil
}
