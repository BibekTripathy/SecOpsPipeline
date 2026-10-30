package main

import (
	"context"
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/BibekTripathy/SecOpsPipeline/internal/audit"
	"github.com/BibekTripathy/SecOpsPipeline/internal/auth"
	"github.com/BibekTripathy/SecOpsPipeline/internal/config"
	"github.com/BibekTripathy/SecOpsPipeline/internal/finding"
	"github.com/BibekTripathy/SecOpsPipeline/internal/policy"
	"github.com/BibekTripathy/SecOpsPipeline/internal/store"
)

// defaultConfigPath is where every subcommand looks unless told otherwise.
const defaultConfigPath = "configs/gateway.example.yaml"

// findingLocation renders where a finding is, for the review output.
func findingLocation(f finding.Finding) string {
	switch {
	case f.File != "" && f.Line > 0:
		return fmt.Sprintf("%s:%d", f.File, f.Line)
	case f.File != "":
		return f.File
	case f.Commit != "":
		return shortRev(f.Commit)
	default:
		return "-"
	}
}

// openDB loads the config and opens the database, which every admin
// subcommand needs.
func openDB(ctx context.Context, configPath string) (*config.Config, *store.DB, error) {
	cfg, err := config.Load(configPath)
	if err != nil {
		return nil, nil, err
	}
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return nil, nil, fmt.Errorf("create data dir: %w", err)
	}
	db, err := store.Open(ctx, cfg.DatabasePath())
	if err != nil {
		return nil, nil, err
	}
	return cfg, db, nil
}

func runUser(args []string) error {
	fs := flagSet("user")
	configPath := fs.String("config", defaultConfigPath, "configuration file")
	create := fs.String("create", "", "create a user with this username")
	email := fs.String("email", "", "email address for the new user")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *create == "" {
		return fmt.Errorf("nothing to do: pass -create <username>")
	}

	ctx := context.Background()
	_, db, err := openDB(ctx, *configPath)
	if err != nil {
		return err
	}
	defer db.Close()

	u, err := db.CreateUser(ctx, auth.User{Username: *create, Email: *email})
	if err != nil {
		return err
	}
	fmt.Printf("created user %s (%s)\n", u.Username, u.ID)
	return nil
}

func runToken(args []string) error {
	fs := flagSet("token")
	configPath := fs.String("config", defaultConfigPath, "configuration file")
	username := fs.String("user", "", "username to act on")
	issue := fs.String("issue", "", "issue a token with this name")
	scopes := fs.String("scopes", "push", "comma-separated scopes: push, approve, admin")
	ttl := fs.Duration("ttl", 0, "token lifetime; 0 never expires")
	list := fs.Bool("list", false, "list the user's tokens")
	revoke := fs.String("revoke", "", "revoke the token with this id")
	if err := fs.Parse(args); err != nil {
		return err
	}

	ctx := context.Background()
	_, db, err := openDB(ctx, *configPath)
	if err != nil {
		return err
	}
	defer db.Close()

	if *revoke != "" {
		if err := db.RevokeToken(ctx, *revoke); err != nil {
			return err
		}
		fmt.Printf("revoked token %s\n", *revoke)
		return nil
	}

	if *username == "" {
		return fmt.Errorf("-user is required")
	}
	u, err := db.UserByUsername(ctx, *username)
	if err != nil {
		return fmt.Errorf("user %q: %w", *username, err)
	}

	switch {
	case *issue != "":
		secret, tok, err := auth.NewToken(u.ID, *issue, parseScopes(*scopes), *ttl)
		if err != nil {
			return err
		}
		if err := db.CreateToken(ctx, tok); err != nil {
			return err
		}
		// Printed once; only the digest is stored, so it cannot be shown again.
		fmt.Printf("token %s issued for %s\n\n    %s\n\n", tok.ID, u.Username, secret)
		fmt.Println("This is the only time the token is shown. Store it now.")
		fmt.Printf("\nPush with it:\n    git remote add gateway http://%s@localhost:8080/<repo>.git\n", secret)
		return nil

	case *list:
		toks, err := db.ListTokens(ctx, u.ID)
		if err != nil {
			return err
		}
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "ID\tNAME\tSCOPES\tCREATED\tSTATE")
		for _, t := range toks {
			fmt.Fprintf(w, "%s\t%s\t%v\t%s\t%s\n",
				t.ID, t.Name, t.Scopes, t.CreatedAt.Format(time.DateOnly), tokenState(t))
		}
		return w.Flush()
	}

	return fmt.Errorf("nothing to do: pass -issue, -list or -revoke")
}

func tokenState(t auth.Token) string {
	if err := t.Valid(time.Now().UTC()); err != nil {
		return err.Error()
	}
	return "active"
}

func parseScopes(s string) []auth.Scope {
	var out []auth.Scope
	for _, part := range splitComma(s) {
		out = append(out, auth.Scope(part))
	}
	return out
}

func splitComma(s string) []string {
	var out []string
	cur := ""
	for _, r := range s {
		if r == ',' {
			if cur != "" {
				out = append(out, cur)
			}
			cur = ""
			continue
		}
		if r != ' ' {
			cur += string(r)
		}
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}

func runAudit(args []string) error {
	fs := flagSet("audit")
	configPath := fs.String("config", defaultConfigPath, "configuration file")
	verify := fs.Bool("verify", false, "verify the hash chain")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	if !*verify {
		return fmt.Errorf("nothing to do: pass -verify")
	}

	n, err := audit.Verify(cfg.AuditLogPath())
	if err != nil {
		return fmt.Errorf("audit log is not intact after %d entries: %w", n, err)
	}
	fmt.Printf("audit log intact: %d entries verified\n", n)
	return nil
}

func runPolicyCheck(args []string) error {
	fs := flagSet("policy")
	path := fs.String("check", "", "policy file to validate")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *path == "" {
		return fmt.Errorf("nothing to do: pass -check <file>")
	}

	p, err := policy.Load(*path)
	if err != nil {
		return err
	}
	fmt.Printf("policy %s is valid: %d rule(s), default %s, fail_closed %v\n",
		*path, len(p.Rules), p.Default, p.FailClosed)
	return nil
}
