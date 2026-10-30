package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/BibekTripathy/SecOpsPipeline/internal/audit"
	"github.com/BibekTripathy/SecOpsPipeline/internal/gateway"
	"github.com/BibekTripathy/SecOpsPipeline/internal/store"
	"github.com/BibekTripathy/SecOpsPipeline/internal/upstream"
)

func runReview(args []string) error {
	fs := flagSet("review")
	configPath := fs.String("config", defaultConfigPath, "configuration file")
	list := fs.Bool("list", false, "list pushes awaiting review")
	show := fs.String("show", "", "show one held push in full")
	approve := fs.String("approve", "", "approve and forward a held push")
	reject := fs.String("reject", "", "reject a held push")
	expire := fs.Duration("expire", 0, "expire pending pushes older than this")
	as := fs.String("as", "", "username of the reviewer making the decision")
	note := fs.String("note", "", "reason recorded with the decision")
	if err := fs.Parse(args); err != nil {
		return err
	}

	ctx := context.Background()
	cfg, db, err := openDB(ctx, *configPath)
	if err != nil {
		return err
	}
	defer db.Close()

	auditLog, err := audit.Open(cfg.AuditLogPath())
	if err != nil {
		return err
	}
	defer auditLog.Close()

	r := &gateway.Reviewer{
		Config: cfg,
		DB:     db,
		Audit:  auditLog,
		Pusher: &upstream.Pusher{
			SSHKeyPath:     cfg.Upstream.SSHKeyPath,
			KnownHostsPath: cfg.Upstream.KnownHostsPath,
		},
	}

	switch {
	case *list:
		return listHeld(ctx, r)
	case *show != "":
		return showHeld(ctx, r, *show)
	case *approve != "":
		id, err := reviewerID(ctx, db, *as)
		if err != nil {
			return err
		}
		if err := r.Approve(ctx, *approve, id, *note); err != nil {
			return err
		}
		fmt.Printf("approved %s and forwarded it upstream\n", *approve)
		return nil
	case *reject != "":
		id, err := reviewerID(ctx, db, *as)
		if err != nil {
			return err
		}
		if err := r.Reject(ctx, *reject, id, *note); err != nil {
			return err
		}
		fmt.Printf("rejected %s; nothing was forwarded\n", *reject)
		return nil
	case *expire > 0:
		stale, err := r.Expire(ctx, *expire)
		if err != nil {
			return err
		}
		fmt.Printf("expired %d push(es) older than %s\n", len(stale), *expire)
		return nil
	}

	return fmt.Errorf("nothing to do: pass -list, -show, -approve, -reject or -expire")
}

// reviewerID resolves the reviewer and checks they may approve.
//
// A decision with no name attached is worth very little in an audit log,
// so -as is required rather than defaulted.
func reviewerID(ctx context.Context, db *store.DB, username string) (string, error) {
	if username == "" {
		return "", fmt.Errorf("-as <username> is required, so the decision is attributable")
	}
	u, err := db.UserByUsername(ctx, username)
	if errors.Is(err, store.ErrNotFound) {
		return "", fmt.Errorf("no such user %q", username)
	}
	if err != nil {
		return "", err
	}
	return u.ID, nil
}

func listHeld(ctx context.Context, r *gateway.Reviewer) error {
	held, err := r.Pending(ctx)
	if err != nil {
		return err
	}
	if len(held) == 0 {
		fmt.Println("nothing awaiting review")
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tREPO\tREF\tACTOR\tFINDINGS\tWAITING")
	for _, h := range held {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%d\t%s\n",
			h.ID, h.Repo, h.Ref, h.ActorUsername, len(h.Findings), waited(h.Age()))
	}
	return w.Flush()
}

func showHeld(ctx context.Context, r *gateway.Reviewer, id string) error {
	h, err := r.Get(ctx, id)
	if err != nil {
		return err
	}

	fmt.Printf("push     %s\nrepo     %s\nref      %s\n", h.ID, h.Repo, h.Ref)
	fmt.Printf("commits  %s..%s\nactor    %s\nstate    %s\nwaiting  %s\n\n",
		shortRev(h.OldRev), shortRev(h.NewRev), h.ActorUsername, h.State, waited(h.Age()))

	if len(h.Findings) == 0 {
		fmt.Println("no findings recorded")
	} else {
		fmt.Printf("%d finding(s):\n\n", len(h.Findings))
		for _, f := range h.Findings {
			fmt.Printf("  %-9s %-28s %s\n", f.Severity, f.RuleID, findingLocation(f))
			fmt.Printf("            %s", f.Message)
			if f.Redacted != "" {
				fmt.Printf(" [%s]", f.Redacted)
			}
			fmt.Println()
		}
	}

	if len(h.Reasons) > 0 {
		fmt.Println("\nwhy it was held:")
		for _, reason := range h.Reasons {
			fmt.Printf("  - %s\n", reason)
		}
	}
	fmt.Printf("\napprove with:  gateway review -approve %s -as <you>\n", h.ID)
	fmt.Printf("reject with:   gateway review -reject  %s -as <you>\n", h.ID)
	return nil
}

func waited(d time.Duration) string {
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd", int(d.Hours()/24))
	}
}

func shortRev(rev string) string {
	if len(rev) > 8 {
		return rev[:8]
	}
	return rev
}
