// Package bench measures what the gateway costs a developer.
//
// The honest question about anything that sits in the push path is how
// much it slows a push down. These benchmarks answer it in the two
// dimensions that actually vary: how many files a push touches, and how
// large they are.
//
// They measure the scan stage specifically -- describing the push and
// running the plugins -- because that is the part the gateway adds.
// Network transfer and git's own packfile handling happen either way.
package bench

import (
	"context"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/BibekTripathy/SecOpsPipeline/internal/gitutil"
	"github.com/BibekTripathy/SecOpsPipeline/internal/scanner"
	"github.com/BibekTripathy/SecOpsPipeline/internal/scanner/secrets"
	"github.com/BibekTripathy/SecOpsPipeline/internal/scanner/signature"
)

// fixture is a git repository with one commit of generated source.
type fixture struct {
	repo    gitutil.Repo
	oldRev  string
	newRev  string
	files   int
	bytes   int64
	commits int
}

// buildFixture creates a repo whose tip commit adds fileCount files of
// roughly fileBytes each.
//
// The content is plausible source rather than random bytes: random data is
// uniformly high entropy, which would make the entropy layer do work it
// never does on real input and overstate the cost.
func buildFixture(tb testing.TB, fileCount, fileBytes, commitCount int) *fixture {
	tb.Helper()
	requireGit(tb)

	dir := tb.TempDir()
	git := func(args ...string) {
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=bench", "GIT_AUTHOR_EMAIL=bench@example.com",
			"GIT_COMMITTER_NAME=bench", "GIT_COMMITTER_EMAIL=bench@example.com",
		)
		if out, err := cmd.CombinedOutput(); err != nil {
			tb.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
		}
	}

	git("init", "--quiet", "--initial-branch=main")
	git("config", "commit.gpgsign", "false")

	// A base commit, so old..new is a real range rather than a root walk.
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("# bench\n"), 0o644); err != nil {
		tb.Fatal(err)
	}
	git("add", "-A")
	git("commit", "--quiet", "-m", "base")

	oldRev := revParse(tb, dir, "HEAD")

	r := rand.New(rand.NewSource(1))
	var total int64
	perCommit := fileCount / commitCount
	if perCommit == 0 {
		perCommit = 1
	}

	written := 0
	for c := 0; c < commitCount; c++ {
		for i := 0; i < perCommit && written < fileCount; i++ {
			name := filepath.Join("pkg", fmt.Sprintf("mod%03d", written/50), fmt.Sprintf("file%05d.go", written))
			path := filepath.Join(dir, name)
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				tb.Fatal(err)
			}
			content := sourceLike(r, fileBytes)
			if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
				tb.Fatal(err)
			}
			total += int64(len(content))
			written++
		}
		git("add", "-A")
		git("commit", "--quiet", "-m", fmt.Sprintf("commit %d", c))
	}

	return &fixture{
		repo:    gitutil.At(dir),
		oldRev:  oldRev,
		newRev:  revParse(tb, dir, "HEAD"),
		files:   written,
		bytes:   total,
		commits: commitCount,
	}
}

func revParse(tb testing.TB, dir, ref string) string {
	tb.Helper()
	out, err := exec.Command("git", "-C", dir, "rev-parse", ref).Output()
	if err != nil {
		tb.Fatalf("rev-parse %s: %v", ref, err)
	}
	return strings.TrimSpace(string(out))
}

// sourceLike generates Go-ish text of about n bytes.
func sourceLike(r *rand.Rand, n int) string {
	lines := []string{
		"package pkg",
		"",
		"import (",
		`	"context"`,
		`	"fmt"`,
		")",
		"",
	}
	bodies := []string{
		"func handle%d(ctx context.Context, id string) error {",
		"	if id == \"\" {",
		"		return fmt.Errorf(\"empty id\")",
		"	}",
		"	return nil",
		"}",
		"",
		"// doc comment for the next declaration",
		"var threshold%d = 42",
		"",
	}
	var b strings.Builder
	for _, l := range lines {
		b.WriteString(l)
		b.WriteByte('\n')
	}
	for i := 0; b.Len() < n; i++ {
		line := bodies[i%len(bodies)]
		if strings.Contains(line, "%d") {
			fmt.Fprintf(&b, line+"\n", r.Intn(10000))
		} else {
			b.WriteString(line)
			b.WriteByte('\n')
		}
	}
	return b.String()
}

func requireGit(tb testing.TB) {
	tb.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		tb.Skip("git not on PATH")
	}
}

// newRegistry builds the scanner set a default deployment runs.
func newRegistry() *scanner.Registry {
	return scanner.NewRegistry(secrets.New(nil), signature.New(false))
}

// describe is what the gateway does before scanning.
func describe(tb testing.TB, f *fixture) *scanner.Target {
	tb.Helper()
	ctx := context.Background()
	commits, err := gitutil.NewCommits(ctx, f.repo, f.oldRev, f.newRev)
	if err != nil {
		tb.Fatalf("NewCommits: %v", err)
	}
	files, err := gitutil.ChangedFiles(ctx, f.repo, f.oldRev, f.newRev)
	if err != nil {
		tb.Fatalf("ChangedFiles: %v", err)
	}
	return &scanner.Target{
		Repo: "bench/repo", Git: f.repo, Ref: "refs/heads/main",
		OldRev: f.oldRev, NewRev: f.newRev, Commits: commits, Files: files,
	}
}

// withBlobs attaches a batch blob reader, as the gateway does for a real
// push. Benchmarks that omit it measure the slow per-file fallback.
func withBlobs(tb testing.TB, f *fixture, t *scanner.Target) *scanner.Target {
	tb.Helper()
	br, err := gitutil.NewBlobReader(context.Background(), f.repo)
	if err != nil {
		tb.Fatalf("NewBlobReader: %v", err)
	}
	tb.Cleanup(func() { br.Close() })
	t.Blobs = br
	return t
}

// sourceLikeFixed is sourceLike with a fixed seed, for benchmarks that
// need identical input on every run.
func sourceLikeFixed(n int) string {
	return sourceLike(rand.New(rand.NewSource(7)), n)
}

func newSecretsScanner() *secrets.Scanner { return secrets.New(nil) }
