package deps

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/BibekTripathy/SecOpsPipeline/internal/gitutil"
)

// initRepo creates a repo containing the given files, staged so their
// blobs exist.
func initRepo(t *testing.T, files map[string]string) gitutil.Repo {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH")
	}

	dir := t.TempDir()
	run := func(args ...string) {
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
		}
	}
	run("init", "--quiet")

	for name, content := range files {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	run("add", "-A")
	return gitutil.At(dir)
}

// hashObject returns the blob id git stored for a path.
func hashObject(t *testing.T, repo gitutil.Repo, path string) string {
	t.Helper()
	out, err := exec.Command("git", "-C", repo.Path, "rev-parse", ":"+path).Output()
	if err != nil {
		t.Fatalf("rev-parse :%s: %v", path, err)
	}
	return strings.TrimSpace(string(out))
}
