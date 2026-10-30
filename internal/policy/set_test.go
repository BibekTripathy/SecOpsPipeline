package policy

import (
	"os"
	"path/filepath"
	"testing"
)

func writePolicy(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	return path
}

func TestSetFallsBackToGlobalPolicy(t *testing.T) {
	global := Default()
	set := NewSet(global)

	if set.For("acme/api") != global {
		t.Error("a repo with no override should get the global policy")
	}
}

func TestSetAppliesPerRepoOverride(t *testing.T) {
	path := writePolicy(t, `
version: 1
default: block
rules:
  - name: everything
    scanner: "*"
    action: block
`)
	set := NewSet(Default())
	if err := set.LoadFor("acme/api", path); err != nil {
		t.Fatalf("LoadFor: %v", err)
	}

	if got := set.For("acme/api").Default; got != Block {
		t.Errorf("override default = %q, want block", got)
	}
	if got := set.For("acme/other").Default; got != Release {
		t.Errorf("unrelated repo default = %q, want the global release", got)
	}
	if n := len(set.Overrides()); n != 1 {
		t.Errorf("overrides = %d, want 1", n)
	}
}

func TestSetRejectsInvalidPolicyAtLoadTime(t *testing.T) {
	path := writePolicy(t, `
version: 1
default: release
rules:
  - name: broken
    action: not-a-verdict
`)
	set := NewSet(Default())
	err := set.LoadFor("acme/api", path)
	if err == nil {
		t.Fatal("LoadFor returned nil for an invalid policy")
	}
	// The repo must be named, or an operator cannot tell which file to fix.
	if !contains(err.Error(), "acme/api") {
		t.Errorf("error = %v, want it to name the repo", err)
	}
}

func TestSetWithNilFallbackUsesDefault(t *testing.T) {
	if NewSet(nil).Fallback() == nil {
		t.Error("Fallback returned nil")
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	})()
}
