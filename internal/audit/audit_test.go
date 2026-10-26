package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestChainVerifies(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	log, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	for _, v := range []string{"release", "block", "hold"} {
		if _, err := log.Append(Entry{PushID: v, Verdict: v}); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}
	log.Close()

	n, err := Verify(path)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if n != 3 {
		t.Errorf("verified %d entries, want 3", n)
	}
}

func TestChainSurvivesReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	log, _ := Open(path)
	log.Append(Entry{PushID: "one", Verdict: "release"})
	log.Close()

	log2, err := Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	log2.Append(Entry{PushID: "two", Verdict: "block"})
	log2.Close()

	if n, err := Verify(path); err != nil || n != 2 {
		t.Errorf("Verify = (%d, %v), want (2, nil)", n, err)
	}
}

func TestVerifyDetectsTampering(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	log, _ := Open(path)
	log.Append(Entry{PushID: "one", Verdict: "block"})
	log.Append(Entry{PushID: "two", Verdict: "block"})
	log.Close()

	// Rewrite a past verdict, as an attacker covering a blocked push would.
	b, _ := os.ReadFile(path)
	tampered := strings.Replace(string(b), `"verdict":"block"`, `"verdict":"release"`, 1)
	os.WriteFile(path, []byte(tampered), 0o600)

	if _, err := Verify(path); err == nil {
		t.Error("Verify returned nil on a tampered log, want error")
	}
}

func TestVerifyDetectsDeletedEntry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	log, _ := Open(path)
	log.Append(Entry{PushID: "one"})
	log.Append(Entry{PushID: "two"})
	log.Append(Entry{PushID: "three"})
	log.Close()

	b, _ := os.ReadFile(path)
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	os.WriteFile(path, []byte(lines[0]+"\n"+lines[2]+"\n"), 0o600)

	if _, err := Verify(path); err == nil {
		t.Error("Verify returned nil after an entry was removed, want error")
	}
}
