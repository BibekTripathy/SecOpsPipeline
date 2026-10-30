package deps

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/BibekTripathy/SecOpsPipeline/internal/finding"
)

func sampleVuln() Vulnerability {
	return Vulnerability{
		ID: "GHSA-test", Summary: "a problem", Severity: finding.SeverityHigh,
		FixedIn: "v1.0.1", Aliases: []string{"CVE-2026-0001"},
		fixed: map[string]string{"example.com/lib": "v1.0.1"},
	}
}

func TestDiskCacheRoundTrip(t *testing.T) {
	c, err := NewDiskCache(t.TempDir(), time.Hour)
	if err != nil {
		t.Fatalf("NewDiskCache: %v", err)
	}
	c.Put("GHSA-test", sampleVuln())

	got, ok := c.Get("GHSA-test")
	if !ok {
		t.Fatal("entry not found after Put")
	}
	if got.Severity != finding.SeverityHigh || got.Summary != "a problem" {
		t.Errorf("got %+v", got)
	}
	// fixed is unexported, so it only survives if persisted explicitly.
	if got.fixed["example.com/lib"] != "v1.0.1" {
		t.Errorf("fixed versions lost in the round trip: %+v", got.fixed)
	}
}

func TestDiskCacheSurvivesRestart(t *testing.T) {
	dir := t.TempDir()

	first, _ := NewDiskCache(dir, time.Hour)
	first.Put("GHSA-test", sampleVuln())

	// A new cache over the same directory is what a restart looks like.
	second, err := NewDiskCache(dir, time.Hour)
	if err != nil {
		t.Fatalf("NewDiskCache: %v", err)
	}
	if _, ok := second.Get("GHSA-test"); !ok {
		t.Error("the entry did not survive a restart, which is the point of a disk cache")
	}
}

func TestDiskCacheExpires(t *testing.T) {
	dir := t.TempDir()
	c, _ := NewDiskCache(dir, time.Nanosecond)
	c.Put("GHSA-test", sampleVuln())

	time.Sleep(2 * time.Millisecond)
	if _, ok := c.Get("GHSA-test"); ok {
		t.Error("an expired advisory was served; severities and fixes do get revised")
	}
}

func TestDiskCacheIgnoresCorruptEntry(t *testing.T) {
	dir := t.TempDir()
	c, _ := NewDiskCache(dir, time.Hour)
	if err := os.WriteFile(filepath.Join(dir, "GHSA-bad.json"), []byte("{{{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, ok := c.Get("GHSA-bad"); ok {
		t.Error("a corrupt entry was served")
	}
}

// TestDiskCacheRejectsUnsafeIDs: advisory ids come from an upstream
// response, so one must not be able to write outside the cache.
func TestDiskCacheRejectsUnsafeIDs(t *testing.T) {
	dir := t.TempDir()
	c, _ := NewDiskCache(dir, time.Hour)

	for _, id := range []string{"../escape", "a/b", "", ".", ".."} {
		c.Put(id, sampleVuln())
		if _, ok := c.path(id); ok {
			t.Errorf("path(%q) was accepted", id)
		}
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 0 {
		t.Errorf("unsafe ids wrote %d file(s) into the cache", len(entries))
	}
}

func TestPruneRemovesExpiredFiles(t *testing.T) {
	dir := t.TempDir()
	c, _ := NewDiskCache(dir, time.Nanosecond)
	c.Put("GHSA-test", sampleVuln())
	time.Sleep(2 * time.Millisecond)

	n, err := c.Prune()
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if n != 1 {
		t.Errorf("pruned %d entries, want 1", n)
	}
}
