package signature

import (
	"context"
	"testing"

	"github.com/BibekTripathy/SecOpsPipeline/internal/gitutil"
	"github.com/BibekTripathy/SecOpsPipeline/internal/scanner"
)

func scan(t *testing.T, requireSigned bool, states ...gitutil.SignatureState) int {
	t.Helper()
	target := &scanner.Target{}
	for i, s := range states {
		target.Commits = append(target.Commits, gitutil.Commit{Hash: string(rune('a' + i)), Signature: s})
	}
	found, err := New(requireSigned).Scan(context.Background(), target)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	return len(found)
}

func TestGoodSignaturesProduceNoFindings(t *testing.T) {
	if n := scan(t, true, gitutil.SigGood, gitutil.SigGood); n != 0 {
		t.Errorf("findings = %d, want 0", n)
	}
}

func TestBadAndUntrustedAlwaysReported(t *testing.T) {
	if n := scan(t, false, gitutil.SigBad, gitutil.SigUnknownKey); n != 2 {
		t.Errorf("findings = %d, want 2 even when signing is not required", n)
	}
}

func TestUnsignedOnlyReportedWhenRequired(t *testing.T) {
	if n := scan(t, false, gitutil.SigNoSignature); n != 0 {
		t.Errorf("findings = %d, want 0 when signing is not required", n)
	}
	if n := scan(t, true, gitutil.SigNoSignature); n != 1 {
		t.Errorf("findings = %d, want 1 when signing is required", n)
	}
}
