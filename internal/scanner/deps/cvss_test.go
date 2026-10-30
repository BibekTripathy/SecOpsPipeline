package deps

import (
	"math"
	"testing"

	"github.com/BibekTripathy/SecOpsPipeline/internal/finding"
)

func TestCVSSScoreMatchesPublishedVectors(t *testing.T) {
	// Vectors and scores taken from published CVE records, so the
	// implementation is checked against the specification rather than
	// against itself.
	cases := []struct {
		vector string
		want   float64
	}{
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8},  // Log4Shell class
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0}, // scope changed
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5},  // info disclosure
		{"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8},  // local privesc
		{"CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N", 3.1},  // low
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 7.5},  // availability
		{"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1},  // reflected XSS
	}

	for _, c := range cases {
		got, ok := CVSSScore(c.vector)
		if !ok {
			t.Errorf("CVSSScore(%q) reported failure", c.vector)
			continue
		}
		if math.Abs(got-c.want) > 0.05 {
			t.Errorf("CVSSScore(%q) = %.1f, want %.1f", c.vector, got, c.want)
		}
	}
}

func TestCVSSScoreRejectsUnusableVectors(t *testing.T) {
	for _, v := range []string{
		"",
		"not a vector",
		"CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P", // v2, different formula
		"CVSS:3.1/AV:N/AC:L",                  // missing metrics
		"CVSS:3.1/AV:Z/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", // bad value
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/C:H/I:H/A:H",     // no scope
	} {
		if _, ok := CVSSScore(v); ok {
			t.Errorf("CVSSScore(%q) should have reported failure", v)
		}
	}
}

func TestSeverityFromScoreBoundaries(t *testing.T) {
	cases := map[float64]finding.Severity{
		10.0: finding.SeverityCritical,
		9.0:  finding.SeverityCritical,
		8.9:  finding.SeverityHigh,
		7.0:  finding.SeverityHigh,
		6.9:  finding.SeverityMedium,
		4.0:  finding.SeverityMedium,
		3.9:  finding.SeverityLow,
		0.1:  finding.SeverityLow,
		0.0:  finding.SeverityInfo,
	}
	for score, want := range cases {
		if got := SeverityFromScore(score); got != want {
			t.Errorf("SeverityFromScore(%.1f) = %s, want %s", score, got, want)
		}
	}
}

func TestSeverityPrefersCVSSOverFallback(t *testing.T) {
	var v osvVuln
	v.Severity = []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	}{{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}

	// With no database_specific rating, the vector must be used rather
	// than the Medium fallback.
	if got := severityOf(v); got != finding.SeverityCritical {
		t.Errorf("severity = %s, want critical from the CVSS vector", got)
	}
}

func TestDatabaseSpecificWinsOverVector(t *testing.T) {
	var v osvVuln
	v.DatabaseSpecific.Severity = "LOW"
	v.Severity = []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	}{{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}

	// The advisory curator's own rating reflects context the vector
	// does not carry, so it is preferred where present.
	if got := severityOf(v); got != finding.SeverityLow {
		t.Errorf("severity = %s, want the curated low rating", got)
	}
}
