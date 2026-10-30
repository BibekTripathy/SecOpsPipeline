// Package sarif renders findings as SARIF 2.1.0.
//
// SARIF is what makes the gateway's output portable: GitHub code scanning,
// VS Code and most security dashboards read it directly, so a verdict can be
// reviewed somewhere other than the terminal that saw it.
package sarif

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"

	"github.com/BibekTripathy/SecOpsPipeline/internal/finding"
)

const (
	version = "2.1.0"
	schema  = "https://json.schemastore.org/sarif-2.1.0.json"
	toolURI = "https://github.com/BibekTripathy/SecOpsPipeline"
)

// Log is the top-level SARIF document.
type Log struct {
	Schema  string `json:"$schema"`
	Version string `json:"version"`
	Runs    []Run  `json:"runs"`
}

type Run struct {
	Tool       Tool              `json:"tool"`
	Results    []Result          `json:"results"`
	Invocation []Invocation      `json:"invocations,omitempty"`
	Properties map[string]string `json:"properties,omitempty"`
}

type Tool struct {
	Driver Driver `json:"driver"`
}

type Driver struct {
	Name           string `json:"name"`
	Version        string `json:"version"`
	InformationURI string `json:"informationUri"`
	Rules          []Rule `json:"rules,omitempty"`
}

type Rule struct {
	ID               string           `json:"id"`
	ShortDescription Message          `json:"shortDescription"`
	Properties       RuleProperties   `json:"properties,omitempty"`
	DefaultConfig    *ReportingConfig `json:"defaultConfiguration,omitempty"`
}

type RuleProperties struct {
	Tags []string `json:"tags,omitempty"`
}

type ReportingConfig struct {
	Level string `json:"level"`
}

type Result struct {
	RuleID       string            `json:"ruleId"`
	Level        string            `json:"level"`
	Message      Message           `json:"message"`
	Locations    []Location        `json:"locations,omitempty"`
	Properties   map[string]string `json:"properties,omitempty"`
	Suppressions []Suppression     `json:"suppressions,omitempty"`
}

// Suppression marks a result as accepted. SARIF-aware tools hide
// suppressed results by default while keeping them in the record.
type Suppression struct {
	Kind          string `json:"kind"`
	Justification string `json:"justification,omitempty"`
}

type Message struct {
	Text string `json:"text"`
}

type Location struct {
	PhysicalLocation PhysicalLocation `json:"physicalLocation"`
}

type PhysicalLocation struct {
	ArtifactLocation ArtifactLocation `json:"artifactLocation"`
	Region           *Region          `json:"region,omitempty"`
}

type ArtifactLocation struct {
	URI string `json:"uri"`
}

type Region struct {
	StartLine int `json:"startLine"`
}

type Invocation struct {
	ExecutionSuccessful bool   `json:"executionSuccessful"`
	CommandLine         string `json:"commandLine,omitempty"`
}

// level maps our severities onto SARIF's four, which is all it has.
func level(s finding.Severity) string {
	switch s {
	case finding.SeverityCritical, finding.SeverityHigh:
		return "error"
	case finding.SeverityMedium:
		return "warning"
	case finding.SeverityLow:
		return "note"
	default:
		return "none"
	}
}

// Build renders findings as a SARIF log. toolVersion identifies the gateway
// build, and properties carries push context (repo, ref, verdict).
func Build(findings []finding.Finding, toolVersion string, properties map[string]string) Log {
	rules := map[string]Rule{}
	results := make([]Result, 0, len(findings))

	for _, f := range findings {
		if _, seen := rules[f.RuleID]; !seen {
			rules[f.RuleID] = Rule{
				ID:               f.RuleID,
				ShortDescription: Message{Text: f.Message},
				Properties:       RuleProperties{Tags: []string{f.Scanner}},
				DefaultConfig:    &ReportingConfig{Level: level(f.Severity)},
			}
		}

		r := Result{
			RuleID:     f.RuleID,
			Level:      level(f.Severity),
			Message:    Message{Text: resultMessage(f)},
			Properties: resultProperties(f),
		}
		if f.File != "" {
			loc := Location{PhysicalLocation: PhysicalLocation{
				ArtifactLocation: ArtifactLocation{URI: f.File},
			}}
			if f.Line > 0 {
				loc.PhysicalLocation.Region = &Region{StartLine: f.Line}
			}
			r.Locations = append(r.Locations, loc)
		}
		results = append(results, r)
	}

	// Sort rules so the same findings always produce byte-identical SARIF;
	// otherwise the reports are not diffable between runs.
	ruleList := make([]Rule, 0, len(rules))
	for _, r := range rules {
		ruleList = append(ruleList, r)
	}
	sort.Slice(ruleList, func(i, j int) bool { return ruleList[i].ID < ruleList[j].ID })

	return Log{
		Schema:  schema,
		Version: version,
		Runs: []Run{{
			Tool: Tool{Driver: Driver{
				Name:           "commit-quarantine-gateway",
				Version:        toolVersion,
				InformationURI: toolURI,
				Rules:          ruleList,
			}},
			Results:    results,
			Invocation: []Invocation{{ExecutionSuccessful: true}},
			Properties: properties,
		}},
	}
}

func resultMessage(f finding.Finding) string {
	if f.Redacted != "" {
		return fmt.Sprintf("%s (%s)", f.Message, f.Redacted)
	}
	return f.Message
}

func resultProperties(f finding.Finding) map[string]string {
	props := map[string]string{
		"scanner":  f.Scanner,
		"severity": f.Severity.String(),
	}
	if f.Commit != "" {
		props["commit"] = f.Commit
	}
	for k, v := range f.Metadata {
		props[k] = v
	}
	return props
}

// Write renders the log as indented JSON.
func Write(w io.Writer, log Log) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(log); err != nil {
		return fmt.Errorf("write sarif: %w", err)
	}
	return nil
}

// SuppressedFinding is a finding waived by a baseline.
type SuppressedFinding struct {
	Finding       finding.Finding
	Justification string
}

// AppendSuppressed adds waived findings to a log, marked with SARIF's
// own suppression mechanism.
//
// They are included rather than dropped so the report shows what the
// baseline hid: a reader can see the exception, its justification, and
// decide whether it still holds. Tools that honour SARIF suppressions
// will hide them from the default view anyway.
func AppendSuppressed(log *Log, suppressed []SuppressedFinding) {
	if len(suppressed) == 0 || len(log.Runs) == 0 {
		return
	}
	run := &log.Runs[0]

	for _, s := range suppressed {
		f := s.Finding
		r := Result{
			RuleID:     f.RuleID,
			Level:      level(f.Severity),
			Message:    Message{Text: resultMessage(f)},
			Properties: resultProperties(f),
			Suppressions: []Suppression{{
				Kind:          "external",
				Justification: s.Justification,
			}},
		}
		if f.File != "" {
			loc := Location{PhysicalLocation: PhysicalLocation{
				ArtifactLocation: ArtifactLocation{URI: f.File},
			}}
			if f.Line > 0 {
				loc.PhysicalLocation.Region = &Region{StartLine: f.Line}
			}
			r.Locations = append(r.Locations, loc)
		}
		run.Results = append(run.Results, r)
	}
}
