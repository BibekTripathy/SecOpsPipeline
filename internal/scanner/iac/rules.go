// Package iac checks infrastructure definitions that a push changes:
// Dockerfiles, GitHub Actions workflows, Terraform and Kubernetes
// manifests.
//
// Detection is pattern based rather than a full parse of each format.
// That is a deliberate trade: this runs in the push path, and a complete
// HCL and YAML evaluator would be both slow and a large attack surface
// for a scanner. The cost is that a rule reasons about one line at a
// time and cannot follow a variable to its definition, so every rule
// here is written to fire only on an unambiguous literal. Anything
// needing real dataflow belongs in a dedicated IaC tool run in CI, not
// in a push gateway.
package iac

import (
	"regexp"

	"github.com/BibekTripathy/SecOpsPipeline/internal/finding"
)

// Kind groups rules by the file type they apply to.
type Kind string

const (
	KindDockerfile Kind = "dockerfile"
	KindActions    Kind = "github-actions"
	KindTerraform  Kind = "terraform"
	KindKubernetes Kind = "kubernetes"
)

// Rule is one line-level check.
type Rule struct {
	ID       string
	Kind     Kind
	Severity finding.Severity
	Message  string
	// Remediation is appended to the message, because a finding a
	// developer cannot act on is just an obstacle.
	Remediation string
	Pattern     *regexp.Regexp
	// Except suppresses a match, for the cases where a narrower pattern
	// is easier to express as an exclusion.
	Except *regexp.Regexp
	// InRunBlock limits the rule to lines inside a workflow's `run:`
	// block, where the text becomes a shell command. The same
	// interpolation under `env:` is the recommended safe form, so a
	// rule that cannot tell them apart would punish the fix.
	InRunBlock bool
}

// DefaultRules is the built-in rule set.
var DefaultRules = []Rule{
	// --- Dockerfile ----------------------------------------------------

	{
		ID: "docker-user-root", Kind: KindDockerfile,
		Severity:    finding.SeverityMedium,
		Message:     "container explicitly runs as root",
		Remediation: "add a non-root USER, or drop the explicit USER root",
		Pattern:     regexp.MustCompile(`(?im)^\s*USER\s+(root|0)\s*$`),
	},
	{
		ID: "docker-latest-tag", Kind: KindDockerfile,
		Severity:    finding.SeverityLow,
		Message:     "base image is pinned to :latest",
		Remediation: "pin a specific tag or digest, so a rebuild is reproducible",
		Pattern:     regexp.MustCompile(`(?im)^\s*FROM\s+\S+:latest\b`),
	},
	{
		ID: "docker-untagged-image", Kind: KindDockerfile,
		Severity:    finding.SeverityLow,
		Message:     "base image has no tag, so it resolves to :latest",
		Remediation: "pin a specific tag or digest",
		// A FROM with no colon and no digest, ignoring build stages and
		// scratch.
		Pattern: regexp.MustCompile(`(?im)^\s*FROM\s+([a-z0-9][a-z0-9._/-]*)\s*(?:AS\s+\S+)?\s*$`),
		Except:  regexp.MustCompile(`(?i)^\s*FROM\s+(scratch|\S*[:@]\S*)`),
	},
	{
		ID: "docker-add-remote-url", Kind: KindDockerfile,
		Severity:    finding.SeverityMedium,
		Message:     "ADD fetches a remote URL",
		Remediation: "use COPY for local files, or RUN curl with a checksum you verify",
		Pattern:     regexp.MustCompile(`(?im)^\s*ADD\s+https?://`),
	},
	{
		ID: "docker-curl-pipe-shell", Kind: KindDockerfile,
		Severity:    finding.SeverityHigh,
		Message:     "script downloaded and piped straight into a shell",
		Remediation: "download, verify a checksum or signature, then run",
		Pattern:     regexp.MustCompile(`(?i)(curl|wget)[^\n|]*\|\s*(sudo\s+)?(ba|z|k)?sh\b`),
	},

	// --- GitHub Actions --------------------------------------------------

	{
		ID: "actions-pull-request-target", Kind: KindActions,
		Severity:    finding.SeverityCritical,
		Message:     "pull_request_target runs with repository secrets",
		Remediation: "use pull_request, or never check out the PR head under pull_request_target",
		Pattern:     regexp.MustCompile(`(?m)^\s*pull_request_target\s*:`),
	},
	{
		ID: "actions-script-injection", Kind: KindActions,
		Severity:    finding.SeverityHigh,
		Message:     "untrusted event data interpolated into a shell command",
		Remediation: "pass it through an env: variable and reference \"$VAR\" instead",
		Pattern: regexp.MustCompile(
			`\$\{\{\s*github\.(event\.(issue|pull_request|comment|review)\.|head_ref|event\.head_commit\.message)`),
		InRunBlock: true,
	},
	{
		ID: "actions-unpinned-third-party", Kind: KindActions,
		Severity:    finding.SeverityMedium,
		Message:     "third-party action referenced by a mutable ref",
		Remediation: "pin the action to a full commit SHA",
		// A uses: with a branch-like ref rather than a 40-char SHA.
		Pattern: regexp.MustCompile(`(?m)^\s*-?\s*uses\s*:\s*([A-Za-z0-9_.-]+)/\S+@(main|master|HEAD|v?\d+(\.\d+)*)\s*$`),
		// Actions published by GitHub itself are the common, accepted case.
		Except: regexp.MustCompile(`(?m)uses\s*:\s*(actions|github|docker)/`),
	},
	{
		ID: "actions-write-all-permissions", Kind: KindActions,
		Severity:    finding.SeverityHigh,
		Message:     "workflow token granted write-all permissions",
		Remediation: "grant only the scopes the job needs",
		Pattern:     regexp.MustCompile(`(?m)^\s*permissions\s*:\s*write-all\s*$`),
	},
	{
		ID: "actions-self-hosted-on-public", Kind: KindActions,
		Severity:    finding.SeverityMedium,
		Message:     "job runs on a self-hosted runner",
		Remediation: "confirm the runner is not reachable by forked-PR workflows",
		Pattern:     regexp.MustCompile(`(?m)runs-on\s*:.*self-hosted`),
	},

	// --- Terraform --------------------------------------------------------

	{
		ID: "terraform-public-acl", Kind: KindTerraform,
		Severity:    finding.SeverityCritical,
		Message:     "storage granted a public ACL",
		Remediation: "use a bucket policy scoped to the principals that need it",
		Pattern:     regexp.MustCompile(`(?m)acl\s*=\s*"(public-read|public-read-write|authenticated-read)"`),
	},
	{
		ID: "terraform-open-ingress", Kind: KindTerraform,
		Severity:    finding.SeverityHigh,
		Message:     "security group allows ingress from the whole internet",
		Remediation: "restrict cidr_blocks to the networks that need access",
		Pattern:     regexp.MustCompile(`(?m)cidr_blocks\s*=\s*\[\s*"0\.0\.0\.0/0"`),
	},
	{
		ID: "terraform-unencrypted-storage", Kind: KindTerraform,
		Severity:    finding.SeverityMedium,
		Message:     "storage encryption explicitly disabled",
		Remediation: "leave encryption enabled, or state why it is not needed",
		Pattern:     regexp.MustCompile(`(?m)(encrypted|storage_encrypted|enable_encryption)\s*=\s*false`),
	},
	{
		ID: "terraform-plaintext-password", Kind: KindTerraform,
		Severity:    finding.SeverityHigh,
		Message:     "password set to a literal value",
		Remediation: "read it from a secret manager or a sensitive variable",
		Pattern:     regexp.MustCompile(`(?m)(password|secret)\s*=\s*"[^"$][^"]{7,}"`),
	},

	// --- Kubernetes --------------------------------------------------------

	{
		ID: "k8s-privileged-container", Kind: KindKubernetes,
		Severity:    finding.SeverityCritical,
		Message:     "container runs privileged",
		Remediation: "drop privileged and add only the capabilities needed",
		Pattern:     regexp.MustCompile(`(?m)^\s*privileged\s*:\s*true\s*$`),
	},
	{
		ID: "k8s-host-network", Kind: KindKubernetes,
		Severity:    finding.SeverityHigh,
		Message:     "pod shares the host network namespace",
		Remediation: "use a Service rather than hostNetwork",
		Pattern:     regexp.MustCompile(`(?m)^\s*hostNetwork\s*:\s*true\s*$`),
	},
	{
		ID: "k8s-host-path-mount", Kind: KindKubernetes,
		Severity:    finding.SeverityHigh,
		Message:     "pod mounts a path from the host filesystem",
		Remediation: "use a PersistentVolume, or confirm the path is safe to expose",
		Pattern:     regexp.MustCompile(`(?m)^\s*-?\s*hostPath\s*:`),
	},
	{
		ID: "k8s-run-as-root", Kind: KindKubernetes,
		Severity:    finding.SeverityMedium,
		Message:     "container explicitly runs as uid 0",
		Remediation: "set runAsUser to a non-zero uid and runAsNonRoot: true",
		Pattern:     regexp.MustCompile(`(?m)^\s*runAsUser\s*:\s*0\s*$`),
	},
	{
		ID: "k8s-allow-privilege-escalation", Kind: KindKubernetes,
		Severity:    finding.SeverityMedium,
		Message:     "privilege escalation explicitly allowed",
		Remediation: "set allowPrivilegeEscalation: false",
		Pattern:     regexp.MustCompile(`(?m)^\s*allowPrivilegeEscalation\s*:\s*true\s*$`),
	},
}
