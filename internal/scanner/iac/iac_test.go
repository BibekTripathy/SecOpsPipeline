package iac

import (
	"strings"
	"testing"
)

func scan(t *testing.T, path, content string) []string {
	t.Helper()
	kind, ok := KindOf(path)
	if !ok {
		t.Fatalf("KindOf(%q) found no kind", path)
	}
	var ids []string
	for _, f := range New().ScanContent(path, kind, []byte(content)) {
		ids = append(ids, f.RuleID)
	}
	return ids
}

func has(ids []string, want string) bool {
	for _, id := range ids {
		if id == want {
			return true
		}
	}
	return false
}

func TestKindOf(t *testing.T) {
	cases := map[string]Kind{
		"Dockerfile":                    KindDockerfile,
		"docker/Dockerfile.prod":        KindDockerfile,
		"build.dockerfile":              KindDockerfile,
		".github/workflows/ci.yml":      KindActions,
		".github/workflows/deploy.yaml": KindActions,
		"infra/main.tf":                 KindTerraform,
		"k8s/deployment.yaml":           KindKubernetes,
	}
	for path, want := range cases {
		got, ok := KindOf(path)
		if !ok || got != want {
			t.Errorf("KindOf(%q) = (%q, %v), want %q", path, got, ok, want)
		}
	}
	for _, path := range []string{"main.go", "README.md", "package.json"} {
		if _, ok := KindOf(path); ok {
			t.Errorf("KindOf(%q) should find no kind", path)
		}
	}
}

func TestDockerfileRules(t *testing.T) {
	ids := scan(t, "Dockerfile", `FROM golang:latest
USER root
ADD https://example.com/tool.tar.gz /tmp/
RUN curl -sSL https://example.com/install.sh | sh
`)
	for _, want := range []string{
		"docker-latest-tag", "docker-user-root",
		"docker-add-remote-url", "docker-curl-pipe-shell",
	} {
		if !has(ids, want) {
			t.Errorf("%s not detected; got %v", want, ids)
		}
	}
}

func TestDockerfileCleanFileIsQuiet(t *testing.T) {
	ids := scan(t, "Dockerfile", `FROM golang:1.23.4-alpine
RUN adduser -D app
USER app
COPY --chown=app:app . /src
RUN go build -o /bin/app ./cmd/app
`)
	if len(ids) != 0 {
		t.Errorf("false positives on a well-written Dockerfile: %v", ids)
	}
}

func TestDockerfileUntaggedImage(t *testing.T) {
	if ids := scan(t, "Dockerfile", "FROM ubuntu\n"); !has(ids, "docker-untagged-image") {
		t.Errorf("untagged image not detected: %v", ids)
	}
	// A digest, an explicit tag and scratch are all pinned already.
	for _, line := range []string{
		"FROM ubuntu:24.04\n",
		"FROM ubuntu@sha256:abc123\n",
		"FROM scratch\n",
	} {
		if ids := scan(t, "Dockerfile", line); has(ids, "docker-untagged-image") {
			t.Errorf("false positive on %q: %v", strings.TrimSpace(line), ids)
		}
	}
}

func TestActionsRules(t *testing.T) {
	ids := scan(t, ".github/workflows/ci.yml", `on:
  pull_request_target:
permissions: write-all
jobs:
  build:
    runs-on: self-hosted
    steps:
      - uses: some-vendor/action@v1
      - run: echo "${{ github.event.pull_request.title }}"
`)
	for _, want := range []string{
		"actions-pull-request-target", "actions-write-all-permissions",
		"actions-self-hosted-on-public", "actions-unpinned-third-party",
		"actions-script-injection",
	} {
		if !has(ids, want) {
			t.Errorf("%s not detected; got %v", want, ids)
		}
	}
}

func TestActionsCleanWorkflowIsQuiet(t *testing.T) {
	ids := scan(t, ".github/workflows/ci.yml", `on:
  pull_request:
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: some-vendor/action@8f4b7f84864484a7bf31766abe9204da3cbe65b3
      - name: greet
        env:
          TITLE: ${{ github.event.pull_request.title }}
        run: echo "$TITLE"
`)
	if len(ids) != 0 {
		t.Errorf("false positives on a well-written workflow: %v", ids)
	}
}

func TestTerraformRules(t *testing.T) {
	ids := scan(t, "infra/main.tf", `resource "aws_s3_bucket" "b" {
  acl = "public-read"
}
resource "aws_security_group" "sg" {
  ingress {
    cidr_blocks = ["0.0.0.0/0"]
  }
}
resource "aws_db_instance" "db" {
  storage_encrypted = false
  password          = "hunter2hunter2"
}
`)
	for _, want := range []string{
		"terraform-public-acl", "terraform-open-ingress",
		"terraform-unencrypted-storage", "terraform-plaintext-password",
	} {
		if !has(ids, want) {
			t.Errorf("%s not detected; got %v", want, ids)
		}
	}
}

func TestTerraformCleanFileIsQuiet(t *testing.T) {
	ids := scan(t, "infra/main.tf", `resource "aws_s3_bucket" "b" {
  bucket = var.bucket_name
}
resource "aws_security_group" "sg" {
  ingress {
    cidr_blocks = var.allowed_cidrs
  }
}
resource "aws_db_instance" "db" {
  storage_encrypted = true
  password          = var.db_password
}
`)
	if len(ids) != 0 {
		t.Errorf("false positives on well-written Terraform: %v", ids)
	}
}

func TestKubernetesRules(t *testing.T) {
	ids := scan(t, "k8s/deployment.yaml", `spec:
  hostNetwork: true
  containers:
    - name: app
      securityContext:
        privileged: true
        runAsUser: 0
        allowPrivilegeEscalation: true
  volumes:
    - hostPath:
        path: /var/run/docker.sock
`)
	for _, want := range []string{
		"k8s-host-network", "k8s-privileged-container", "k8s-run-as-root",
		"k8s-allow-privilege-escalation", "k8s-host-path-mount",
	} {
		if !has(ids, want) {
			t.Errorf("%s not detected; got %v", want, ids)
		}
	}
}

func TestKubernetesCleanManifestIsQuiet(t *testing.T) {
	ids := scan(t, "k8s/deployment.yaml", `spec:
  containers:
    - name: app
      image: acme/api:1.2.3
      securityContext:
        runAsNonRoot: true
        runAsUser: 10001
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
      resources:
        limits:
          cpu: "1"
`)
	if len(ids) != 0 {
		t.Errorf("false positives on a hardened manifest: %v", ids)
	}
}

// TestCommentedDirectivesAreIgnored: unlike a committed secret, a
// commented-out directive is not active configuration.
func TestCommentedDirectivesAreIgnored(t *testing.T) {
	if ids := scan(t, "Dockerfile", "# USER root\n"); len(ids) != 0 {
		t.Errorf("commented Dockerfile directive reported: %v", ids)
	}
	if ids := scan(t, "infra/main.tf", `# acl = "public-read"`); len(ids) != 0 {
		t.Errorf("commented Terraform line reported: %v", ids)
	}
	if ids := scan(t, "k8s/d.yaml", "#  privileged: true\n"); len(ids) != 0 {
		t.Errorf("commented Kubernetes line reported: %v", ids)
	}
}

func TestEveryRuleHasRemediation(t *testing.T) {
	// A finding a developer cannot act on is just an obstacle.
	for _, r := range DefaultRules {
		if r.Remediation == "" {
			t.Errorf("rule %s has no remediation", r.ID)
		}
		if r.Message == "" {
			t.Errorf("rule %s has no message", r.ID)
		}
	}
}

func TestRuleIDsAreUnique(t *testing.T) {
	seen := map[string]bool{}
	for _, r := range DefaultRules {
		if seen[r.ID] {
			t.Errorf("duplicate rule id %s", r.ID)
		}
		seen[r.ID] = true
	}
}
