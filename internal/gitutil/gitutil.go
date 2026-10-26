// Package gitutil wraps the git plumbing the gateway needs to describe a push.
//
// It shells out to the git binary rather than using a pure-Go implementation:
// the gateway already requires git on PATH to run git-receive-pack, and the
// plumbing commands used here are stable across every git version we support.
package gitutil

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

// ZeroOID is the all-zero object id git sends for a created or deleted ref.
const ZeroOID = "0000000000000000000000000000000000000000"

// Commit is one new commit introduced by a push.
type Commit struct {
	Hash      string
	Author    string
	Email     string
	Subject   string
	Signature SignatureState
}

// SignatureState mirrors the %G? format of git-log.
type SignatureState string

const (
	SigGood        SignatureState = "good"
	SigBad         SignatureState = "bad"
	SigUnknownKey  SignatureState = "unknown-key"
	SigNoSignature SignatureState = "none"
)

// ChangedFile is one path touched by a push, with the blob id of its new
// content. Blob is empty when Status is "D" (deleted).
type ChangedFile struct {
	Path   string
	Status string // A, M, D, R...
	Blob   string
}

// Run executes a git plumbing command inside repo and returns stdout.
func Run(ctx context.Context, repo string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "git", append([]string{"-C", repo}, args...)...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return stdout.Bytes(), nil
}

// NewCommits lists the commits reachable from newRev but not from oldRev --
// exactly the commits this push is responsible for. A zero oldRev (branch
// creation) is treated as "everything not already on another ref".
func NewCommits(ctx context.Context, repo, oldRev, newRev string) ([]Commit, error) {
	const sep = "\x1f"
	format := "--format=%H" + sep + "%an" + sep + "%ae" + sep + "%G?" + sep + "%s"

	var rangeArg []string
	if oldRev == "" || oldRev == ZeroOID {
		rangeArg = []string{newRev, "--not", "--all"}
	} else {
		rangeArg = []string{oldRev + ".." + newRev}
	}

	args := append([]string{"rev-list", format}, rangeArg...)
	out, err := Run(ctx, repo, args...)
	if err != nil {
		return nil, err
	}

	var commits []Commit
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, sep, 5)
		if len(parts) != 5 {
			return nil, fmt.Errorf("unexpected rev-list output: %q", line)
		}
		commits = append(commits, Commit{
			Hash:      parts[0],
			Author:    parts[1],
			Email:     parts[2],
			Signature: parseSignature(parts[3]),
			Subject:   parts[4],
		})
	}
	return commits, nil
}

func parseSignature(g string) SignatureState {
	switch g {
	case "G", "U":
		return SigGood
	case "B":
		return SigBad
	case "E", "X", "Y", "R":
		return SigUnknownKey
	default:
		return SigNoSignature
	}
}

// ChangedFiles lists the paths the push touches, with the blob id of the new
// content so scanners can read a file version without checking out a worktree.
func ChangedFiles(ctx context.Context, repo, oldRev, newRev string) ([]ChangedFile, error) {
	args := []string{"diff-tree", "-r", "--no-commit-id", "--raw", "-z"}
	if oldRev == "" || oldRev == ZeroOID {
		args = append(args, "--root", newRev)
	} else {
		args = append(args, oldRev, newRev)
	}

	out, err := Run(ctx, repo, args...)
	if err != nil {
		return nil, err
	}
	return parseRawDiff(out)
}

// parseRawDiff reads `diff-tree --raw -z` records, each of the shape
// ":<srcmode> <dstmode> <srcsha> <dstsha> <status>\x00<path>\x00".
func parseRawDiff(out []byte) ([]ChangedFile, error) {
	fields := strings.Split(string(out), "\x00")
	var files []ChangedFile
	for i := 0; i < len(fields); i++ {
		meta := fields[i]
		if !strings.HasPrefix(meta, ":") {
			continue
		}
		cols := strings.Fields(strings.TrimPrefix(meta, ":"))
		if len(cols) < 5 {
			return nil, fmt.Errorf("unexpected diff-tree record: %q", meta)
		}
		status := cols[4]
		i++
		if i >= len(fields) {
			return nil, fmt.Errorf("diff-tree record %q has no path", meta)
		}
		path := fields[i]
		// Renames and copies carry a second path; the destination is what
		// we scan.
		if strings.HasPrefix(status, "R") || strings.HasPrefix(status, "C") {
			i++
			if i >= len(fields) {
				return nil, fmt.Errorf("diff-tree rename %q has no destination", meta)
			}
			path = fields[i]
		}
		blob := cols[3]
		if blob == ZeroOID || strings.HasPrefix(status, "D") {
			blob = ""
		}
		files = append(files, ChangedFile{Path: path, Status: status, Blob: blob})
	}
	return files, nil
}

// ReadBlob returns the contents of a blob by object id.
func ReadBlob(ctx context.Context, repo, blob string) ([]byte, error) {
	return Run(ctx, repo, "cat-file", "blob", blob)
}

// BlobSize returns the size of a blob in bytes without reading it, so scanners
// can skip files above a configured limit.
func BlobSize(ctx context.Context, repo, blob string) (int64, error) {
	out, err := Run(ctx, repo, "cat-file", "-s", blob)
	if err != nil {
		return 0, err
	}
	return strconv.ParseInt(strings.TrimSpace(string(out)), 10, 64)
}
