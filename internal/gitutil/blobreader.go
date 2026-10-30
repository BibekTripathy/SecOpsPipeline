package gitutil

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os/exec"
	"strconv"
	"strings"
	"sync"
)

// BlobReader streams blob contents from one long-lived `git cat-file
// --batch` process.
//
// The naive alternative -- `git cat-file -s` then `git cat-file blob` per
// file -- costs two process spawns per changed file, and on a push of any
// size that spawn cost dominates everything the scanners actually do. A
// benchmark of a 200-file push spent roughly a second there before this
// existed. One process for the whole push removes it.
//
// A BlobReader is safe for concurrent use but serialises its callers: it
// owns a single pipe whose request and response order must match, so Read
// holds a lock for the whole exchange. Plugins scanning in parallel will
// contend here, which is still far cheaper than a process spawn each.
type BlobReader struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout *bufio.Reader

	mu     sync.Mutex
	closed bool
}

// NewBlobReader starts the batch process. Close it when the push is done.
func NewBlobReader(ctx context.Context, repo Repo) (*BlobReader, error) {
	cmd := exec.CommandContext(ctx, "git", "-C", repo.Path, "cat-file", "--batch")
	cmd.Env = repo.env()

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("cat-file stdin: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("cat-file stdout: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start cat-file: %w", err)
	}

	return &BlobReader{
		cmd:    cmd,
		stdin:  stdin,
		stdout: bufio.NewReaderSize(stdout, 64*1024),
	}, nil
}

// ErrBlobTooLarge reports a blob skipped because of maxBytes.
type ErrBlobTooLarge struct {
	OID  string
	Size int64
}

func (e *ErrBlobTooLarge) Error() string {
	return fmt.Sprintf("blob %s is %d bytes", e.OID, e.Size)
}

// Read returns a blob's contents.
//
// When maxBytes is positive and the blob is larger, the content is drained
// and discarded and *ErrBlobTooLarge is returned: the protocol is a strict
// request/response stream, so the bytes must be consumed either way to
// keep later reads aligned.
func (b *BlobReader) Read(oid string, maxBytes int64) ([]byte, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return nil, fmt.Errorf("blob reader is closed")
	}

	if _, err := io.WriteString(b.stdin, oid+"\n"); err != nil {
		return nil, fmt.Errorf("request blob %s: %w", oid, err)
	}

	header, err := b.stdout.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("read blob header for %s: %w", oid, err)
	}
	header = strings.TrimRight(header, "\n")

	// "<oid> missing" for an unknown object.
	fields := strings.Fields(header)
	if len(fields) == 2 && fields[1] == "missing" {
		return nil, fmt.Errorf("blob %s is missing", oid)
	}
	if len(fields) != 3 {
		return nil, fmt.Errorf("unexpected cat-file header %q", header)
	}

	size, err := strconv.ParseInt(fields[2], 10, 64)
	if err != nil {
		return nil, fmt.Errorf("parse blob size in %q: %w", header, err)
	}

	// git writes size bytes then a trailing newline.
	if maxBytes > 0 && size > maxBytes {
		if _, err := b.stdout.Discard(int(size) + 1); err != nil {
			return nil, fmt.Errorf("discard oversized blob %s: %w", oid, err)
		}
		return nil, &ErrBlobTooLarge{OID: oid, Size: size}
	}

	content := make([]byte, size)
	if _, err := io.ReadFull(b.stdout, content); err != nil {
		return nil, fmt.Errorf("read blob %s: %w", oid, err)
	}
	if _, err := b.stdout.Discard(1); err != nil {
		return nil, fmt.Errorf("read blob terminator for %s: %w", oid, err)
	}
	return content, nil
}

// Close shuts the batch process down. It is safe to call more than once.
func (b *BlobReader) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return nil
	}
	b.closed = true

	b.stdin.Close()
	// cat-file exits cleanly once stdin closes; Wait reaps it.
	if err := b.cmd.Wait(); err != nil {
		return fmt.Errorf("cat-file exited: %w", err)
	}
	return nil
}
