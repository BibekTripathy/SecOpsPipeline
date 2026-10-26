// Package audit records one tamper-evident entry per verdict.
//
// Entries are written as JSON lines, each carrying the SHA-256 of the previous
// entry. Append-only is enforced by the format rather than by file
// permissions: removing or editing a past entry breaks the chain, and Verify
// reports where.
package audit

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

// GenesisHash starts the chain.
const GenesisHash = "0000000000000000000000000000000000000000000000000000000000000000"

// Entry is one recorded verdict.
type Entry struct {
	Time    time.Time `json:"time"`
	PushID  string    `json:"push_id"`
	Repo    string    `json:"repo"`
	Ref     string    `json:"ref"`
	OldRev  string    `json:"old_rev"`
	NewRev  string    `json:"new_rev"`
	Actor   string    `json:"actor"`
	Verdict string    `json:"verdict"`

	FindingCount  int      `json:"finding_count"`
	ScannerErrors int      `json:"scanner_errors"`
	Reasons       []string `json:"reasons,omitempty"`

	// PrevHash chains this entry to the one before it. Hash is the digest of
	// this entry with Hash itself blanked.
	PrevHash string `json:"prev_hash"`
	Hash     string `json:"hash"`
}

// Log appends entries to a file.
type Log struct {
	mu   sync.Mutex
	f    *os.File
	last string
}

// Open opens or creates an audit log and reads the tail hash so a restart
// continues the existing chain.
func Open(filename string) (*Log, error) {
	last, err := tailHash(filename)
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open audit log: %w", err)
	}
	return &Log{f: f, last: last}, nil
}

// Append writes one entry, filling in PrevHash and Hash, and fsyncs so a
// verdict is durable before the push is forwarded or rejected.
func (l *Log) Append(e Entry) (Entry, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}
	e.PrevHash = l.last
	e.Hash = ""
	e.Hash = hashEntry(e)

	line, err := json.Marshal(e)
	if err != nil {
		return e, fmt.Errorf("marshal audit entry: %w", err)
	}
	if _, err := l.f.Write(append(line, '\n')); err != nil {
		return e, fmt.Errorf("write audit entry: %w", err)
	}
	if err := l.f.Sync(); err != nil {
		return e, fmt.Errorf("sync audit log: %w", err)
	}
	l.last = e.Hash
	return e, nil
}

func (l *Log) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.f.Close()
}

// Verify walks the chain and returns the number of valid entries, or an error
// naming the first entry that does not match.
func Verify(filename string) (int, error) {
	f, err := os.Open(filename)
	if err != nil {
		return 0, fmt.Errorf("open audit log: %w", err)
	}
	defer f.Close()

	prev := GenesisHash
	n := 0
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		if len(sc.Bytes()) == 0 {
			continue
		}
		var e Entry
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			return n, fmt.Errorf("entry %d: %w", n+1, err)
		}
		if e.PrevHash != prev {
			return n, fmt.Errorf("entry %d (%s): chain broken, prev_hash=%s want %s", n+1, e.PushID, e.PrevHash, prev)
		}
		want := e.Hash
		e.Hash = ""
		if got := hashEntry(e); got != want {
			return n, fmt.Errorf("entry %d (%s): content hash mismatch", n+1, e.PushID)
		}
		prev = want
		n++
	}
	if err := sc.Err(); err != nil {
		return n, fmt.Errorf("read audit log: %w", err)
	}
	return n, nil
}

func hashEntry(e Entry) string {
	b, err := json.Marshal(e)
	if err != nil {
		// Entry contains only marshalable types; a failure here is a bug.
		panic(fmt.Sprintf("audit: marshal entry for hashing: %v", err))
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// tailHash returns the hash of the last entry, or GenesisHash for a new log.
func tailHash(filename string) (string, error) {
	f, err := os.Open(filename)
	if os.IsNotExist(err) {
		return GenesisHash, nil
	}
	if err != nil {
		return "", fmt.Errorf("read audit log: %w", err)
	}
	defer f.Close()

	last := GenesisHash
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		if len(sc.Bytes()) == 0 {
			continue
		}
		var e Entry
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			return "", fmt.Errorf("corrupt audit log: %w", err)
		}
		last = e.Hash
	}
	return last, sc.Err()
}
