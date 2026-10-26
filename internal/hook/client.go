package hook

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"
)

// DialTimeout bounds how long the hook waits to reach the gateway.
const DialTimeout = 5 * time.Second

// ScanTimeout bounds how long the hook waits for a verdict. It is generous
// because it covers every scanner running over the whole push.
const ScanTimeout = 10 * time.Minute

// ParseStdin reads the ref updates git feeds the pre-receive hook, one
// "<old> <new> <ref>" line per updated ref.
func ParseStdin(r io.Reader) ([]RefUpdate, error) {
	var updates []RefUpdate
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 3 {
			return nil, fmt.Errorf("unexpected pre-receive line %q", line)
		}
		updates = append(updates, RefUpdate{OldRev: fields[0], NewRev: fields[1], Ref: fields[2]})
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read pre-receive input: %w", err)
	}
	return updates, nil
}

// Ask sends the ref updates to the gateway and returns its verdict.
func Ask(socket string, req Request) (Response, error) {
	conn, err := net.DialTimeout("unix", socket, DialTimeout)
	if err != nil {
		return Response{}, fmt.Errorf("reach gateway at %s: %w", socket, err)
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(ScanTimeout)); err != nil {
		return Response{}, fmt.Errorf("set deadline: %w", err)
	}
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return Response{}, fmt.Errorf("send hook request: %w", err)
	}
	// Signal end of request so the gateway can start reading.
	if uc, ok := conn.(*net.UnixConn); ok {
		_ = uc.CloseWrite()
	}

	var resp Response
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return Response{}, fmt.Errorf("read verdict: %w", err)
	}
	return resp, nil
}

// RunPreReceive is the whole hook-mode entry point. It returns the process
// exit code: 0 releases the push, 1 rejects it.
//
// Every failure path rejects. A gateway that cannot be reached, or that
// cannot decide, must not let a push through.
func RunPreReceive(stdin io.Reader, stderr io.Writer) int {
	socket := os.Getenv(EnvSocket)
	pushID := os.Getenv(EnvPushID)
	if socket == "" || pushID == "" {
		fmt.Fprintf(stderr, "quarantine gateway: hook invoked without %s/%s\n", EnvSocket, EnvPushID)
		return 1
	}

	updates, err := ParseStdin(stdin)
	if err != nil {
		fmt.Fprintf(stderr, "quarantine gateway: %v\n", err)
		return 1
	}
	if len(updates) == 0 {
		return 0
	}

	resp, err := Ask(socket, Request{PushID: pushID, Updates: updates})
	if err != nil {
		fmt.Fprintf(stderr, "quarantine gateway: %v\n", err)
		fmt.Fprintln(stderr, "quarantine gateway: push rejected because no verdict could be reached")
		return 1
	}

	if resp.Message != "" {
		fmt.Fprintln(stderr, resp.Message)
	}
	if resp.Err != "" {
		fmt.Fprintf(stderr, "quarantine gateway: %s\n", resp.Err)
		return 1
	}
	if !resp.Accept() {
		return 1
	}
	return 0
}
