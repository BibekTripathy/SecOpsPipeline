package e2e

import (
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// requireGit skips the suite where git is unavailable rather than failing;
// these tests are meaningless without the real binary.
func requireGit(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH")
	}
}

// run executes a command and fails the test on error.
func run(t *testing.T, dir string, name string, args ...string) string {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, out)
	}
	return string(out)
}

// freeAddr reserves a loopback port and releases it, so the gateway can
// bind it without the tests colliding when run in parallel.
func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

// waitReachable blocks until the gateway accepts connections.
func waitReachable(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			conn.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("gateway at %s never became reachable", addr)
}

var (
	buildPath string
	buildErr  error
)

// TestMain compiles the gateway once for the whole suite.
//
// The binary must outlive any single test, because git execs it as the
// pre-receive hook: building into a t.TempDir() would delete it as soon as
// the first test finished. The real binary is used rather than a test
// double precisely because the hook exec is the path under test.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "sqg-e2e-bin")
	if err != nil {
		fmt.Fprintf(os.Stderr, "create build dir: %v\n", err)
		os.Exit(1)
	}
	defer os.RemoveAll(dir)

	buildPath = filepath.Join(dir, "gateway")
	cmd := exec.Command("go", "build", "-o", buildPath,
		"github.com/BibekTripathy/SecOpsPipeline/cmd/gateway")
	if b, err := cmd.CombinedOutput(); err != nil {
		buildErr = fmt.Errorf("build gateway: %w\n%s", err, b)
	}

	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

func buildGatewayBinary(t *testing.T) string {
	t.Helper()
	if buildErr != nil {
		t.Fatal(buildErr)
	}
	return buildPath
}

func testLogger(t *testing.T) *slog.Logger {
	t.Helper()
	if testing.Verbose() {
		return slog.New(slog.NewTextHandler(testWriter{t}, &slog.HandlerOptions{Level: slog.LevelDebug}))
	}
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

type testWriter struct{ t *testing.T }

func (w testWriter) Write(p []byte) (int, error) {
	w.t.Logf("%s", strings.TrimRight(string(p), "\n"))
	return len(p), nil
}

// findReports lists the SARIF reports the gateway wrote.
func findReports(t *testing.T, dir string) []string {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(dir, "*.sarif.json"))
	if err != nil {
		t.Fatalf("glob reports: %v", err)
	}
	return matches
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}
