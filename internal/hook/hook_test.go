package hook

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"

	"github.com/BibekTripathy/SecOpsPipeline/internal/policy"
)

func TestParseStdin(t *testing.T) {
	in := "aaa bbb refs/heads/main\nccc ddd refs/heads/dev\n"
	got, err := ParseStdin(strings.NewReader(in))
	if err != nil {
		t.Fatalf("ParseStdin: %v", err)
	}
	if len(got) != 2 || got[0].Ref != "refs/heads/main" || got[1].NewRev != "ddd" {
		t.Errorf("ParseStdin = %+v", got)
	}
}

func TestParseStdinRejectsMalformed(t *testing.T) {
	if _, err := ParseStdin(strings.NewReader("only-two fields\n")); err == nil {
		t.Error("ParseStdin returned nil for a malformed line, want error")
	}
}

func TestAcceptOnlyOnRelease(t *testing.T) {
	cases := map[policy.Verdict]bool{policy.Release: true, policy.Block: false, policy.Hold: false}
	for v, want := range cases {
		if got := (Response{Verdict: v}).Accept(); got != want {
			t.Errorf("Accept(%q) = %v, want %v", v, got, want)
		}
	}
	if (Response{Verdict: policy.Release, Err: "boom"}).Accept() {
		t.Error("a response carrying an error must not be accepted")
	}
}

func TestServerRoundTrip(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "hook.sock")
	srv := NewServer(socket, func(ctx context.Context, req Request) Response {
		if len(req.Updates) != 1 || req.PushID != "p1" {
			return Response{Err: "unexpected request"}
		}
		return Response{Verdict: policy.Block, Message: "secret found"}
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))

	if err := srv.Listen(); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	go srv.Serve(context.Background())
	defer srv.Close()

	resp, err := Ask(socket, Request{PushID: "p1", Updates: []RefUpdate{{OldRev: "a", NewRev: "b", Ref: "refs/heads/main"}}})
	if err != nil {
		t.Fatalf("Ask: %v", err)
	}
	if resp.Verdict != policy.Block || resp.Message != "secret found" {
		t.Errorf("resp = %+v", resp)
	}
	if resp.Accept() {
		t.Error("a block verdict must not be accepted")
	}
}

func TestRunPreReceiveRejectsWhenGatewayUnreachable(t *testing.T) {
	t.Setenv(EnvSocket, filepath.Join(t.TempDir(), "absent.sock"))
	t.Setenv(EnvPushID, "p1")

	var stderr bytes.Buffer
	code := RunPreReceive(strings.NewReader("a b refs/heads/main\n"), &stderr)
	if code != 1 {
		t.Errorf("exit code = %d, want 1 when the gateway is unreachable", code)
	}
	if !strings.Contains(stderr.String(), "rejected") {
		t.Errorf("stderr = %q, want it to explain the rejection", stderr.String())
	}
}

func TestRunPreReceiveRejectsWithoutEnv(t *testing.T) {
	t.Setenv(EnvSocket, "")
	t.Setenv(EnvPushID, "")
	if code := RunPreReceive(strings.NewReader(""), io.Discard); code != 1 {
		t.Errorf("exit code = %d, want 1", code)
	}
}
