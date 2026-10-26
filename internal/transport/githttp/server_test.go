package githttp

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/BibekTripathy/SecOpsPipeline/internal/auth"
	"github.com/BibekTripathy/SecOpsPipeline/internal/store"
)

type fakeAuth struct {
	token string
	id    auth.Identity
}

func (f fakeAuth) Authenticate(_ context.Context, secret string) (auth.Identity, error) {
	if secret != f.token {
		return auth.Identity{}, store.ErrNotFound
	}
	return f.id, nil
}

type fakePushes struct {
	advertised string
	received   string
}

func (f *fakePushes) Advertise(_ context.Context, repo string, w io.Writer) error {
	f.advertised = repo
	_, err := io.WriteString(w, "advertisement")
	return err
}

func (f *fakePushes) Receive(_ context.Context, _ auth.Identity, repo string, body io.Reader, w io.Writer) error {
	f.received = repo
	io.Copy(io.Discard, body)
	_, err := io.WriteString(w, "result")
	return err
}

func testServer(t *testing.T) (*Server, *fakePushes) {
	t.Helper()
	pushes := &fakePushes{}
	return &Server{
		Auth: fakeAuth{token: "sqg_good", id: auth.Identity{
			User:   auth.User{Username: "dev"},
			Scopes: []auth.Scope{auth.ScopePush},
		}},
		Pushes: pushes,
		Log:    slog.New(slog.NewTextHandler(io.Discard, nil)),
	}, pushes
}

func TestAdvertiseRequiresAuth(t *testing.T) {
	s, _ := testServer(t)
	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/acme/api.git/info/refs?service=git-receive-pack", nil))

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("code = %d, want 401", rr.Code)
	}
	if rr.Header().Get("WWW-Authenticate") == "" {
		t.Error("missing WWW-Authenticate header; git will not prompt for credentials")
	}
}

func TestAdvertiseWithValidToken(t *testing.T) {
	s, pushes := testServer(t)
	req := httptest.NewRequest(http.MethodGet, "/acme/api.git/info/refs?service=git-receive-pack", nil)
	req.SetBasicAuth("token", "sqg_good")
	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("code = %d, want 200", rr.Code)
	}
	if got := rr.Header().Get("Content-Type"); got != "application/x-git-receive-pack-advertisement" {
		t.Errorf("content type = %q", got)
	}
	// The service header must be pkt-line framed and followed by a flush.
	if want := "001f# service=git-receive-pack\n0000advertisement"; rr.Body.String() != want {
		t.Errorf("body = %q, want %q", rr.Body.String(), want)
	}
	if pushes.advertised != "acme/api" {
		t.Errorf("repo = %q, want acme/api", pushes.advertised)
	}
}

func TestReceivePack(t *testing.T) {
	s, pushes := testServer(t)
	req := httptest.NewRequest(http.MethodPost, "/acme/api.git/git-receive-pack", bytes.NewBufferString("packdata"))
	req.SetBasicAuth("token", "sqg_good")
	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK || rr.Body.String() != "result" {
		t.Errorf("code = %d body = %q", rr.Code, rr.Body.String())
	}
	if pushes.received != "acme/api" {
		t.Errorf("repo = %q, want acme/api", pushes.received)
	}
}

func TestRejectsBadToken(t *testing.T) {
	s, _ := testServer(t)
	req := httptest.NewRequest(http.MethodPost, "/acme/api.git/git-receive-pack", nil)
	req.SetBasicAuth("token", "sqg_wrong")
	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("code = %d, want 401", rr.Code)
	}
}

func TestRejectsTokenWithoutPushScope(t *testing.T) {
	s, _ := testServer(t)
	s.Auth = fakeAuth{token: "sqg_good", id: auth.Identity{
		User:   auth.User{Username: "reviewer"},
		Scopes: []auth.Scope{auth.ScopeApprove},
	}}
	req := httptest.NewRequest(http.MethodPost, "/acme/api.git/git-receive-pack", nil)
	req.SetBasicAuth("token", "sqg_good")
	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("code = %d, want 403", rr.Code)
	}
}

func TestRejectsUploadPack(t *testing.T) {
	s, _ := testServer(t)
	req := httptest.NewRequest(http.MethodGet, "/acme/api.git/info/refs?service=git-upload-pack", nil)
	req.SetBasicAuth("token", "sqg_good")
	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("code = %d, want 403; the gateway must not serve an unscanned fetch path", rr.Code)
	}
}

func TestRejectsPathTraversal(t *testing.T) {
	s, _ := testServer(t)
	for _, path := range []string{
		"/../../etc/passwd/git-receive-pack",
		"/a/b/c/git-receive-pack",
		"/acme/api.git/hooks/pre-receive",
	} {
		req := httptest.NewRequest(http.MethodPost, path, nil)
		req.SetBasicAuth("token", "sqg_good")
		rr := httptest.NewRecorder()
		s.ServeHTTP(rr, req)
		if rr.Code != http.StatusNotFound {
			t.Errorf("%s: code = %d, want 404", path, rr.Code)
		}
	}
}
