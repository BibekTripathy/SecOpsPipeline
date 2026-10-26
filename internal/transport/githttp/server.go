// Package githttp serves git's smart-HTTP protocol in front of a quarantine
// repository.
//
// The handler does not interpret the protocol itself. It authenticates the
// caller, prepares a quarantine repo and then hands the request body to
// git-receive-pack, which runs the pre-receive hook that asks the gateway
// for a verdict. Git therefore remains the thing that accepts or rejects the
// push, and the developer gets a native git error with our findings in it.
package githttp

import (
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os/exec"
	"regexp"
	"strings"

	"github.com/BibekTripathy/SecOpsPipeline/internal/auth"
)

// endpointRe splits a request path into a repository name and one of the
// three smart-HTTP endpoints. The repo name is validated separately by
// parseRepo rather than by this pattern, so the rules that keep traversal
// out of a repo name are stated once, in readable Go.
var endpointRe = regexp.MustCompile(`^/(.+)/(info/refs|git-receive-pack|git-upload-pack)$`)

// segmentRe is one legal path segment of a repository name.
var segmentRe = regexp.MustCompile(`^[A-Za-z0-9_-][A-Za-z0-9._-]*$`)

// parseRepo validates and normalises the repository part of a request path.
//
// A name is at most two segments ("owner/name" or "name"), each of which
// must look like an identifier. That rules out "..", absolute paths and
// anything else that could walk out of the quarantine root, and the optional
// .git suffix is stripped so "acme/api" and "acme/api.git" are one repo.
func parseRepo(raw string) (string, bool) {
	raw = strings.TrimSuffix(raw, ".git")
	if raw == "" {
		return "", false
	}
	segments := strings.Split(raw, "/")
	if len(segments) > 2 {
		return "", false
	}
	for _, seg := range segments {
		if !segmentRe.MatchString(seg) {
			return "", false
		}
	}
	return raw, true
}

// Authenticator resolves a presented token to an identity.
type Authenticator interface {
	Authenticate(ctx context.Context, secret string) (auth.Identity, error)
}

// PushHandler runs a single receive-pack push through quarantine. The
// transport owns HTTP; everything about quarantine, scanning and forwarding
// lives behind this interface.
type PushHandler interface {
	// Advertise writes the ref advertisement for repo, as
	// git-receive-pack --advertise-refs would.
	Advertise(ctx context.Context, repo string, w io.Writer) error

	// Receive consumes a receive-pack request body and writes the
	// receive-pack response. It is responsible for quarantining, scanning,
	// reaching a verdict and forwarding a released push upstream.
	Receive(ctx context.Context, id auth.Identity, repo string, body io.Reader, w io.Writer) error
}

// Server is the HTTP front end.
type Server struct {
	Auth   Authenticator
	Pushes PushHandler
	Log    *slog.Logger
	// MaxBodyBytes caps a single push. Zero means unlimited.
	MaxBodyBytes int64
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	m := endpointRe.FindStringSubmatch(r.URL.Path)
	if m == nil {
		http.NotFound(w, r)
		return
	}
	repo, ok := parseRepo(m[1])
	if !ok {
		http.NotFound(w, r)
		return
	}
	endpoint := m[2]

	// Fetching is not the gateway's job: developers clone from the real
	// remote. Serving uploads here would only create a second, unscanned
	// path to the same objects.
	if endpoint == "git-upload-pack" || r.URL.Query().Get("service") == "git-upload-pack" {
		httpError(w, http.StatusForbidden, "this gateway only accepts pushes; clone from the upstream remote")
		return
	}

	id, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	if !id.HasScope(auth.ScopePush) {
		httpError(w, http.StatusForbidden, "token lacks the push scope")
		return
	}

	switch {
	case endpoint == "info/refs" && r.Method == http.MethodGet:
		s.handleAdvertise(w, r, repo)
	case endpoint == "git-receive-pack" && r.Method == http.MethodPost:
		s.handleReceive(w, r, id, repo)
	default:
		httpError(w, http.StatusMethodNotAllowed, "unsupported method for this endpoint")
	}
}

// authenticate reads the PAT from Basic auth. Git sends the password field;
// the username is ignored, matching how GitHub treats token auth.
func (s *Server) authenticate(w http.ResponseWriter, r *http.Request) (auth.Identity, bool) {
	_, token, ok := r.BasicAuth()
	if !ok || token == "" {
		// The WWW-Authenticate header is what makes git prompt for
		// credentials rather than fail outright.
		w.Header().Set("WWW-Authenticate", `Basic realm="commit quarantine gateway"`)
		httpError(w, http.StatusUnauthorized, "authentication required")
		return auth.Identity{}, false
	}

	id, err := s.Auth.Authenticate(r.Context(), token)
	if err != nil {
		s.Log.Warn("rejected push credential", "remote", r.RemoteAddr, "error", err)
		w.Header().Set("WWW-Authenticate", `Basic realm="commit quarantine gateway"`)
		// The reason is deliberately vague to the caller; the detail is in
		// the gateway log.
		httpError(w, http.StatusUnauthorized, "invalid credentials")
		return auth.Identity{}, false
	}
	return id, true
}

func (s *Server) handleAdvertise(w http.ResponseWriter, r *http.Request, repo string) {
	if r.URL.Query().Get("service") != "git-receive-pack" {
		httpError(w, http.StatusForbidden, "dumb http protocol is not supported")
		return
	}

	setGitHeaders(w, "application/x-git-receive-pack-advertisement")

	if err := writePktLine(w, "# service=git-receive-pack\n"); err != nil {
		s.Log.Error("write advertisement header", "error", err)
		return
	}
	if err := writeFlush(w); err != nil {
		s.Log.Error("write advertisement flush", "error", err)
		return
	}
	if err := s.Pushes.Advertise(r.Context(), repo, w); err != nil {
		// Headers are already sent, so the only honest signal left is to
		// stop writing and log. Git reports a truncated response.
		s.Log.Error("advertise refs", "repo", repo, "error", err)
	}
}

func (s *Server) handleReceive(w http.ResponseWriter, r *http.Request, id auth.Identity, repo string) {
	body, err := requestBody(r, s.MaxBodyBytes)
	if err != nil {
		httpError(w, http.StatusBadRequest, err.Error())
		return
	}
	defer body.Close()

	setGitHeaders(w, "application/x-git-receive-pack-result")

	if err := s.Pushes.Receive(r.Context(), id, repo, body, w); err != nil {
		s.Log.Error("receive push", "repo", repo, "actor", id.User.Username, "error", err)
	}
}

// requestBody unwraps gzip, which git uses when the client sets
// Content-Encoding, and applies the body size cap.
func requestBody(r *http.Request, max int64) (io.ReadCloser, error) {
	var body io.ReadCloser = r.Body
	if max > 0 {
		body = struct {
			io.Reader
			io.Closer
		}{io.LimitReader(r.Body, max), r.Body}
	}
	if strings.EqualFold(r.Header.Get("Content-Encoding"), "gzip") {
		gz, err := gzip.NewReader(body)
		if err != nil {
			return nil, fmt.Errorf("decompress request body: %w", err)
		}
		return gz, nil
	}
	return body, nil
}

// setGitHeaders sends the no-cache headers git's smart HTTP protocol
// requires; a cached advertisement would make a client push against a stale
// ref.
func setGitHeaders(w http.ResponseWriter, contentType string) {
	h := w.Header()
	h.Set("Content-Type", contentType)
	h.Set("Cache-Control", "no-cache, max-age=0, must-revalidate")
	h.Set("Pragma", "no-cache")
	h.Set("Expires", "Fri, 01 Jan 1980 00:00:00 GMT")
	w.WriteHeader(http.StatusOK)
}

func httpError(w http.ResponseWriter, code int, msg string) {
	http.Error(w, msg, code)
}

// ExitCode extracts a child process exit code, or -1.
func ExitCode(err error) int {
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode()
	}
	return -1
}
