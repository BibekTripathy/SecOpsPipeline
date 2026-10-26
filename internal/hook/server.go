package hook

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
)

// Decider reaches a verdict for one push. The gateway supplies this.
type Decider func(ctx context.Context, req Request) Response

// Server listens on a unix socket for hook callbacks.
type Server struct {
	socket  string
	decide  Decider
	log     *slog.Logger
	ln      net.Listener
	wg      sync.WaitGroup
	closing chan struct{}
}

// NewServer prepares a hook server. The socket is created with 0600 so only
// the user running the gateway -- which is also the user git-receive-pack
// runs as -- can ask for a verdict.
func NewServer(socket string, decide Decider, log *slog.Logger) *Server {
	return &Server{socket: socket, decide: decide, log: log, closing: make(chan struct{})}
}

// Listen binds the socket, removing a stale one left by an unclean shutdown.
func (s *Server) Listen() error {
	if err := os.MkdirAll(filepath.Dir(s.socket), 0o700); err != nil {
		return fmt.Errorf("prepare socket directory: %w", err)
	}
	if err := os.Remove(s.socket); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove stale socket: %w", err)
	}
	ln, err := net.Listen("unix", s.socket)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", s.socket, err)
	}
	if err := os.Chmod(s.socket, 0o600); err != nil {
		ln.Close()
		return fmt.Errorf("restrict socket permissions: %w", err)
	}
	s.ln = ln
	return nil
}

// Serve accepts hook connections until Close is called.
func (s *Server) Serve(ctx context.Context) error {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			select {
			case <-s.closing:
				s.wg.Wait()
				return nil
			default:
				return fmt.Errorf("accept hook connection: %w", err)
			}
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer conn.Close()
			s.handle(ctx, conn)
		}()
	}
}

func (s *Server) handle(ctx context.Context, conn net.Conn) {
	var req Request
	if err := json.NewDecoder(conn).Decode(&req); err != nil {
		s.log.Error("decode hook request", "error", err)
		writeResponse(conn, Response{Err: "malformed hook request"}, s.log)
		return
	}

	resp := s.decide(ctx, req)
	writeResponse(conn, resp, s.log)
}

func writeResponse(conn net.Conn, resp Response, log *slog.Logger) {
	if err := json.NewEncoder(conn).Encode(resp); err != nil {
		log.Error("write hook response", "error", err)
	}
}

// Close stops accepting and waits for in-flight verdicts to finish.
func (s *Server) Close() error {
	close(s.closing)
	if s.ln == nil {
		return nil
	}
	err := s.ln.Close()
	s.wg.Wait()
	os.Remove(s.socket)
	return err
}

// Install writes the pre-receive hook into a quarantine repo. The hook is a
// two-line shell script that execs the gateway binary in hook mode, so the
// detection logic lives in Go and the script never needs to change.
func Install(repoPath, gatewayBin, socket, pushID string) error {
	hooks := filepath.Join(repoPath, "hooks")
	if err := os.MkdirAll(hooks, 0o700); err != nil {
		return fmt.Errorf("create hooks dir: %w", err)
	}
	script := fmt.Sprintf(`#!/bin/sh
# Installed by the Commit Quarantine Gateway. Do not edit.
%s=%q %s=%q exec %q hook pre-receive
`, EnvSocket, socket, EnvPushID, pushID, gatewayBin)

	path := filepath.Join(hooks, "pre-receive")
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		return fmt.Errorf("install pre-receive hook: %w", err)
	}
	return nil
}
