// Package server assembles Cairn's single HTTP listener.
//
// Phase 0 wires liveness/readiness and a version endpoint. MDM, SCEP,
// enrollment, API, and the admin UI mount onto this same mux in later phases.
package server

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/dzsec/cairn/internal/config"
	"github.com/dzsec/cairn/internal/version"
)

// Readiness reports whether backing dependencies are healthy. The storage layer
// satisfies this.
type Readiness interface {
	Ping(ctx context.Context) error
}

// Deps are the optional subsystem handlers the server mounts. A nil handler is
// simply not mounted.
type Deps struct {
	MDM    http.Handler // NanoMDM check-in/command handler (mounted at mdm_path)
	SCEP   http.Handler // embedded-CA SCEP handler (mounted at /scep)
	Enroll http.Handler // enrollment profile handler (mounted at /enroll)
}

// Server holds the mux and its dependencies.
type Server struct {
	cfg   config.Config
	log   *slog.Logger
	ready Readiness
	deps  Deps
	mux   *http.ServeMux
}

// New builds a Server and registers routes.
func New(cfg config.Config, log *slog.Logger, ready Readiness, deps Deps) *Server {
	s := &Server{cfg: cfg, log: log, ready: ready, deps: deps, mux: http.NewServeMux()}
	s.routes()
	return s
}

// Handler returns the root handler wrapped in the base middleware chain.
func (s *Server) Handler() http.Handler {
	return s.recoverer(s.accessLog(s.mux))
}

func (s *Server) routes() {
	s.mux.HandleFunc("GET /healthz", s.handleHealthz)
	s.mux.HandleFunc("GET /readyz", s.handleReadyz)
	s.mux.HandleFunc("GET /version", s.handleVersion)

	if s.deps.MDM != nil {
		// Apple devices PUT check-in and command results to this single path.
		// Mount without a method restriction and let NanoMDM's handler decide;
		// the pattern has no method token so all methods match.
		s.mux.Handle(s.cfg.Server.MDMPath, s.deps.MDM)
	}

	if s.deps.SCEP != nil {
		// The SCEP handler's internal router matches exactly "/scep", so the
		// request path must reach it unchanged. Mount the subtree at "/scep/"
		// as well so a trailing slash still routes.
		s.mux.Handle("/scep", s.deps.SCEP)
		s.mux.Handle("/scep/", s.deps.SCEP)
	}

	if s.deps.Enroll != nil {
		s.mux.Handle("GET /enroll", s.deps.Enroll)
	}
}

// handleHealthz reports process liveness — it never touches dependencies.
func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// handleReadyz reports readiness to serve — it pings storage.
func (s *Server) handleReadyz(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	if s.ready != nil {
		if err := s.ready.Ping(ctx); err != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{
				"status": "unavailable",
				"error":  err.Error(),
			})
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}

func (s *Server) handleVersion(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"version": version.Version,
		"commit":  version.Commit,
		"date":    version.Date,
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
