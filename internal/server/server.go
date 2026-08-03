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
	"strings"
	"time"

	"github.com/nickpdawson/cairn-mdm/internal/config"
	"github.com/nickpdawson/cairn-mdm/internal/version"
)

// Readiness reports whether backing dependencies are healthy. The storage layer
// satisfies this.
type Readiness interface {
	Ping(ctx context.Context) error
}

// Deps are the optional subsystem handlers the server mounts. A nil handler is
// simply not mounted.
type Deps struct {
	MDM         http.Handler // NanoMDM check-in/command handler (mounted at mdm_path)
	SCEP        http.Handler // embedded-CA SCEP handler (mounted at /scep)
	Enroll      http.Handler // bare enrollment handler (mounted at GET /enroll; default-denied)
	EnrollGrant http.Handler // grant-based enrollment (mounted at GET /e/{token})
	CA          http.Handler // CA trust-anchor download (mounted at GET /ca)
	UI          UIRegistrar  // admin console; registers its own routes
}

// UIRegistrar registers admin-console routes on the server mux. Implementing
// this interface keeps the server package from importing the web package.
type UIRegistrar interface {
	Register(mux *http.ServeMux)
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
	return s.recoverer(s.secureHeaders(s.accessLog(s.mux)))
}

// secureHeaders sets baseline security headers on every response and marks
// sensitive paths uncacheable.
//
// The CSP keeps 'unsafe-inline' for styles and scripts on purpose: the admin
// templates use inline styles and inline onsubmit/onclick handlers. HSTS is only
// emitted when the request arrived over TLS — either directly (r.TLS != nil) or
// via a reverse proxy that set X-Forwarded-Proto=https — so plaintext/proxy
// deployments that terminate TLS elsewhere don't pin an origin the browser can't
// reach. This assumes the fronting proxy strips a client-supplied
// X-Forwarded-Proto, which is standard reverse-proxy practice.
func (s *Server) secureHeaders(next http.Handler) http.Handler {
	const csp = "default-src 'self'; style-src 'self' 'unsafe-inline'; " +
		"script-src 'self' 'unsafe-inline'; img-src 'self' data:; " +
		"object-src 'none'; base-uri 'self'; frame-ancestors 'none'"
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
		h.Set("Content-Security-Policy", csp)
		if r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") {
			h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		if sensitivePath(r.URL.Path) {
			h.Set("Cache-Control", "no-store")
		}
		next.ServeHTTP(w, r)
	})
}

// sensitivePath reports whether a path serves authenticated or credential-bearing
// content that must never be cached (admin console, login/logout, enrollment).
func sensitivePath(p string) bool {
	switch {
	case p == "/admin" || strings.HasPrefix(p, "/admin/"):
		return true
	case p == "/login" || p == "/logout":
		return true
	case p == "/enroll" || strings.HasPrefix(p, "/enroll/"):
		return true
	case strings.HasPrefix(p, "/e/"):
		return true
	default:
		return false
	}
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

	if s.deps.EnrollGrant != nil {
		s.mux.Handle("GET /e/{token}", s.deps.EnrollGrant)
	}

	if s.deps.CA != nil {
		s.mux.Handle("GET /ca", s.deps.CA)
	}

	if s.deps.UI != nil {
		s.deps.UI.Register(s.mux)
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
			// Log the dependency detail server-side; return a generic body so we
			// don't leak backend errors (DSNs, driver messages) to clients.
			s.log.Warn("readiness check failed", "err", err)
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{
				"status": "unavailable",
				"error":  "not ready",
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
