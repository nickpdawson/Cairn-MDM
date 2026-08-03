package server

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nickpdawson/cairn-mdm/internal/config"
)

func testServer(t *testing.T, ready Readiness) *Server {
	t.Helper()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	return New(config.Config{}, log, ready, Deps{})
}

func TestSecureHeadersPresent(t *testing.T) {
	s := testServer(t, nil)
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/healthz", nil))

	if rr.Code != http.StatusOK {
		t.Fatalf("healthz = %d, want 200", rr.Code)
	}
	want := map[string]string{
		"X-Content-Type-Options":  "nosniff",
		"Referrer-Policy":         "no-referrer",
		"Permissions-Policy":      "geolocation=(), microphone=(), camera=()",
		"Content-Security-Policy": "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; img-src 'self' data:; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
	}
	for k, v := range want {
		if got := rr.Header().Get(k); got != v {
			t.Errorf("header %s = %q, want %q", k, got, v)
		}
	}
	// CSP must retain 'unsafe-inline' for the app's inline styles/handlers.
	if !strings.Contains(rr.Header().Get("Content-Security-Policy"), "'unsafe-inline'") {
		t.Error("CSP dropped 'unsafe-inline'; inline styles/handlers would break")
	}
}

func TestHSTSOnlyOverTLS(t *testing.T) {
	s := testServer(t, nil)

	// Plaintext request: no HSTS.
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if got := rr.Header().Get("Strict-Transport-Security"); got != "" {
		t.Errorf("HSTS on plaintext request = %q, want empty", got)
	}

	// TLS request (httptest sets req.TLS for an https target): HSTS present.
	rr = httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "https://cairn.example.org/healthz", nil))
	if got := rr.Header().Get("Strict-Transport-Security"); got != "max-age=31536000; includeSubDomains" {
		t.Errorf("HSTS over TLS = %q, want max-age=31536000; includeSubDomains", got)
	}

	// Proxy-terminated TLS advertised via X-Forwarded-Proto.
	rr = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	s.Handler().ServeHTTP(rr, req)
	if got := rr.Header().Get("Strict-Transport-Security"); got == "" {
		t.Error("HSTS missing when X-Forwarded-Proto=https")
	}
}

func TestCacheControlOnSensitivePaths(t *testing.T) {
	s := testServer(t, nil)
	// Sensitive paths get no-store even when unrouted (middleware runs first).
	for _, p := range []string{"/login", "/admin", "/admin/devices", "/enroll"} {
		rr := httptest.NewRecorder()
		s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, p, nil))
		if got := rr.Header().Get("Cache-Control"); got != "no-store" {
			t.Errorf("Cache-Control on %s = %q, want no-store", p, got)
		}
	}
	// Non-sensitive path is not force-marked no-store.
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if got := rr.Header().Get("Cache-Control"); got == "no-store" {
		t.Error("healthz should not be marked no-store")
	}
}

type failReady struct{}

func (failReady) Ping(context.Context) error {
	return errors.New("dsn=secret host=internal.db driver blew up")
}

func TestReadyzHidesDependencyError(t *testing.T) {
	s := testServer(t, failReady{})
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("readyz = %d, want 503", rr.Code)
	}
	if strings.Contains(rr.Body.String(), "secret") || strings.Contains(rr.Body.String(), "driver blew up") {
		t.Errorf("readyz leaked dependency detail: %s", rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "not ready") {
		t.Errorf("readyz body = %s, want generic \"not ready\"", rr.Body.String())
	}
}
