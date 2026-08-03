package web

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func newAppWithTrusted(t *testing.T, cidrs ...string) *App {
	t.Helper()
	nets, err := parseTrustedProxies(cidrs)
	if err != nil {
		t.Fatalf("parseTrustedProxies: %v", err)
	}
	return &App{trusted: nets}
}

func reqWith(remote, xff string) *http.Request {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = remote
	if xff != "" {
		r.Header.Set("X-Forwarded-For", xff)
	}
	return r
}

func TestClientIP(t *testing.T) {
	cases := []struct {
		name    string
		trusted []string
		remote  string
		xff     string
		want    string
	}{
		{"no trusted config uses peer", nil, "10.25.1.182:5000", "1.2.3.4", "10.25.1.182"},
		{"untrusted peer ignores xff", []string{"10.25.1.182"}, "9.9.9.9:5000", "1.2.3.4", "9.9.9.9"},
		{"trusted proxy takes real client", []string{"10.25.1.182"}, "10.25.1.182:5000", "1.2.3.4", "1.2.3.4"},
		{"trusted CIDR", []string{"10.25.1.0/24"}, "10.25.1.182:5000", "203.0.113.7", "203.0.113.7"},
		{"chained proxies skip trusted hops", []string{"10.25.1.0/24"}, "10.25.1.182:5000", "203.0.113.7, 10.25.1.5", "203.0.113.7"},
		{"trusted peer but empty xff falls back to peer", []string{"10.25.1.182"}, "10.25.1.182:5000", "", "10.25.1.182"},
		{"all-trusted xff falls back to peer", []string{"10.25.1.0/24"}, "10.25.1.182:5000", "10.25.1.5", "10.25.1.182"},
		{"no host:port", nil, "10.25.1.182", "", "10.25.1.182"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a := newAppWithTrusted(t, c.trusted...)
			if got := a.clientIP(reqWith(c.remote, c.xff)); got != c.want {
				t.Errorf("clientIP = %q, want %q", got, c.want)
			}
		})
	}
}

func TestParseTrustedProxiesRejectsGarbage(t *testing.T) {
	if _, err := parseTrustedProxies([]string{"not-an-ip"}); err == nil {
		t.Fatal("expected error for invalid entry")
	}
	if _, err := parseTrustedProxies([]string{"  ", ""}); err != nil {
		t.Fatalf("blank entries should be skipped, got %v", err)
	}
}
