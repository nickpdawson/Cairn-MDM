package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestGrantConsoleCreateShowsLinkAndQR(t *testing.T) {
	app, sessions, _ := testApp(t)
	m := mux(app)
	cookie, csrf := adminSession(t, sessions)

	// Create a grant.
	form := "csrf=" + csrf + "&label=Test+Mac&owner=nick%40dzsec.net&platform=macos&max_uses=1&expires_hours=24"
	req := httptest.NewRequest(http.MethodPost, "/admin/enrollment", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	m.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("create grant = %d, want 200 (inline link page)", rr.Code)
	}
	body := rr.Body.String()
	// The one-time link is shown, contains /e/<token>, and a QR data URI.
	if !strings.Contains(body, "/e/") || !strings.Contains(body, "Enrollment link created") {
		t.Error("created link not shown on the page")
	}
	if !strings.Contains(body, "data:image/png;base64,") {
		t.Error("QR code not rendered")
	}
	// The grant now appears in the list.
	req = httptest.NewRequest(http.MethodGet, "/admin/enrollment", nil)
	req.AddCookie(cookie)
	rr = httptest.NewRecorder()
	m.ServeHTTP(rr, req)
	if !strings.Contains(rr.Body.String(), "nick@dzsec.net") {
		t.Error("grant missing from list")
	}
}

func TestGrantCreateRequiresCSRF(t *testing.T) {
	app, sessions, _ := testApp(t)
	m := mux(app)
	cookie, _ := adminSession(t, sessions)
	req := httptest.NewRequest(http.MethodPost, "/admin/enrollment", strings.NewReader("label=x"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	m.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("no-CSRF create = %d, want 403", rr.Code)
	}
}
