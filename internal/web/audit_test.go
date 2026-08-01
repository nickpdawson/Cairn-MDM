package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// login signs in the seeded admin and returns the session cookies.
func login(t *testing.T, m *http.ServeMux) []*http.Cookie {
	t.Helper()
	form := strings.NewReader("username=nick&password=hunter2hunter2")
	req := httptest.NewRequest(http.MethodPost, "/login", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = "203.0.113.7:9999"
	rr := httptest.NewRecorder()
	m.ServeHTTP(rr, req)
	cookies := rr.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("login did not set a session cookie")
	}
	return cookies
}

// TestLoginIsAudited checks that the middleware records the login POST with the
// submitted username, the method as the action, the path (no query) as the
// target, the status, and the client IP.
func TestLoginIsAudited(t *testing.T) {
	app, _, db := testApp(t)
	m := mux(app)
	login(t, m)

	rows, err := db.ListAudit(context.Background(), 200)
	if err != nil {
		t.Fatalf("ListAudit: %v", err)
	}
	if len(rows) == 0 {
		t.Fatal("login was not audited")
	}
	e := rows[0]
	if e.Action != "POST" {
		t.Errorf("action = %q, want POST", e.Action)
	}
	if e.Target != "/login" {
		t.Errorf("target = %q, want /login", e.Target)
	}
	if e.Username != "nick" {
		t.Errorf("username = %q, want nick (submitted username)", e.Username)
	}
	if e.Result != "302" {
		t.Errorf("result = %q, want 302", e.Result)
	}
	if e.Remote != "203.0.113.7" {
		t.Errorf("remote = %q, want 203.0.113.7 (host of RemoteAddr)", e.Remote)
	}
}

// TestMutatingRouteIsAudited checks that a POST to an admin mutating route
// records the session user, provider, method, and path.
func TestMutatingRouteIsAudited(t *testing.T) {
	app, sessions, db := testApp(t)
	m := mux(app)
	cookies := login(t, m)

	// Fetch the CSRF token from the session backing the cookie.
	var csrf string
	for _, c := range cookies {
		if c.Name == SessionCookie {
			sess, err := sessions.Get(context.Background(), c.Value)
			if err != nil {
				t.Fatalf("load session: %v", err)
			}
			csrf = sess.CSRF
		}
	}
	if csrf == "" {
		t.Fatal("no CSRF token on session")
	}

	form := strings.NewReader("csrf=" + csrf + "&name=Field+Techs&description=")
	req := httptest.NewRequest(http.MethodPost, "/admin/groups", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://mdm.example.org")
	req.RemoteAddr = "198.51.100.4:5000"
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rr := httptest.NewRecorder()
	m.ServeHTTP(rr, req)

	rows, err := db.ListAudit(context.Background(), 200)
	if err != nil {
		t.Fatalf("ListAudit: %v", err)
	}
	found := false
	for _, e := range rows {
		if e.Target != "/admin/groups" || e.Action != "POST" {
			continue
		}
		found = true
		if e.Username != "nick" {
			t.Errorf("username = %q, want nick", e.Username)
		}
		if e.Provider != "local" {
			t.Errorf("provider = %q, want local", e.Provider)
		}
		if e.Remote != "198.51.100.4" {
			t.Errorf("remote = %q, want 198.51.100.4", e.Remote)
		}
		break
	}
	if !found {
		t.Fatalf("POST /admin/groups was not audited; rows: %+v", rows)
	}
}

// TestActivityPageRenders checks the /admin/activity page lists audit rows.
func TestActivityPageRenders(t *testing.T) {
	app, _, _ := testApp(t)
	m := mux(app)
	cookies := login(t, m) // creates at least one audit row

	req := httptest.NewRequest(http.MethodGet, "/admin/activity", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rr := httptest.NewRecorder()
	m.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("activity page = %d, want 200", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "Activity") {
		t.Error("activity page missing heading")
	}
	if !strings.Contains(body, "/login") {
		t.Error("activity page did not list the recorded login action")
	}
}
