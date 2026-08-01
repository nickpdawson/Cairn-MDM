package web

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/dzsec/cairn/internal/auth"
	"github.com/dzsec/cairn/internal/config"
	"github.com/dzsec/cairn/internal/storage/sqlite"
)

func testApp(t *testing.T) (*App, *auth.SessionStore, *sqlite.DB) {
	t.Helper()
	db, err := sqlite.Open(context.Background(), t.TempDir()+"/web.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })

	local := auth.NewLocalStore(db.SQL())
	if err := local.CreateUser(context.Background(), "nick", "hunter2hunter2", auth.RoleAdmin, "Nick"); err != nil {
		t.Fatal(err)
	}
	sessions := auth.NewSessionStore(db.SQL(), time.Hour)
	app, err := New(sessions, local, db, stubCommander{}, nil, Config{PublicURL: "https://mdm.example.org"}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	return app, sessions, db
}

type stubCommander struct{}

func (stubCommander) SendDeviceInformation(context.Context, ...string) error      { return nil }
func (stubCommander) SendInstallProfile(context.Context, []byte, ...string) error { return nil }
func (stubCommander) SendRemoveProfile(context.Context, string, ...string) error  { return nil }

func mux(app *App) *http.ServeMux {
	m := http.NewServeMux()
	app.Register(m)
	return m
}

func TestAdminRequiresSession(t *testing.T) {
	app, _, _ := testApp(t)
	rr := httptest.NewRecorder()
	mux(app).ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/admin", nil))
	if rr.Code != http.StatusFound || rr.Header().Get("Location") != "/login" {
		t.Fatalf("unauthenticated /admin = %d -> %q, want 302 -> /login", rr.Code, rr.Header().Get("Location"))
	}
}

func TestLoginSetsSessionAndDashboardLoads(t *testing.T) {
	app, _, _ := testApp(t)
	m := mux(app)

	// Log in.
	form := strings.NewReader("username=nick&password=hunter2hunter2")
	req := httptest.NewRequest(http.MethodPost, "/login", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	m.ServeHTTP(rr, req)
	if rr.Code != http.StatusFound || rr.Header().Get("Location") != "/admin" {
		t.Fatalf("login = %d -> %q, want 302 -> /admin", rr.Code, rr.Header().Get("Location"))
	}
	cookie := rr.Result().Cookies()
	if len(cookie) == 0 {
		t.Fatal("login did not set a session cookie")
	}

	// Use the cookie to load the dashboard.
	req2 := httptest.NewRequest(http.MethodGet, "/admin", nil)
	for _, c := range cookie {
		req2.AddCookie(c)
	}
	rr2 := httptest.NewRecorder()
	m.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusOK {
		t.Fatalf("dashboard = %d, want 200", rr2.Code)
	}
	if !strings.Contains(rr2.Body.String(), "Dashboard") {
		t.Error("dashboard body missing expected content")
	}
}

func TestLoginThrottleReturns429(t *testing.T) {
	app, _, _ := testApp(t)
	app.SetLoginThrottle(auth.NewLoginThrottle(config.LoginPolicy{
		MaxAttempts: 3, WindowSeconds: 300, LockoutSeconds: 300,
	}))
	m := mux(app)

	got429 := false
	for i := 0; i < 6; i++ {
		form := strings.NewReader("username=nick&password=wrong")
		req := httptest.NewRequest(http.MethodPost, "/login", form)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.RemoteAddr = "203.0.113.9:5555"
		rr := httptest.NewRecorder()
		m.ServeHTTP(rr, req)
		if rr.Code == http.StatusTooManyRequests {
			got429 = true
			if rr.Header().Get("Retry-After") == "" {
				t.Error("429 response missing Retry-After header")
			}
			break
		}
	}
	if !got429 {
		t.Fatal("expected a 429 after repeated bad logins")
	}
}

func TestDashboardShowsPerTopicAPNs(t *testing.T) {
	app, _, db := testApp(t)
	m := mux(app)
	ctx := context.Background()

	// Two fleets: a migrated one expiring soon (the November cliff) and a test
	// topic expiring in 2027. Both must appear; the nearer one must be flagged.
	near := time.Now().AddDate(0, 0, 20).UTC().Format(time.RFC3339)
	far := time.Now().AddDate(1, 1, 0).UTC().Format(time.RFC3339)
	if err := db.UpsertAPNSTopic(ctx, "com.apple.mgmt.External.fleet-nov", near, "CN=fleet", "nick"); err != nil {
		t.Fatal(err)
	}
	if err := db.UpsertAPNSTopic(ctx, "com.apple.mgmt.External.test-2027", far, "CN=test", "nick"); err != nil {
		t.Fatal(err)
	}

	body := loadDashboard(t, m)
	if !strings.Contains(body, "com.apple.mgmt.External.fleet-nov") {
		t.Error("dashboard missing the near-expiry topic")
	}
	if !strings.Contains(body, "com.apple.mgmt.External.test-2027") {
		t.Error("dashboard missing the far-expiry topic")
	}
	// The 20-day topic falls in the 30-day (warning) tier and must be flagged.
	if !strings.Contains(body, "sev-warning") {
		t.Error("dashboard did not flag the nearer-expiry topic with a renewal tier")
	}
	if !strings.Contains(body, "⚠️") {
		t.Error("dashboard summary did not warn about an expiring APNs cert")
	}
}

// loadDashboard logs in as the seeded admin and returns the /admin body.
func loadDashboard(t *testing.T, m *http.ServeMux) string {
	t.Helper()
	form := strings.NewReader("username=nick&password=hunter2hunter2")
	req := httptest.NewRequest(http.MethodPost, "/login", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	m.ServeHTTP(rr, req)
	cookies := rr.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("login did not set a session cookie")
	}
	req2 := httptest.NewRequest(http.MethodGet, "/admin", nil)
	for _, c := range cookies {
		req2.AddCookie(c)
	}
	rr2 := httptest.NewRecorder()
	m.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusOK {
		t.Fatalf("dashboard = %d, want 200", rr2.Code)
	}
	return rr2.Body.String()
}

func TestLoginRejectsBadPassword(t *testing.T) {
	app, _, _ := testApp(t)
	form := strings.NewReader("username=nick&password=wrong")
	req := httptest.NewRequest(http.MethodPost, "/login", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	mux(app).ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("bad login = %d, want 401", rr.Code)
	}
}
