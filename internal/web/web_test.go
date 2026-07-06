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
	app, err := New(sessions, local, db, db, db, stubCommander{}, Config{PublicURL: "https://mdm.example.org"}, slog.New(slog.NewTextHandler(io.Discard, nil)))
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
