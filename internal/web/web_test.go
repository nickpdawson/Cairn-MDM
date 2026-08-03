package web

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nickpdawson/cairn-mdm/internal/auth"
	"github.com/nickpdawson/cairn-mdm/internal/config"
	"github.com/nickpdawson/cairn-mdm/internal/mdmcore"
	"github.com/nickpdawson/cairn-mdm/internal/storage/sqlite"
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

func TestDevicesSearchFilters(t *testing.T) {
	app, _, db := testApp(t)
	m := mux(app)
	ctx := context.Background()

	if err := db.DeviceEnrolled(ctx, mdmcore.DeviceRecord{
		ID: "UDID-RIDGE", UDID: "UDID-RIDGE", Serial: "C02RIDGE", Name: "Ridge MBP", Model: "MacBookPro18,2",
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.DeviceEnrolled(ctx, mdmcore.DeviceRecord{
		ID: "UDID-SUMMIT", UDID: "UDID-SUMMIT", Serial: "C02SUMMIT", Name: "Summit Air", Model: "MacBookAir10,1",
	}); err != nil {
		t.Fatal(err)
	}

	// Log in and reuse the session cookie for the devices request.
	form := strings.NewReader("username=nick&password=hunter2hunter2")
	loginReq := httptest.NewRequest(http.MethodPost, "/login", form)
	loginReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	loginRR := httptest.NewRecorder()
	m.ServeHTTP(loginRR, loginReq)
	cookies := loginRR.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("login did not set a session cookie")
	}

	req := httptest.NewRequest(http.MethodGet, "/admin/devices?q=Ridge", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rr := httptest.NewRecorder()
	m.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("devices search = %d, want 200", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "Ridge MBP") {
		t.Error("devices search body missing the matching device")
	}
	if strings.Contains(body, "Summit Air") {
		t.Error("devices search body included a non-matching device")
	}
}

func TestDeviceInstallProfileAndDeployStatus(t *testing.T) {
	app, sessions, db := testApp(t)
	m := mux(app)
	cookie, csrf := adminSession(t, sessions)
	ctx := context.Background()

	if err := db.DeviceEnrolled(ctx, mdmcore.DeviceRecord{
		ID: "UDID-RIDGE", UDID: "UDID-RIDGE", Serial: "C02RIDGE", Name: "Ridge MBP", Model: "MacBookPro18,2",
	}); err != nil {
		t.Fatal(err)
	}
	pid, err := db.SaveProfile(ctx, sqlite.Profile{
		Identifier: "com.example.wifi", UUID: "u-1", Name: "Corp Wi-Fi",
		PayloadTypes: "com.apple.wifi.managed", Source: "upload", Data: []byte("v1"),
	})
	if err != nil {
		t.Fatal(err)
	}

	// POST install: library profile pushed to the device → redirect + flash.
	form := strings.NewReader("csrf=" + csrf + "&profile_id=" + itoa64(pid))
	req := httptest.NewRequest(http.MethodPost, "/admin/devices/UDID-RIDGE/install", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	m.ServeHTTP(rr, req)
	if rr.Code != http.StatusSeeOther {
		t.Fatalf("install = %d, want 303", rr.Code)
	}
	if loc := rr.Header().Get("Location"); !strings.Contains(loc, "flash=Install") {
		t.Fatalf("install redirect = %q, want an Install-queued flash", loc)
	}

	// Seed a deploy row so the device page shows the deployed profile.
	if _, err := db.SQL().ExecContext(ctx,
		`INSERT INTO profile_deploys (device_id, profile_id, command_uuid, profile_updated_at, status, updated_at)
		 VALUES ('UDID-RIDGE', ?, 'cmd-1', 'v1', 'installed', datetime('now'))`, pid); err != nil {
		t.Fatal(err)
	}

	req = httptest.NewRequest(http.MethodGet, "/admin/devices/UDID-RIDGE", nil)
	req.AddCookie(cookie)
	rr = httptest.NewRecorder()
	m.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("device detail = %d, want 200", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "Corp Wi-Fi") {
		t.Error("device page missing the deployed profile name")
	}
	if !strings.Contains(body, "installed") {
		t.Error("device page missing the deploy status")
	}
}

// itoa64 formats an int64 for form bodies without pulling strconv into the test
// preamble more than once.
func itoa64(n int64) string { return strconv.FormatInt(n, 10) }

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
