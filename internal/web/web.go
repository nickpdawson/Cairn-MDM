// Package web serves Cairn's admin console: a light-first, Apple-HIG-inspired,
// server-rendered UI (html/template) over the device inventory and enrollment.
// It deliberately avoids a JavaScript build step — the polish lives in the CSS.
package web

import (
	"context"
	"database/sql"
	"embed"
	"html/template"
	"log/slog"
	"net/http"
	"time"

	"github.com/dzsec/cairn/internal/auth"
	"github.com/dzsec/cairn/internal/storage/sqlite"
)

//go:embed templates/*.html assets/*
var files embed.FS

// SessionCookie is the name of the session cookie. The __Host- prefix pins it to
// the origin, HTTPS-only, no subdomains — the browser enforces this.
const SessionCookie = "__Host-cairn_session"

// Authenticator verifies local credentials.
type Authenticator interface {
	Authenticate(ctx context.Context, username, password string) (*auth.Identity, error)
}

// DeviceSource provides the inventory for the console.
type DeviceSource interface {
	ListDevices(ctx context.Context) ([]sqlite.Device, error)
	GetDevice(ctx context.Context, id string) (sqlite.Device, error)
	DeviceCounts(ctx context.Context) (total, active int, err error)
}

// SettingsSource reads stored settings (e.g. the APNs topic/expiry).
type SettingsSource interface {
	GetSetting(ctx context.Context, key string) (string, error)
}

// ProfileStore is the configuration-profile library plus per-device command
// history (both live in the same storage).
type ProfileStore interface {
	SaveProfile(ctx context.Context, p sqlite.Profile) (int64, error)
	ListProfiles(ctx context.Context) ([]sqlite.Profile, error)
	GetProfile(ctx context.Context, id int64) (sqlite.Profile, error)
	DeleteProfile(ctx context.Context, id int64) error
	ListCommands(ctx context.Context, deviceID string, limit int) ([]sqlite.CommandEntry, error)
}

// GroupStore manages device groups and profile assignments.
type GroupStore interface {
	CreateGroup(ctx context.Context, name, description string) (int64, error)
	ListGroups(ctx context.Context) ([]sqlite.Group, error)
	GetGroup(ctx context.Context, id int64) (sqlite.Group, error)
	DeleteGroup(ctx context.Context, id int64) error
	AddDeviceToGroup(ctx context.Context, groupID int64, deviceID string) error
	RemoveDeviceFromGroup(ctx context.Context, groupID int64, deviceID string) error
	AssignProfile(ctx context.Context, groupID, profileID int64) error
	UnassignProfile(ctx context.Context, groupID, profileID int64) error
	GroupDevices(ctx context.Context, groupID int64) ([]sqlite.Device, error)
	GroupProfiles(ctx context.Context, groupID int64) ([]sqlite.Profile, error)
	DeviceGroups(ctx context.Context, deviceID string) ([]sqlite.Group, error)
}

// Store bundles everything the console reads and writes; *sqlite.DB implements
// all of it.
type Store interface {
	DeviceSource
	SettingsSource
	ProfileStore
	GroupStore
}

// Commander runs device actions from the console.
type Commander interface {
	SendDeviceInformation(ctx context.Context, ids ...string) error
	SendInstallProfile(ctx context.Context, profile []byte, ids ...string) error
	SendRemoveProfile(ctx context.Context, identifier string, ids ...string) error
}

// Reconciler pushes assigned profiles after membership/assignment changes.
type Reconciler interface {
	ReconcileDevice(ctx context.Context, deviceID string) error
	ReconcileGroup(ctx context.Context, groupID int64) error
}

// Config holds display settings.
type Config struct {
	PublicURL string // for showing the enrollment URL
}

// App is the admin console.
type App struct {
	sessions *auth.SessionStore
	auth     Authenticator
	devices  DeviceSource
	settings SettingsSource
	profiles ProfileStore
	groups   GroupStore
	cmd      Commander
	rec      Reconciler // may be nil (no auto-push)
	cfg      Config
	tmpl     *template.Template
	log      *slog.Logger
}

// New builds the console. rec may be nil to disable assignment auto-push.
func New(sessions *auth.SessionStore, authn Authenticator, store Store, cmd Commander, rec Reconciler, cfg Config, log *slog.Logger) (*App, error) {
	tmpl, err := template.New("").Funcs(funcMap).ParseFS(files, "templates/*.html")
	if err != nil {
		return nil, err
	}
	return &App{
		sessions: sessions, auth: authn,
		devices: store, settings: store, profiles: store, groups: store,
		cmd: cmd, rec: rec, cfg: cfg, tmpl: tmpl, log: log,
	}, nil
}

// Register mounts the console routes on mux. Implementing this interface keeps
// the server package from importing web.
func (a *App) Register(mux *http.ServeMux) {
	// Static assets.
	mux.Handle("GET /assets/", http.FileServerFS(files))

	// Public auth routes.
	mux.HandleFunc("GET /login", a.handleLoginForm)
	mux.HandleFunc("POST /login", a.handleLogin)
	mux.HandleFunc("POST /logout", a.handleLogout)

	// Authenticated console (operator or higher).
	mux.Handle("GET /admin", a.requireRole(auth.RoleOperator, a.handleDashboard))
	mux.Handle("GET /admin/devices", a.requireRole(auth.RoleOperator, a.handleDevices))
	mux.Handle("GET /admin/devices/{id}", a.requireRole(auth.RoleOperator, a.handleDeviceDetail))
	mux.Handle("POST /admin/devices/{id}/refresh", a.requireRole(auth.RoleOperator, a.handleDeviceRefresh))

	// Profile library. Viewing/pushing is operator work; changing the library
	// (upload/delete) is admin-only.
	mux.Handle("GET /admin/profiles", a.requireRole(auth.RoleOperator, a.handleProfiles))
	mux.Handle("POST /admin/profiles/upload", a.requireRole(auth.RoleAdmin, a.handleProfileUpload))
	mux.Handle("GET /admin/profiles/{id}", a.requireRole(auth.RoleOperator, a.handleProfileDetail))
	mux.Handle("GET /admin/profiles/{id}/download", a.requireRole(auth.RoleOperator, a.handleProfileDownload))
	mux.Handle("POST /admin/profiles/{id}/delete", a.requireRole(auth.RoleAdmin, a.handleProfileDelete))

	// Groups + assignments. Membership/assignment changes trigger the
	// reconciler, which pushes profiles — admin-only, like the library.
	mux.Handle("GET /admin/groups", a.requireRole(auth.RoleOperator, a.handleGroups))
	mux.Handle("POST /admin/groups", a.requireRole(auth.RoleAdmin, a.handleGroupCreate))
	mux.Handle("GET /admin/groups/{id}", a.requireRole(auth.RoleOperator, a.handleGroupDetail))
	mux.Handle("POST /admin/groups/{id}/delete", a.requireRole(auth.RoleAdmin, a.handleGroupDelete))
	mux.Handle("POST /admin/groups/{id}/devices", a.requireRole(auth.RoleAdmin, a.handleGroupDeviceChange))
	mux.Handle("POST /admin/groups/{id}/profiles", a.requireRole(auth.RoleAdmin, a.handleGroupProfileChange))

	// Bare "/" redirects to the console.
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/admin", http.StatusFound)
	})
}

// ctxKey is the type for the request-scoped session value.
type ctxKey int

const sessionKey ctxKey = 0

// requireRole wraps h with session loading and a minimum-role check. Anything
// unauthenticated redirects to /login; insufficient role gets 403.
func (a *App) requireRole(min auth.Role, h http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess := a.currentSession(r)
		if sess == nil {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		if !sess.Identity.Role.AtLeast(min) {
			a.render(w, r, http.StatusForbidden, "error.html", map[string]any{
				"Title": "Forbidden", "Message": "Your account does not have access to this page.",
			})
			return
		}
		ctx := context.WithValue(r.Context(), sessionKey, sess)
		h(w, r.WithContext(ctx))
	})
}

// currentSession loads and validates the session from the request cookie.
func (a *App) currentSession(r *http.Request) *auth.Session {
	c, err := r.Cookie(SessionCookie)
	if err != nil {
		return nil
	}
	sess, err := a.sessions.Get(r.Context(), c.Value)
	if err != nil {
		return nil
	}
	return sess
}

func sessionFrom(r *http.Request) *auth.Session {
	s, _ := r.Context().Value(sessionKey).(*auth.Session)
	return s
}

// setSessionCookie writes the __Host- session cookie.
func setSessionCookie(w http.ResponseWriter, token string, expires time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookie,
		Value:    token,
		Path:     "/",
		Expires:  expires,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

func clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: SessionCookie, Value: "", Path: "/", MaxAge: -1,
		Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})
}

var funcMap = template.FuncMap{
	"nullStr": nullStr,
}

// nullStr renders a nullable timestamp/string column as its value or an em dash.
func nullStr(ns sql.NullString) string {
	if !ns.Valid || ns.String == "" {
		return "—"
	}
	return ns.String
}
