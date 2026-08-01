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

// APNSTopicSource lists the per-topic APNs push-certificate metadata the
// dashboard renders. Modeling every topic (not one global setting) is the fix
// for MDM-APNS-001 — a second fleet's expiry must not hide behind a later date.
type APNSTopicSource interface {
	ListAPNSTopics(ctx context.Context) ([]sqlite.APNSTopic, error)
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

// GrantStore manages single-use enrollment grants.
type GrantStore interface {
	CreateGrant(ctx context.Context, g sqlite.Grant, tokenHash string) (int64, error)
	ListGrants(ctx context.Context) ([]sqlite.Grant, error)
	GetGrant(ctx context.Context, id int64) (sqlite.Grant, error)
	RevokeGrant(ctx context.Context, id int64) error
}

// AuditStore records and reads the append-only audit log of security-sensitive
// admin actions. *sqlite.DB satisfies it.
type AuditStore interface {
	AppendAudit(ctx context.Context, e sqlite.AuditEntry) error
	ListAudit(ctx context.Context, limit int) ([]sqlite.AuditEntry, error)
}

// DeployStore reads profile-deploy status: what group-assigned profiles have
// been pushed where, and how the pushes landed. *sqlite.DB satisfies it.
type DeployStore interface {
	DeviceDeploys(ctx context.Context, deviceID string) ([]sqlite.DeviceDeploy, error)
	ProfileDeploys(ctx context.Context, profileID int64) ([]sqlite.ProfileDeploy, error)
	GroupDeployStatus(ctx context.Context, groupID int64) ([]sqlite.GroupProfileStatus, error)
}

// Store bundles everything the console reads and writes; *sqlite.DB implements
// all of it.
type Store interface {
	DeviceSource
	SettingsSource
	APNSTopicSource
	ProfileStore
	GroupStore
	GrantStore
	AuditStore
	DeployStore
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

// Config holds display settings and the defaults the profile builders prefill.
type Config struct {
	PublicURL string // for showing the enrollment URL

	// Builder defaults, from the wired PKI:
	Organization  string   // reverse-DNS identifier root for built profiles
	SCEPURL       string   // device-identity SCEP endpoint
	SCEPChallenge string   // its static challenge (may be empty)
	CAAnchorsDER  [][]byte // Cairn's trust anchors (embedded CA cert or external chain)
}

// App is the admin console.
type App struct {
	sessions   *auth.SessionStore
	auth       Authenticator
	devices    DeviceSource
	settings   SettingsSource
	apnsTopics APNSTopicSource
	profiles   ProfileStore
	groups     GroupStore
	grants     GrantStore
	audit      AuditStore
	deploys    DeployStore
	cmd        Commander
	rec        Reconciler   // may be nil (no auto-push)
	oidc       OIDCProvider // may be nil (OIDC disabled); set via SetOIDC
	cfg        Config
	tmpl       *template.Template
	log        *slog.Logger
}

// New builds the console. rec may be nil to disable assignment auto-push.
func New(sessions *auth.SessionStore, authn Authenticator, store Store, cmd Commander, rec Reconciler, cfg Config, log *slog.Logger) (*App, error) {
	a := &App{
		sessions: sessions, auth: authn,
		devices: store, settings: store, apnsTopics: store, profiles: store, groups: store, grants: store, audit: store, deploys: store,
		cmd: cmd, rec: rec, cfg: cfg, log: log,
	}
	// oidcEnabled lets the login template render the SSO button only when an
	// OIDC provider has been installed. The closure reads a.oidc at render time,
	// after SetOIDC has (or has not) run during startup.
	tmpl, err := template.New("").Funcs(funcMap).Funcs(template.FuncMap{
		"oidcEnabled": func() bool { return a.oidc != nil },
	}).ParseFS(files, "templates/*.html")
	if err != nil {
		return nil, err
	}
	a.tmpl = tmpl
	return a, nil
}

// Register mounts the console routes on mux. Implementing this interface keeps
// the server package from importing web.
func (a *App) Register(mux *http.ServeMux) {
	// Static assets.
	mux.Handle("GET /assets/", http.FileServerFS(files))

	// Public auth routes. The mutating ones (POST /login, POST /logout) are
	// wrapped with a.audited so every sign-in/sign-out is recorded.
	mux.HandleFunc("GET /login", a.handleLoginForm)
	mux.Handle("POST /login", a.audited(http.HandlerFunc(a.handleLogin)))
	mux.Handle("POST /logout", a.audited(http.HandlerFunc(a.handleLogout)))

	// OIDC single sign-on (redirect flow). Registered unconditionally: when no
	// provider is installed the handlers render the login page with an error, so
	// the login-page SSO link degrades gracefully.
	mux.HandleFunc("GET /auth/oidc/login", a.handleOIDCLogin)
	mux.HandleFunc("GET /auth/oidc/callback", a.handleOIDCCallback)

	// Authenticated console (operator or higher).
	mux.Handle("GET /admin", a.requireRole(auth.RoleOperator, a.handleDashboard))
	mux.Handle("GET /admin/activity", a.requireRole(auth.RoleOperator, a.handleActivity))
	mux.Handle("GET /admin/devices", a.requireRole(auth.RoleOperator, a.handleDevices))
	mux.Handle("GET /admin/devices/{id}", a.requireRole(auth.RoleOperator, a.handleDeviceDetail))
	mux.Handle("POST /admin/devices/{id}/refresh", a.audited(a.requireRole(auth.RoleOperator, a.handleDeviceRefresh)))
	mux.Handle("POST /admin/devices/{id}/install", a.audited(a.requireRole(auth.RoleOperator, a.handleDeviceInstall)))
	mux.Handle("POST /admin/devices/{id}/remove", a.audited(a.requireRole(auth.RoleOperator, a.handleDeviceRemove)))

	// Profile library. Viewing/pushing is operator work; changing the library
	// (upload/delete) is admin-only.
	mux.Handle("GET /admin/profiles", a.requireRole(auth.RoleOperator, a.handleProfiles))
	mux.Handle("POST /admin/profiles/upload", a.audited(a.requireRole(auth.RoleAdmin, a.handleProfileUpload)))
	mux.Handle("GET /admin/profiles/{id}", a.requireRole(auth.RoleOperator, a.handleProfileDetail))
	mux.Handle("GET /admin/profiles/{id}/download", a.requireRole(auth.RoleOperator, a.handleProfileDownload))
	mux.Handle("POST /admin/profiles/{id}/delete", a.audited(a.requireRole(auth.RoleAdmin, a.handleProfileDelete)))

	// Profile builders (typed payloads generated into the library).
	mux.Handle("GET /admin/profiles/new/wifi", a.requireRole(auth.RoleAdmin, a.handleBuilderWiFiForm))
	mux.Handle("POST /admin/profiles/new/wifi", a.audited(a.requireRole(auth.RoleAdmin, a.handleBuilderWiFi)))
	mux.Handle("GET /admin/profiles/new/sso", a.requireRole(auth.RoleAdmin, a.handleBuilderSSOForm))
	mux.Handle("POST /admin/profiles/new/sso", a.audited(a.requireRole(auth.RoleAdmin, a.handleBuilderSSO)))

	// Groups + assignments. Membership/assignment changes trigger the
	// reconciler, which pushes profiles — admin-only, like the library.
	// Enrollment grants — operators create/revoke single-use enroll links.
	mux.Handle("GET /admin/enrollment", a.requireRole(auth.RoleOperator, a.handleEnrollment))
	mux.Handle("POST /admin/enrollment", a.audited(a.requireRole(auth.RoleOperator, a.handleGrantCreate)))
	mux.Handle("POST /admin/enrollment/{id}/revoke", a.audited(a.requireRole(auth.RoleOperator, a.handleGrantRevoke)))

	mux.Handle("GET /admin/groups", a.requireRole(auth.RoleOperator, a.handleGroups))
	mux.Handle("POST /admin/groups", a.audited(a.requireRole(auth.RoleAdmin, a.handleGroupCreate)))
	mux.Handle("GET /admin/groups/{id}", a.requireRole(auth.RoleOperator, a.handleGroupDetail))
	mux.Handle("POST /admin/groups/{id}/delete", a.audited(a.requireRole(auth.RoleAdmin, a.handleGroupDelete)))
	mux.Handle("POST /admin/groups/{id}/devices", a.audited(a.requireRole(auth.RoleAdmin, a.handleGroupDeviceChange)))
	mux.Handle("POST /admin/groups/{id}/profiles", a.audited(a.requireRole(auth.RoleAdmin, a.handleGroupProfileChange)))

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
