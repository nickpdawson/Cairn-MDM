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
	DeviceCounts(ctx context.Context) (total, active int, err error)
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
	cfg      Config
	tmpl     *template.Template
	log      *slog.Logger
}

// New builds the console.
func New(sessions *auth.SessionStore, authn Authenticator, devices DeviceSource, cfg Config, log *slog.Logger) (*App, error) {
	tmpl, err := template.New("").Funcs(funcMap).ParseFS(files, "templates/*.html")
	if err != nil {
		return nil, err
	}
	return &App{sessions: sessions, auth: authn, devices: devices, cfg: cfg, tmpl: tmpl, log: log}, nil
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
