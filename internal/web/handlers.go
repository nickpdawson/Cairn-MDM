package web

import (
	"net/http"
	"strings"
)

// render executes a template as a full page. On error it logs and writes a 500.
func (a *App) render(w http.ResponseWriter, r *http.Request, status int, name string, data map[string]any) {
	if data == nil {
		data = map[string]any{}
	}
	if sess := sessionFrom(r); sess != nil {
		data["User"] = sess.Identity
		data["CSRF"] = sess.CSRF
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := a.tmpl.ExecuteTemplate(w, name, data); err != nil {
		a.log.Error("template render failed", "template", name, "err", err)
	}
}

func (a *App) handleLoginForm(w http.ResponseWriter, r *http.Request) {
	// Already signed in? Go to the console.
	if a.currentSession(r) != nil {
		http.Redirect(w, r, "/admin", http.StatusFound)
		return
	}
	a.render(w, r, http.StatusOK, "login.html", nil)
}

func (a *App) handleLogin(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	username := strings.TrimSpace(r.PostFormValue("username"))
	password := r.PostFormValue("password")

	id, err := a.auth.Authenticate(r.Context(), username, password)
	if err != nil {
		a.log.Info("failed login", "username", username, "remote", r.RemoteAddr)
		a.render(w, r, http.StatusUnauthorized, "login.html", map[string]any{
			"Error": "Incorrect username or password.", "Username": username,
		})
		return
	}

	sess, err := a.sessions.Create(r.Context(), *id)
	if err != nil {
		a.log.Error("create session", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	setSessionCookie(w, sess.Token, sess.ExpiresAt)
	a.log.Info("login", "username", id.Username, "role", id.Role)
	http.Redirect(w, r, "/admin", http.StatusFound)
}

func (a *App) handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(SessionCookie); err == nil {
		if !a.checkCSRF(r) {
			http.Error(w, "invalid CSRF token", http.StatusForbidden)
			return
		}
		_ = a.sessions.Delete(r.Context(), c.Value)
	}
	clearSessionCookie(w)
	http.Redirect(w, r, "/login", http.StatusFound)
}

func (a *App) handleDashboard(w http.ResponseWriter, r *http.Request) {
	total, active, err := a.devices.DeviceCounts(r.Context())
	if err != nil {
		a.log.Error("device counts", "err", err)
	}
	devices, err := a.devices.ListDevices(r.Context())
	if err != nil {
		a.log.Error("list devices", "err", err)
	}
	recent := devices
	if len(recent) > 5 {
		recent = recent[:5]
	}
	a.render(w, r, http.StatusOK, "dashboard.html", map[string]any{
		"Title":         "Dashboard",
		"Total":         total,
		"Active":        active,
		"Recent":        recent,
		"EnrollmentURL": strings.TrimRight(a.cfg.PublicURL, "/") + "/enroll",
	})
}

func (a *App) handleDevices(w http.ResponseWriter, r *http.Request) {
	devices, err := a.devices.ListDevices(r.Context())
	if err != nil {
		a.log.Error("list devices", "err", err)
	}
	a.render(w, r, http.StatusOK, "devices.html", map[string]any{
		"Title":   "Devices",
		"Devices": devices,
	})
}

// checkCSRF verifies the submitted token matches the session's for mutating
// requests.
func (a *App) checkCSRF(r *http.Request) bool {
	sess := a.currentSession(r)
	if sess == nil {
		return false
	}
	got := r.PostFormValue("csrf")
	if got == "" {
		got = r.Header.Get("X-CSRF-Token")
	}
	return got != "" && got == sess.CSRF
}
