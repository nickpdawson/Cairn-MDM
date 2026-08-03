package web

import (
	"context"
	"net/http"
	"strconv"

	"github.com/nickpdawson/cairn-mdm/internal/storage/sqlite"
)

// statusRecorder wraps http.ResponseWriter to capture the response status code
// so the audit middleware can record it. It defaults to 200 because a handler
// that writes a body without an explicit WriteHeader implies 200.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	if s.status == 0 {
		s.status = http.StatusOK
	}
	return s.ResponseWriter.Write(b)
}

// audited wraps a mutating route handler so that, AFTER it runs, one row is
// appended to the audit log. It records the acting user (from the session
// cookie if present, else the submitted username for /login), the auth
// provider, the HTTP method as the action, the request PATH as the target
// (never the query string, never the body — no secrets), the response status,
// and the client IP. Wiring it here (in Register) rather than inside each
// handler keeps every mutating action logged from one place and out of
// handlers.go.
func (a *App) audited(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := &statusRecorder{ResponseWriter: w}
		next.ServeHTTP(rec, r)

		if a.audit == nil {
			return
		}
		status := rec.status
		if status == 0 {
			status = http.StatusOK
		}

		username, provider := "", ""
		if sess := a.currentSession(r); sess != nil {
			username = sess.Identity.Username
			provider = sess.Identity.Provider
		}
		if username == "" {
			// /login has no session yet (and on success the cookie is only on the
			// response). Record the submitted username; the handler already parsed
			// the form, so this reads the cached value — never the password.
			username = r.PostFormValue("username")
		}

		// Use a background context so a request cancellation (client disconnect
		// after the response) does not drop the audit write.
		e := sqlite.AuditEntry{
			Username: username,
			Provider: provider,
			Action:   r.Method,
			Target:   r.URL.Path,
			Result:   strconv.Itoa(status),
			Remote:   a.clientIP(r),
		}
		if err := a.audit.AppendAudit(context.Background(), e); err != nil {
			a.log.Error("audit append failed", "action", e.Action, "target", e.Target, "err", err)
		}
	})
}

// handleActivity renders the audit log at /admin/activity (operator+).
func (a *App) handleActivity(w http.ResponseWriter, r *http.Request) {
	entries, err := a.audit.ListAudit(r.Context(), 200)
	if err != nil {
		a.log.Error("list audit", "err", err)
	}
	a.render(w, r, http.StatusOK, "activity.html", map[string]any{
		"Title":   "Activity",
		"Entries": entries,
	})
}
