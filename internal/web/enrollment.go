package web

import (
	"encoding/base64"
	"html/template"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	qrcode "github.com/skip2/go-qrcode"

	"github.com/dzsec/cairn/internal/storage/sqlite"
)

func (a *App) handleEnrollment(w http.ResponseWriter, r *http.Request) {
	a.renderEnrollment(w, r, nil)
}

// renderEnrollment lists grants; created (if non-nil) shows a just-created
// grant's one-time link + QR inline (the raw token is never redirected or
// logged — it exists only in this response).
func (a *App) renderEnrollment(w http.ResponseWriter, r *http.Request, created map[string]any) {
	grants, err := a.grants.ListGrants(r.Context())
	if err != nil {
		a.log.Error("list grants", "err", err)
	}
	a.render(w, r, http.StatusOK, "enrollment.html", map[string]any{
		"Title":   "Enrollment",
		"Grants":  grants,
		"Created": created,
		"Flash":   r.URL.Query().Get("flash"),
		"Error":   r.URL.Query().Get("error"),
	})
}

func (a *App) handleGrantCreate(w http.ResponseWriter, r *http.Request) {
	limitForm(w, r)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if !a.checkCSRF(r) {
		http.Error(w, "invalid CSRF token", http.StatusForbidden)
		return
	}
	f := r.PostFormValue

	platform := f("platform")
	switch platform {
	case "macos", "ios", "any":
	default:
		platform = "any"
	}
	maxUses, _ := strconv.Atoi(f("max_uses"))
	if maxUses <= 0 {
		maxUses = 1
	}
	hours, _ := strconv.Atoi(f("expires_hours"))
	if hours <= 0 {
		hours = 24
	}
	expiresAt := time.Now().Add(time.Duration(hours) * time.Hour).UTC().Format("2006-01-02 15:04:05")

	raw, hash := sqlite.NewGrantToken()
	id, err := a.grants.CreateGrant(r.Context(), sqlite.Grant{
		Label:          strings.TrimSpace(f("label")),
		Platform:       platform,
		Owner:          strings.TrimSpace(f("owner")),
		CreatedBy:      sessionFrom(r).Identity.Username,
		ExpiresAt:      expiresAt,
		MaxUses:        maxUses,
		ExpectedSerial: strings.TrimSpace(f("expected_serial")),
	}, hash)
	if err != nil {
		a.log.Error("create grant", "err", err)
		http.Redirect(w, r, "/admin/enrollment?error="+url.QueryEscape("Creating the grant failed."), http.StatusSeeOther)
		return
	}

	link := strings.TrimRight(a.cfg.PublicURL, "/") + "/e/" + raw
	a.log.Info("enrollment grant created", "id", id, "owner", f("owner"), "platform", platform,
		"user", sessionFrom(r).Identity.Username) // never logs the raw token

	created := map[string]any{"Link": link, "QR": qrDataURI(link), "ExpiresHours": hours, "MaxUses": maxUses}
	a.renderEnrollment(w, r, created)
}

func (a *App) handleGrantRevoke(w http.ResponseWriter, r *http.Request) {
	if !a.checkCSRF(r) {
		http.Error(w, "invalid CSRF token", http.StatusForbidden)
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if err := a.grants.RevokeGrant(r.Context(), id); err != nil {
		a.log.Error("revoke grant", "id", id, "err", err)
		http.Redirect(w, r, "/admin/enrollment?error="+url.QueryEscape("Revoke failed."), http.StatusSeeOther)
		return
	}
	a.log.Info("enrollment grant revoked", "id", id, "user", sessionFrom(r).Identity.Username)
	http.Redirect(w, r, "/admin/enrollment?flash="+url.QueryEscape("Grant revoked."), http.StatusSeeOther)
}

// qrDataURI renders a QR PNG for s as a data: URI (self-contained, no external
// requests — CSP-safe under img-src 'self' data:). Returned as template.URL
// because html/template otherwise rewrites data: URLs in src to #ZgotmplZ; the
// value is safe because we generate it here from a QR encode, not user HTML.
func qrDataURI(s string) template.URL {
	png, err := qrcode.Encode(s, qrcode.Medium, 256)
	if err != nil {
		return ""
	}
	return template.URL("data:image/png;base64," + base64.StdEncoding.EncodeToString(png))
}
