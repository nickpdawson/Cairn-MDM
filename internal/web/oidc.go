package web

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"

	"github.com/nickpdawson/cairn-mdm/internal/auth"
)

// OIDCProvider is the narrow view of the OIDC login flow the web layer needs.
// Keeping it an interface (rather than importing the concrete
// internal/auth/oidc.Provider) lets tests stub the IdP round-trip and keeps the
// web package free of the go-oidc/oauth2 dependency.
type OIDCProvider interface {
	// AuthCodeURL builds the IdP authorize URL, binding the CSRF state and the
	// replay-defense nonce.
	AuthCodeURL(state, nonce string) string
	// Exchange trades the callback code for a verified identity, checking the
	// nonce against expectedNonce.
	Exchange(ctx context.Context, code, expectedNonce string) (*auth.Identity, error)
}

// SetOIDC installs (or clears, with nil) the OIDC provider. When nil the
// /auth/oidc/* routes report that SSO is disabled and the login page hides the
// SSO button. Call once during startup, before serving.
func (a *App) SetOIDC(p OIDCProvider) { a.oidc = p }

// Short-lived cookies that carry the CSRF state and the OIDC nonce across the
// redirect to the IdP and back. The __Host- prefix pins them to the origin
// (HTTPS-only, no subdomains); they are HttpOnly so page scripts can't read
// them and are cleared as soon as the callback consumes them.
const (
	oidcStateCookie = "__Host-cairn_oidc_state"
	oidcNonceCookie = "__Host-cairn_oidc_nonce"
)

// handleOIDCLogin starts the authorization-code flow: mint a random state +
// nonce, stash them in short-lived cookies, and redirect to the IdP.
func (a *App) handleOIDCLogin(w http.ResponseWriter, r *http.Request) {
	if a.oidc == nil {
		a.render(w, r, http.StatusNotFound, "login.html", map[string]any{
			"Error": "Single sign-on is not enabled.",
		})
		return
	}
	// Already signed in? Go to the console.
	if a.currentSession(r) != nil {
		http.Redirect(w, r, "/admin", http.StatusFound)
		return
	}
	state, err := randToken()
	if err != nil {
		a.log.Error("oidc: generate state", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	nonce, err := randToken()
	if err != nil {
		a.log.Error("oidc: generate nonce", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	setShortCookie(w, oidcStateCookie, state)
	setShortCookie(w, oidcNonceCookie, nonce)
	http.Redirect(w, r, a.oidc.AuthCodeURL(state, nonce), http.StatusFound)
}

// handleOIDCCallback completes the flow: verify the state (CSRF), exchange the
// code (which verifies the ID token and nonce), then create a session.
func (a *App) handleOIDCCallback(w http.ResponseWriter, r *http.Request) {
	if a.oidc == nil {
		a.render(w, r, http.StatusNotFound, "login.html", map[string]any{
			"Error": "Single sign-on is not enabled.",
		})
		return
	}

	// Read the stashed state/nonce, then clear both cookies unconditionally so a
	// single value can never be replayed against a later callback.
	stateCookie, stateErr := r.Cookie(oidcStateCookie)
	nonceCookie, nonceErr := r.Cookie(oidcNonceCookie)
	clearShortCookie(w, oidcStateCookie)
	clearShortCookie(w, oidcNonceCookie)

	q := r.URL.Query()
	if e := q.Get("error"); e != "" {
		a.log.Info("oidc: idp returned error", "error", e, "remote", r.RemoteAddr)
		a.loginError(w, r, "Single sign-on was declined by the identity provider.")
		return
	}

	// State check: the query param must match the HttpOnly cookie (double-submit
	// CSRF defense for the redirect). A missing or mismatched value is rejected.
	state := q.Get("state")
	if stateErr != nil || stateCookie.Value == "" || state == "" || state != stateCookie.Value {
		a.log.Info("oidc: state check failed", "remote", r.RemoteAddr)
		a.loginError(w, r, "Sign-on could not be verified. Please try again.")
		return
	}

	code := q.Get("code")
	if code == "" {
		a.loginError(w, r, "Sign-on returned no authorization code.")
		return
	}
	nonce := ""
	if nonceErr == nil {
		nonce = nonceCookie.Value
	}

	id, err := a.oidc.Exchange(r.Context(), code, nonce)
	if err != nil {
		a.log.Info("oidc: exchange failed", "err", err, "remote", r.RemoteAddr)
		a.loginError(w, r, "Single sign-on failed.")
		return
	}

	sess, err := a.sessions.Create(r.Context(), *id)
	if err != nil {
		a.log.Error("oidc: create session", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	setSessionCookie(w, sess.Token, sess.ExpiresAt)
	a.log.Info("oidc login", "username", id.Username, "role", id.Role)
	http.Redirect(w, r, "/admin", http.StatusFound)
}

// loginError re-renders the login page with an error message.
func (a *App) loginError(w http.ResponseWriter, r *http.Request, msg string) {
	a.render(w, r, http.StatusUnauthorized, "login.html", map[string]any{"Error": msg})
}

// setShortCookie writes a 10-minute HttpOnly cookie for the redirect round-trip.
func setShortCookie(w http.ResponseWriter, name, value string) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		MaxAge:   600,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

func clearShortCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{
		Name: name, Value: "", Path: "/", MaxAge: -1,
		Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})
}

// randToken returns 32 bytes of hex-encoded CSPRNG output for state/nonce.
func randToken() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}
