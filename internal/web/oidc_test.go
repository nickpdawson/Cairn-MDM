package web

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nickpdawson/cairn-mdm/internal/auth"
)

// stubOIDC is a fake OIDCProvider: AuthCodeURL echoes the state, and Exchange
// returns a preset identity (or error). It records what it was called with.
type stubOIDC struct {
	authURL     string
	id          *auth.Identity
	exchangeErr error

	gotState string
	gotNonce string
	gotCode  string
	gotExNon string
}

func (s *stubOIDC) AuthCodeURL(state, nonce string) string {
	s.gotState, s.gotNonce = state, nonce
	return s.authURL + "?state=" + state + "&nonce=" + nonce
}

func (s *stubOIDC) Exchange(_ context.Context, code, nonce string) (*auth.Identity, error) {
	s.gotCode, s.gotExNon = code, nonce
	if s.exchangeErr != nil {
		return nil, s.exchangeErr
	}
	return s.id, nil
}

func cookieNamed(cookies []*http.Cookie, name string) *http.Cookie {
	for _, c := range cookies {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func TestOIDCDisabledByDefault(t *testing.T) {
	app, _, _ := testApp(t)
	m := mux(app)

	// The login page hides the SSO button.
	rr := httptest.NewRecorder()
	m.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/login", nil))
	if strings.Contains(rr.Body.String(), "/auth/oidc/login") {
		t.Error("login page showed the SSO button while OIDC is disabled")
	}

	// The login route is registered but reports SSO disabled (no redirect).
	rr = httptest.NewRecorder()
	m.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/auth/oidc/login", nil))
	if rr.Code == http.StatusFound {
		t.Errorf("oidc login redirected while disabled: %d", rr.Code)
	}
}

func TestOIDCLoginRedirectsAndSetsCookies(t *testing.T) {
	app, _, _ := testApp(t)
	stub := &stubOIDC{authURL: "https://idp.example.org/authorize"}
	app.SetOIDC(stub)
	m := mux(app)

	// The login page now shows the SSO button.
	rr := httptest.NewRecorder()
	m.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/login", nil))
	if !strings.Contains(rr.Body.String(), "/auth/oidc/login") {
		t.Error("login page missing the SSO button while OIDC is enabled")
	}

	rr = httptest.NewRecorder()
	m.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/auth/oidc/login", nil))
	if rr.Code != http.StatusFound {
		t.Fatalf("oidc login = %d, want 302", rr.Code)
	}
	loc := rr.Header().Get("Location")
	if !strings.HasPrefix(loc, "https://idp.example.org/authorize") {
		t.Errorf("redirect Location = %q, want the stub authorize URL", loc)
	}
	cookies := rr.Result().Cookies()
	state := cookieNamed(cookies, oidcStateCookie)
	nonce := cookieNamed(cookies, oidcNonceCookie)
	if state == nil || state.Value == "" {
		t.Fatal("login did not set the state cookie")
	}
	if nonce == nil || nonce.Value == "" {
		t.Fatal("login did not set the nonce cookie")
	}
	if stub.gotState != state.Value || stub.gotNonce != nonce.Value {
		t.Errorf("AuthCodeURL got state/nonce %q/%q, cookies %q/%q",
			stub.gotState, stub.gotNonce, state.Value, nonce.Value)
	}
	if !strings.Contains(loc, "state="+state.Value) {
		t.Errorf("authorize URL %q did not carry the state", loc)
	}
}

func TestOIDCCallbackStateMismatchNoSession(t *testing.T) {
	app, _, _ := testApp(t)
	stub := &stubOIDC{id: &auth.Identity{Username: "alice", Role: auth.RoleOperator, Provider: "oidc"}}
	app.SetOIDC(stub)
	m := mux(app)

	req := httptest.NewRequest(http.MethodGet, "/auth/oidc/callback?state=attacker&code=abc", nil)
	req.AddCookie(&http.Cookie{Name: oidcStateCookie, Value: "genuine"})
	req.AddCookie(&http.Cookie{Name: oidcNonceCookie, Value: "nnn"})
	rr := httptest.NewRecorder()
	m.ServeHTTP(rr, req)

	if rr.Code == http.StatusFound {
		t.Fatalf("state mismatch redirected (%d); it must not create a session", rr.Code)
	}
	if c := cookieNamed(rr.Result().Cookies(), SessionCookie); c != nil && c.Value != "" {
		t.Error("a session cookie was set despite the state mismatch")
	}
	if stub.gotCode != "" {
		t.Error("Exchange was called even though the state did not match")
	}
}

func TestOIDCCallbackSuccessCreatesSession(t *testing.T) {
	app, _, _ := testApp(t)
	stub := &stubOIDC{
		authURL: "https://idp.example.org/authorize",
		id:      &auth.Identity{Username: "alice", DisplayName: "Alice", Role: auth.RoleOperator, Provider: "oidc"},
	}
	app.SetOIDC(stub)
	m := mux(app)

	// Drive the login route to obtain a genuine state/nonce cookie pair.
	lrr := httptest.NewRecorder()
	m.ServeHTTP(lrr, httptest.NewRequest(http.MethodGet, "/auth/oidc/login", nil))
	cookies := lrr.Result().Cookies()
	state := cookieNamed(cookies, oidcStateCookie)
	nonce := cookieNamed(cookies, oidcNonceCookie)
	if state == nil || nonce == nil {
		t.Fatal("login did not set state/nonce cookies")
	}

	req := httptest.NewRequest(http.MethodGet, "/auth/oidc/callback?state="+state.Value+"&code=thecode", nil)
	req.AddCookie(state)
	req.AddCookie(nonce)
	rr := httptest.NewRecorder()
	m.ServeHTTP(rr, req)

	if rr.Code != http.StatusFound || rr.Header().Get("Location") != "/admin" {
		t.Fatalf("callback = %d -> %q, want 302 -> /admin", rr.Code, rr.Header().Get("Location"))
	}
	sc := cookieNamed(rr.Result().Cookies(), SessionCookie)
	if sc == nil || sc.Value == "" {
		t.Fatal("successful callback did not set a session cookie")
	}
	if stub.gotCode != "thecode" {
		t.Errorf("Exchange got code %q, want thecode", stub.gotCode)
	}
	if stub.gotExNon != nonce.Value {
		t.Errorf("Exchange got nonce %q, want the stored %q", stub.gotExNon, nonce.Value)
	}

	// The session is usable: the dashboard loads with the new cookie.
	dreq := httptest.NewRequest(http.MethodGet, "/admin", nil)
	dreq.AddCookie(sc)
	drr := httptest.NewRecorder()
	m.ServeHTTP(drr, dreq)
	if drr.Code != http.StatusOK {
		t.Fatalf("dashboard with oidc session = %d, want 200", drr.Code)
	}
}

func TestOIDCCallbackExchangeErrorNoSession(t *testing.T) {
	app, _, _ := testApp(t)
	stub := &stubOIDC{
		authURL:     "https://idp.example.org/authorize",
		exchangeErr: errors.New("nonce mismatch"),
	}
	app.SetOIDC(stub)
	m := mux(app)

	lrr := httptest.NewRecorder()
	m.ServeHTTP(lrr, httptest.NewRequest(http.MethodGet, "/auth/oidc/login", nil))
	cookies := lrr.Result().Cookies()
	state := cookieNamed(cookies, oidcStateCookie)
	nonce := cookieNamed(cookies, oidcNonceCookie)

	req := httptest.NewRequest(http.MethodGet, "/auth/oidc/callback?state="+state.Value+"&code=thecode", nil)
	req.AddCookie(state)
	req.AddCookie(nonce)
	rr := httptest.NewRecorder()
	m.ServeHTTP(rr, req)

	if rr.Code == http.StatusFound {
		t.Fatalf("exchange failure redirected (%d); it must not create a session", rr.Code)
	}
	if c := cookieNamed(rr.Result().Cookies(), SessionCookie); c != nil && c.Value != "" {
		t.Error("a session cookie was set despite the exchange failure")
	}
}
