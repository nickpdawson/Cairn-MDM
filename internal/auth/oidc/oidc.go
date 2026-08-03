// Package oidc is Cairn's OpenID Connect single-sign-on provider: the
// authorization-code login flow (e.g. against Authentik), complementing the
// local and LDAP providers.
//
// This is a browser redirect flow, not a username/password check, so it does
// NOT implement the auth.Authenticator interface. The web layer drives it over
// two routes (/auth/oidc/login and /auth/oidc/callback) and mints a session
// from the returned Identity.
//
// Design goals mirror the LDAP provider:
//
//  1. No implicit privilege. A group value from the configured group claim maps
//     to a role via group_roles; an authenticated user matching no mapped group
//     gets the default role ("user"). There is deliberately no path where
//     "authenticated at the IdP" implies "admin".
//  2. Verify the ID token: the token endpoint response is exchanged, the ID
//     token signature/issuer/audience are verified, and the nonce is checked
//     against the value stored before the redirect (replay defense).
package oidc

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"

	coreoidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/dzsec/cairn-mdm/internal/auth"
	"github.com/dzsec/cairn-mdm/internal/config"
)

// Provider runs the OIDC authorization-code flow against a discovered issuer.
type Provider struct {
	cfg        config.OIDCCfg
	oauth      *oauth2.Config
	verifier   *coreoidc.IDTokenVerifier
	httpClient *http.Client
}

// New discovers the issuer and builds the flow. redirectURL is the absolute
// callback URL (publicURL + "/auth/oidc/callback"). An optional ca_file trusts
// an internal CA for the IdP's TLS on top of the system roots.
func New(ctx context.Context, cfg config.OIDCCfg, redirectURL string) (*Provider, error) {
	cfg = cfg.WithDefaults()

	httpClient := http.DefaultClient
	if cfg.CAFile != "" {
		pool, err := x509.SystemCertPool()
		if err != nil {
			pool = x509.NewCertPool()
		}
		pem, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("oidc: read ca_file: %w", err)
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("oidc: ca_file %s contains no certificates", cfg.CAFile)
		}
		httpClient = &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}
	}

	// oidc.ClientContext threads our http.Client through discovery, JWKS fetch,
	// and the token exchange so the ca_file trust applies to all of them.
	dctx := coreoidc.ClientContext(ctx, httpClient)
	op, err := coreoidc.NewProvider(dctx, cfg.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("oidc: discover issuer %q: %w", cfg.IssuerURL, err)
	}

	return &Provider{
		cfg: cfg,
		oauth: &oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			Endpoint:     op.Endpoint(),
			RedirectURL:  redirectURL,
			Scopes:       cfg.Scopes,
		},
		verifier:   op.Verifier(&coreoidc.Config{ClientID: cfg.ClientID}),
		httpClient: httpClient,
	}, nil
}

// AuthCodeURL returns the IdP authorize URL for the login redirect, binding the
// CSRF state and the replay-defense nonce.
func (p *Provider) AuthCodeURL(state, nonce string) string {
	return p.oauth.AuthCodeURL(state, coreoidc.Nonce(nonce))
}

// Exchange trades the callback's authorization code for tokens, verifies the ID
// token and its nonce, and maps the claims to an Identity. It never grants a
// role beyond default_role without an explicit group mapping.
func (p *Provider) Exchange(ctx context.Context, code, expectedNonce string) (*auth.Identity, error) {
	ctx = coreoidc.ClientContext(ctx, p.httpClient)

	tok, err := p.oauth.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("oidc: token exchange: %w", err)
	}
	rawID, ok := tok.Extra("id_token").(string)
	if !ok || rawID == "" {
		return nil, errors.New("oidc: token response has no id_token")
	}
	idTok, err := p.verifier.Verify(ctx, rawID)
	if err != nil {
		return nil, fmt.Errorf("oidc: verify id_token: %w", err)
	}
	if idTok.Nonce != expectedNonce {
		return nil, errors.New("oidc: id_token nonce mismatch")
	}

	var claims map[string]any
	if err := idTok.Claims(&claims); err != nil {
		return nil, fmt.Errorf("oidc: parse claims: %w", err)
	}
	id := identityFromClaims(claims, p.cfg)
	if id.Username == "" {
		// The username claim was absent; the subject is always present and
		// stable, so use it as the last-resort account identifier.
		id.Username = idTok.Subject
	}
	return id, nil
}

// identityFromClaims maps a verified claims set to an Identity. Factored out of
// Exchange so the claim→role mapping is unit-testable without a live IdP.
func identityFromClaims(claims map[string]any, cfg config.OIDCCfg) *auth.Identity {
	cfg = cfg.WithDefaults()
	username := stringClaim(claims, cfg.UsernameClaim)
	if username == "" {
		username = stringClaim(claims, "sub")
	}
	display := stringClaim(claims, "name")
	if display == "" {
		display = stringClaim(claims, "email")
	}
	return &auth.Identity{
		Username:    username,
		DisplayName: display,
		Role:        mapRole(groupValues(claims, cfg.GroupClaim), cfg),
		Provider:    "oidc",
	}
}

// mapRole resolves the highest role granted by any matching group value; no
// match yields the configured default. This mirrors ldap.mapRole — an
// authenticated user is never implicitly an admin.
func mapRole(groups []string, cfg config.OIDCCfg) auth.Role {
	role := auth.Role(cfg.DefaultRole)
	if !role.Valid() {
		role = auth.RoleUser
	}
	for _, g := range groups {
		mapped, ok := lookupGroup(cfg.GroupRoles, g)
		if !ok {
			continue
		}
		if r := auth.Role(mapped); r.Valid() && r.AtLeast(role) {
			role = r
		}
	}
	return role
}

// lookupGroup finds a group mapping by case-insensitive value comparison.
func lookupGroup(m map[string]string, group string) (string, bool) {
	for k, v := range m {
		if strings.EqualFold(k, group) {
			return v, true
		}
	}
	return "", false
}

// stringClaim reads a string-valued claim, or "" if absent or non-string.
func stringClaim(claims map[string]any, key string) string {
	if s, ok := claims[key].(string); ok {
		return s
	}
	return ""
}

// groupValues normalizes the group claim, which an IdP may encode as a JSON
// array (decoded to []any), a []string, or a single string.
func groupValues(claims map[string]any, key string) []string {
	switch t := claims[key].(type) {
	case []any:
		out := make([]string, 0, len(t))
		for _, e := range t {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case []string:
		return t
	case string:
		if t == "" {
			return nil
		}
		return []string{t}
	default:
		return nil
	}
}
