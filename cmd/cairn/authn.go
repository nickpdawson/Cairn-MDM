package main

import (
	"context"
	"log/slog"
	"strings"

	"github.com/nickpdawson/cairn-mdm/internal/auth"
	ldapauth "github.com/nickpdawson/cairn-mdm/internal/auth/ldap"
	oidcauth "github.com/nickpdawson/cairn-mdm/internal/auth/oidc"
	"github.com/nickpdawson/cairn-mdm/internal/config"
	"github.com/nickpdawson/cairn-mdm/internal/storage/sqlite"
)

// buildAuthenticator assembles the login chain: external providers first,
// with the local store always last as the break-glass path.
func buildAuthenticator(cfg config.Config, db *sqlite.DB, log *slog.Logger) (auth.Authenticator, error) {
	local := auth.NewLocalStore(db.SQL())
	if !cfg.Auth.LDAP.Enabled {
		return local, nil
	}
	provider, err := ldapauth.New(cfg.Auth.LDAP, log)
	if err != nil {
		return nil, err
	}
	log.Info("ldap auth enabled", "servers", cfg.Auth.LDAP.Servers,
		"mapped_groups", len(cfg.Auth.LDAP.GroupRoles), "default_role", cfg.Auth.LDAP.DefaultRole)
	return auth.Chain{provider, local}, nil
}

// buildOIDC constructs the OIDC single-sign-on provider when enabled. OIDC is a
// redirect flow, not part of the username/password Authenticator chain, so it is
// wired into the web console separately (via App.SetOIDC). Returns (nil, nil)
// when OIDC is disabled.
func buildOIDC(ctx context.Context, cfg config.Config, log *slog.Logger) (*oidcauth.Provider, error) {
	if !cfg.Auth.OIDC.Enabled {
		return nil, nil
	}
	redirectURL := strings.TrimRight(cfg.Server.PublicURL, "/") + "/auth/oidc/callback"
	p, err := oidcauth.New(ctx, cfg.Auth.OIDC, redirectURL)
	if err != nil {
		return nil, err
	}
	log.Info("oidc auth enabled", "issuer", cfg.Auth.OIDC.IssuerURL,
		"mapped_groups", len(cfg.Auth.OIDC.GroupRoles), "default_role", cfg.Auth.OIDC.DefaultRole)
	return p, nil
}
