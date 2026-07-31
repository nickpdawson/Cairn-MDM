package main

import (
	"log/slog"

	"github.com/dzsec/cairn/internal/auth"
	ldapauth "github.com/dzsec/cairn/internal/auth/ldap"
	"github.com/dzsec/cairn/internal/config"
	"github.com/dzsec/cairn/internal/storage/sqlite"
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
