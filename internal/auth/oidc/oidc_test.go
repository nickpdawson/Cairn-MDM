package oidc

import (
	"testing"

	"github.com/dzsec/cairn-mdm/internal/auth"
	"github.com/dzsec/cairn-mdm/internal/config"
)

func mapCfg() config.OIDCCfg {
	return config.OIDCCfg{
		GroupClaim: "groups",
		GroupRoles: map[string]string{
			// Deliberately different case than the claim values below.
			"cairn-admins":   "admin",
			"CAIRN-HELPDESK": "operator",
		},
		UsernameClaim: "preferred_username",
	}
}

func TestIdentityFromClaimsMapsGroupsExplicitly(t *testing.T) {
	cfg := mapCfg()

	// Admin group (case differs from mapping) → admin.
	id := identityFromClaims(map[string]any{
		"preferred_username": "nick",
		"name":               "Nick D",
		"groups":             []any{"Cairn-Admins", "everyone"},
	}, cfg)
	if id.Role != auth.RoleAdmin {
		t.Errorf("role = %q, want admin", id.Role)
	}
	if id.Username != "nick" || id.DisplayName != "Nick D" || id.Provider != "oidc" {
		t.Errorf("identity = %+v", id)
	}

	// Unmapped groups only → default role "user", NEVER admin.
	id = identityFromClaims(map[string]any{
		"preferred_username": "bob",
		"groups":             []any{"everyone", "staff"},
	}, cfg)
	if id.Role != auth.RoleUser {
		t.Errorf("unmapped groups got role %q, want user", id.Role)
	}

	// Multiple mapped groups → highest wins.
	id = identityFromClaims(map[string]any{
		"preferred_username": "sam",
		"groups":             []any{"cairn-helpdesk", "cairn-admins"},
	}, cfg)
	if id.Role != auth.RoleAdmin {
		t.Errorf("got %q, want admin (highest of mapped)", id.Role)
	}
}

func TestIdentityFromClaimsDefaultRoleConfigurable(t *testing.T) {
	cfg := mapCfg()
	cfg.DefaultRole = "operator"
	id := identityFromClaims(map[string]any{
		"preferred_username": "ops",
		"groups":             []any{"nothing-mapped"},
	}, cfg)
	if id.Role != auth.RoleOperator {
		t.Errorf("role = %q, want operator (configured default)", id.Role)
	}
}

func TestIdentityFromClaimsUsernameFallbackAndDisplay(t *testing.T) {
	cfg := mapCfg()

	// No preferred_username → username falls back to sub; no name → display
	// falls back to email.
	id := identityFromClaims(map[string]any{
		"sub":   "abc-123",
		"email": "someone@example.org",
	}, cfg)
	if id.Username != "abc-123" {
		t.Errorf("username = %q, want sub fallback abc-123", id.Username)
	}
	if id.DisplayName != "someone@example.org" {
		t.Errorf("display = %q, want email fallback", id.DisplayName)
	}
	// No mapped group at all → default "user" via WithDefaults, never admin.
	if id.Role != auth.RoleUser {
		t.Errorf("role = %q, want user", id.Role)
	}
}

func TestGroupValuesShapes(t *testing.T) {
	cfg := mapCfg()

	// Single-string group claim.
	id := identityFromClaims(map[string]any{
		"preferred_username": "single",
		"groups":             "cairn-admins",
	}, cfg)
	if id.Role != auth.RoleAdmin {
		t.Errorf("single-string group: role = %q, want admin", id.Role)
	}

	// []string group claim.
	id = identityFromClaims(map[string]any{
		"preferred_username": "slice",
		"groups":             []string{"cairn-admins"},
	}, cfg)
	if id.Role != auth.RoleAdmin {
		t.Errorf("[]string group: role = %q, want admin", id.Role)
	}

	// Missing group claim → default role.
	id = identityFromClaims(map[string]any{"preferred_username": "nogroups"}, cfg)
	if id.Role != auth.RoleUser {
		t.Errorf("missing group claim: role = %q, want user", id.Role)
	}
}

func TestCustomGroupAndUsernameClaims(t *testing.T) {
	cfg := config.OIDCCfg{
		GroupClaim:    "roles",
		UsernameClaim: "email",
		GroupRoles:    map[string]string{"mdm-admin": "admin"},
	}
	id := identityFromClaims(map[string]any{
		"email": "admin@example.org",
		"roles": []any{"mdm-admin"},
	}, cfg)
	if id.Username != "admin@example.org" {
		t.Errorf("username = %q, want email claim", id.Username)
	}
	if id.Role != auth.RoleAdmin {
		t.Errorf("role = %q, want admin from custom roles claim", id.Role)
	}
}
