// Package auth handles authentication and role-based authorization.
//
// Roles are always explicit: a Role is assigned when an account is created (or
// mapped from an external provider's groups), never inferred from the mere fact
// of being authenticated. This is the structural fix for v1, where any
// Kerberos-authenticated user was treated as an admin.
package auth

// Role is a coarse authorization level. Ordering: admin > operator > user.
type Role string

const (
	// RoleAdmin can do everything, including settings and user management.
	RoleAdmin Role = "admin"
	// RoleOperator can manage devices and profiles but not settings/users.
	RoleOperator Role = "operator"
	// RoleUser can enroll and view their own devices (self-service).
	RoleUser Role = "user"
)

// Valid reports whether r is a known role.
func (r Role) Valid() bool {
	switch r {
	case RoleAdmin, RoleOperator, RoleUser:
		return true
	}
	return false
}

// AtLeast reports whether r is at least as privileged as min.
func (r Role) AtLeast(min Role) bool {
	return rank(r) >= rank(min)
}

func rank(r Role) int {
	switch r {
	case RoleAdmin:
		return 3
	case RoleOperator:
		return 2
	case RoleUser:
		return 1
	default:
		return 0
	}
}

// Identity is an authenticated principal.
type Identity struct {
	Username    string
	DisplayName string
	Role        Role
	Provider    string // "local", "oidc", "ldap", "kerberos"
}
