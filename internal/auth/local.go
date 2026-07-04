package auth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/alexedwards/argon2id"
)

// ErrInvalidCredentials is returned when a username/password does not match.
var ErrInvalidCredentials = errors.New("invalid credentials")

// LocalStore is the built-in local-account provider, backed by app_users.
type LocalStore struct {
	db *sql.DB
}

// NewLocalStore wraps a database handle.
func NewLocalStore(db *sql.DB) *LocalStore { return &LocalStore{db: db} }

// Name identifies this provider.
func (s *LocalStore) Name() string { return "local" }

// CreateUser adds a local account with the given role. The password is hashed
// with argon2id. Fails if the username already exists.
func (s *LocalStore) CreateUser(ctx context.Context, username, password string, role Role, displayName string) error {
	if username == "" || password == "" {
		return errors.New("auth: username and password are required")
	}
	if !role.Valid() {
		return fmt.Errorf("auth: invalid role %q", role)
	}
	hash, err := argon2id.CreateHash(password, argon2id.DefaultParams)
	if err != nil {
		return fmt.Errorf("auth: hash password: %w", err)
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO app_users (username, password_hash, role, display_name) VALUES (?, ?, ?, ?)`,
		username, hash, string(role), displayName)
	if err != nil {
		return fmt.Errorf("auth: create user: %w", err)
	}
	return nil
}

// SetPassword resets an existing user's password.
func (s *LocalStore) SetPassword(ctx context.Context, username, password string) error {
	hash, err := argon2id.CreateHash(password, argon2id.DefaultParams)
	if err != nil {
		return fmt.Errorf("auth: hash password: %w", err)
	}
	res, err := s.db.ExecContext(ctx,
		`UPDATE app_users SET password_hash = ? WHERE username = ?`, hash, username)
	if err != nil {
		return fmt.Errorf("auth: set password: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("auth: no such user %q", username)
	}
	return nil
}

// Authenticate verifies a username/password and returns the identity.
func (s *LocalStore) Authenticate(ctx context.Context, username, password string) (*Identity, error) {
	var hash, role, display string
	err := s.db.QueryRowContext(ctx,
		`SELECT password_hash, role, display_name FROM app_users WHERE username = ?`, username).
		Scan(&hash, &role, &display)
	if errors.Is(err, sql.ErrNoRows) {
		// Burn comparable work so a missing username is not distinguishable by
		// timing from a wrong password.
		_, _ = argon2id.CreateHash(password, argon2id.DefaultParams)
		return nil, ErrInvalidCredentials
	}
	if err != nil {
		return nil, err
	}
	match, err := argon2id.ComparePasswordAndHash(password, hash)
	if err != nil {
		return nil, fmt.Errorf("auth: compare password: %w", err)
	}
	if !match {
		return nil, ErrInvalidCredentials
	}
	return &Identity{Username: username, DisplayName: display, Role: Role(role), Provider: "local"}, nil
}

// UserRole returns the stored role for a username (used by tests/admin tooling).
func (s *LocalStore) UserRole(ctx context.Context, username string) (Role, error) {
	var role string
	err := s.db.QueryRowContext(ctx, `SELECT role FROM app_users WHERE username = ?`, username).Scan(&role)
	return Role(role), err
}

// CountUsers returns the number of local accounts (used to detect first-run).
func (s *LocalStore) CountUsers(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM app_users`).Scan(&n)
	return n, err
}
