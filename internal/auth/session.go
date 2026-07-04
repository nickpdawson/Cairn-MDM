package auth

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"time"
)

// ErrNoSession is returned when a token is unknown or expired.
var ErrNoSession = errors.New("no valid session")

// Session is an active admin session.
type Session struct {
	Token     string
	Identity  Identity
	CSRF      string
	ExpiresAt time.Time
}

// SessionStore manages server-side sessions in app_sessions.
type SessionStore struct {
	db  *sql.DB
	ttl time.Duration
}

// NewSessionStore creates a store with the given session lifetime.
func NewSessionStore(db *sql.DB, ttl time.Duration) *SessionStore {
	if ttl <= 0 {
		ttl = 12 * time.Hour
	}
	return &SessionStore{db: db, ttl: ttl}
}

// Create starts a new session for id and returns it (token + CSRF token).
func (s *SessionStore) Create(ctx context.Context, id Identity) (*Session, error) {
	token := randomToken()
	csrf := randomToken()
	expires := time.Now().Add(s.ttl).UTC()

	_, err := s.db.ExecContext(ctx,
		`INSERT INTO app_sessions (token, username, role, display_name, provider, csrf_token, expires_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		token, id.Username, string(id.Role), id.DisplayName, providerOr(id.Provider), csrf,
		expires.Format(time.RFC3339))
	if err != nil {
		return nil, err
	}
	return &Session{Token: token, Identity: id, CSRF: csrf, ExpiresAt: expires}, nil
}

// Get returns the session for token, or ErrNoSession if unknown/expired.
func (s *SessionStore) Get(ctx context.Context, token string) (*Session, error) {
	if token == "" {
		return nil, ErrNoSession
	}
	var (
		username, role, display, provider, csrf, expires string
	)
	err := s.db.QueryRowContext(ctx,
		`SELECT username, role, display_name, provider, csrf_token, expires_at
		 FROM app_sessions WHERE token = ?`, token).
		Scan(&username, &role, &display, &provider, &csrf, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNoSession
	}
	if err != nil {
		return nil, err
	}
	exp, _ := time.Parse(time.RFC3339, expires)
	if time.Now().After(exp) {
		_ = s.Delete(ctx, token)
		return nil, ErrNoSession
	}
	return &Session{
		Token:     token,
		Identity:  Identity{Username: username, DisplayName: display, Role: Role(role), Provider: provider},
		CSRF:      csrf,
		ExpiresAt: exp,
	}, nil
}

// Delete removes a session (logout).
func (s *SessionStore) Delete(ctx context.Context, token string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM app_sessions WHERE token = ?`, token)
	return err
}

// DeleteExpired purges expired sessions (called by the cleanup job).
func (s *SessionStore) DeleteExpired(ctx context.Context) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM app_sessions WHERE expires_at < ?`, time.Now().UTC().Format(time.RFC3339))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func randomToken() string {
	var b [32]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func providerOr(p string) string {
	if p == "" {
		return "local"
	}
	return p
}
