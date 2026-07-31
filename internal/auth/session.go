package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
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
	// maxLifetime, when > 0, caps a session's absolute age regardless of
	// activity. Zero disables the cap (idle timeout only).
	maxLifetime time.Duration
}

// NewSessionStore creates a store whose ttl is the session idle timeout: each
// successful Get slides expires_at forward by ttl. Use SetMaxLifetime to also
// bound the absolute lifetime.
func NewSessionStore(db *sql.DB, ttl time.Duration) *SessionStore {
	if ttl <= 0 {
		ttl = 12 * time.Hour
	}
	return &SessionStore{db: db, ttl: ttl}
}

// SetMaxLifetime bounds the absolute lifetime of a session. A session older than
// d (measured from its created_at) is rejected and deleted on the next Get, even
// if it has stayed active. Zero (the default) disables the cap.
func (s *SessionStore) SetMaxLifetime(d time.Duration) {
	if d < 0 {
		d = 0
	}
	s.maxLifetime = d
}

// Create starts a new session for id and returns it (token + CSRF token).
func (s *SessionStore) Create(ctx context.Context, id Identity) (*Session, error) {
	token := randomToken()
	csrf := randomToken()
	expires := time.Now().Add(s.ttl).UTC()

	// Only the hash of the token is persisted; the raw token lives solely in the
	// caller's cookie (MDM-AUTH-001). A stolen database therefore yields no
	// usable session tokens.
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO app_sessions (token, username, role, display_name, provider, csrf_token, expires_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		hashToken(token), id.Username, string(id.Role), id.DisplayName, providerOr(id.Provider), csrf,
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
		username, role, display, provider, csrf, expires, created string
	)
	err := s.db.QueryRowContext(ctx,
		`SELECT username, role, display_name, provider, csrf_token, expires_at, created_at
		 FROM app_sessions WHERE token = ?`, hashToken(token)).
		Scan(&username, &role, &display, &provider, &csrf, &expires, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNoSession
	}
	if err != nil {
		return nil, err
	}
	now := time.Now()
	exp, _ := time.Parse(time.RFC3339, expires)
	if now.After(exp) {
		_ = s.Delete(ctx, token)
		return nil, ErrNoSession
	}

	// Absolute-lifetime cap: reject a session older than maxLifetime even if it
	// has stayed active. Best-effort — it depends on a parseable created_at.
	var lifetimeCap time.Time
	if s.maxLifetime > 0 {
		if c, ok := parseSessionTime(created); ok {
			lifetimeCap = c.Add(s.maxLifetime)
			if now.After(lifetimeCap) {
				_ = s.Delete(ctx, token)
				return nil, ErrNoSession
			}
		}
	}

	// Idle renewal: slide expires_at forward by the idle timeout (ttl), never
	// past the absolute cap. This is the sliding-window idle timeout.
	newExp := now.Add(s.ttl)
	if !lifetimeCap.IsZero() && newExp.After(lifetimeCap) {
		newExp = lifetimeCap
	}
	if newExp.After(exp) {
		newExp = newExp.UTC()
		if _, err := s.db.ExecContext(ctx,
			`UPDATE app_sessions SET expires_at = ? WHERE token = ?`,
			newExp.Format(time.RFC3339), hashToken(token)); err == nil {
			exp = newExp
		}
	}

	return &Session{
		Token:     token,
		Identity:  Identity{Username: username, DisplayName: display, Role: Role(role), Provider: provider},
		CSRF:      csrf,
		ExpiresAt: exp,
	}, nil
}

// parseSessionTime parses a stored timestamp, accepting both RFC3339 (written by
// Create) and SQLite's default datetime('now') form (written by the created_at
// column default). SQLite emits UTC without a zone suffix.
func parseSessionTime(v string) (time.Time, bool) {
	if v == "" {
		return time.Time{}, false
	}
	if t, err := time.Parse(time.RFC3339, v); err == nil {
		return t, true
	}
	if t, err := time.Parse("2006-01-02 15:04:05", v); err == nil {
		return t.UTC(), true
	}
	return time.Time{}, false
}

// Delete removes a session (logout).
func (s *SessionStore) Delete(ctx context.Context, token string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM app_sessions WHERE token = ?`, hashToken(token))
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

// DeleteByUsername removes every session belonging to username and returns the
// number deleted. Used to invalidate active sessions after a password or role
// change so a compromised or stale login can't outlive the credential.
func (s *SessionStore) DeleteByUsername(ctx context.Context, username string) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM app_sessions WHERE username = ?`, username)
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

// hashToken returns the hex-encoded SHA-256 of a raw session token. Only this
// value is stored in app_sessions; the raw token never touches the database.
func hashToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

func providerOr(p string) string {
	if p == "" {
		return "local"
	}
	return p
}
