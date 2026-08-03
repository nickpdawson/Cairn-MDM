package auth

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/nickpdawson/cairn-mdm/internal/storage/sqlite"
)

func testSessionStore(t *testing.T) *SessionStore {
	t.Helper()
	db, err := sqlite.Open(context.Background(), t.TempDir()+"/sessions.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return NewSessionStore(db.SQL(), time.Hour)
}

// TestSessionTokenHashedAtRest proves the raw token round-trips through
// Create/Get/Delete while the database stores only its hash (MDM-AUTH-001).
func TestSessionTokenHashedAtRest(t *testing.T) {
	ctx := context.Background()
	s := testSessionStore(t)

	id := Identity{Username: "nick", Role: RoleAdmin, DisplayName: "Nick", Provider: "local"}
	sess, err := s.Create(ctx, id)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	raw := sess.Token
	if raw == "" {
		t.Fatal("Create returned an empty token")
	}

	// The raw token retrieves the session.
	got, err := s.Get(ctx, raw)
	if err != nil {
		t.Fatalf("get with raw token: %v", err)
	}
	if got.Identity.Username != "nick" || got.Identity.Role != RoleAdmin {
		t.Errorf("identity = %+v", got.Identity)
	}
	if got.Token != raw {
		t.Errorf("Get returned token %q, want raw %q", got.Token, raw)
	}

	// The DB must not hold the raw token.
	var stored string
	if err := s.db.QueryRowContext(ctx,
		`SELECT token FROM app_sessions WHERE username = ?`, "nick").Scan(&stored); err != nil {
		t.Fatalf("read stored token: %v", err)
	}
	if stored == raw {
		t.Fatal("database stores the raw token; expected a hash")
	}
	if stored != hashToken(raw) {
		t.Errorf("stored token = %q, want sha256 hex of raw", stored)
	}

	// Delete accepts the raw token and removes the session.
	if err := s.Delete(ctx, raw); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := s.Get(ctx, raw); !errors.Is(err, ErrNoSession) {
		t.Errorf("after delete, Get err = %v, want ErrNoSession", err)
	}
}

// TestSessionDeleteByUsername removes only the named user's sessions.
func TestSessionDeleteByUsername(t *testing.T) {
	ctx := context.Background()
	s := testSessionStore(t)

	for i := 0; i < 3; i++ {
		if _, err := s.Create(ctx, Identity{Username: "nick", Role: RoleAdmin}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.Create(ctx, Identity{Username: "other", Role: RoleUser}); err != nil {
		t.Fatal(err)
	}

	n, err := s.DeleteByUsername(ctx, "nick")
	if err != nil {
		t.Fatalf("DeleteByUsername: %v", err)
	}
	if n != 3 {
		t.Errorf("deleted %d sessions, want 3", n)
	}

	var remaining int
	if err := s.db.QueryRowContext(ctx,
		`SELECT count(*) FROM app_sessions WHERE username = ?`, "other").Scan(&remaining); err != nil {
		t.Fatal(err)
	}
	if remaining != 1 {
		t.Errorf("other user's sessions = %d, want 1 (untouched)", remaining)
	}
}

// TestSessionIdleRenewal proves Get slides expires_at forward by the idle ttl.
func TestSessionIdleRenewal(t *testing.T) {
	ctx := context.Background()
	s := testSessionStore(t) // ttl = time.Hour
	sess, err := s.Create(ctx, Identity{Username: "nick", Role: RoleAdmin})
	if err != nil {
		t.Fatal(err)
	}

	// Force expires_at close to now, then a Get should push it a full ttl out.
	soon := time.Now().Add(30 * time.Second).UTC()
	if _, err := s.db.ExecContext(ctx,
		`UPDATE app_sessions SET expires_at = ? WHERE token = ?`,
		soon.Format(time.RFC3339), hashToken(sess.Token)); err != nil {
		t.Fatal(err)
	}

	got, err := s.Get(ctx, sess.Token)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.ExpiresAt.Before(time.Now().Add(30 * time.Minute)) {
		t.Errorf("idle renewal did not extend expires_at; got %v", got.ExpiresAt)
	}
}

// TestSessionMaxLifetime rejects a session past its absolute lifetime cap even
// when it is still within the idle window.
func TestSessionMaxLifetime(t *testing.T) {
	ctx := context.Background()
	s := testSessionStore(t)
	s.SetMaxLifetime(time.Hour)

	sess, err := s.Create(ctx, Identity{Username: "nick", Role: RoleAdmin})
	if err != nil {
		t.Fatal(err)
	}

	// Age created_at beyond the cap (SQLite datetime form).
	old := time.Now().Add(-2 * time.Hour).UTC().Format("2006-01-02 15:04:05")
	if _, err := s.db.ExecContext(ctx,
		`UPDATE app_sessions SET created_at = ? WHERE token = ?`,
		old, hashToken(sess.Token)); err != nil {
		t.Fatal(err)
	}

	if _, err := s.Get(ctx, sess.Token); !errors.Is(err, ErrNoSession) {
		t.Errorf("Get past absolute lifetime err = %v, want ErrNoSession", err)
	}
}

// TestSessionUnknownToken confirms a lookup for an unknown token fails cleanly.
func TestSessionUnknownToken(t *testing.T) {
	ctx := context.Background()
	s := testSessionStore(t)
	if _, err := s.Get(ctx, "not-a-real-token"); !errors.Is(err, ErrNoSession) {
		t.Errorf("Get(unknown) err = %v, want ErrNoSession", err)
	}
	if _, err := s.Get(ctx, ""); !errors.Is(err, ErrNoSession) {
		t.Errorf("Get(empty) err = %v, want ErrNoSession", err)
	}
}
