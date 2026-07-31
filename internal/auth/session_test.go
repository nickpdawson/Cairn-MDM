package auth

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/dzsec/cairn/internal/storage/sqlite"
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
