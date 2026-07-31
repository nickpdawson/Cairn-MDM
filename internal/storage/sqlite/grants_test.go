package sqlite

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func newGrantDB(t *testing.T) *DB {
	t.Helper()
	db, err := Open(context.Background(), t.TempDir()+"/grants.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func future() string { return time.Now().Add(time.Hour).UTC().Format("2006-01-02 15:04:05") }
func past() string   { return time.Now().Add(-time.Hour).UTC().Format("2006-01-02 15:04:05") }

func TestGrantRedeemLifecycle(t *testing.T) {
	ctx := context.Background()
	db := newGrantDB(t)

	raw, hash := NewGrantToken()
	id, err := db.CreateGrant(ctx, Grant{
		Label: "Nick's Mac", Platform: "macos", Owner: "nick@dzsec.net",
		CreatedBy: "admin", ExpiresAt: future(), MaxUses: 1,
	}, hash)
	if err != nil {
		t.Fatal(err)
	}

	// First redeem wins and returns the owner.
	red, err := db.RedeemGrant(ctx, raw)
	if err != nil {
		t.Fatalf("redeem: %v", err)
	}
	if red.Owner != "nick@dzsec.net" || red.Platform != "macos" {
		t.Errorf("redemption = %+v", red)
	}

	// Second redeem of a max_uses=1 grant fails (exhausted).
	if _, err := db.RedeemGrant(ctx, raw); !errors.Is(err, ErrGrantInvalid) {
		t.Errorf("second redeem err = %v, want ErrGrantInvalid", err)
	}

	g, _ := db.GetGrant(ctx, id)
	if g.Status() != "used" || g.UseCount != 1 {
		t.Errorf("status=%q use_count=%d, want used/1", g.Status(), g.UseCount)
	}

	// Unknown token is indistinctly invalid.
	if _, err := db.RedeemGrant(ctx, "deadbeef"); !errors.Is(err, ErrGrantInvalid) {
		t.Errorf("unknown token err = %v", err)
	}
}

func TestGrantExpiredAndRevoked(t *testing.T) {
	ctx := context.Background()
	db := newGrantDB(t)

	// Expired grant cannot be redeemed.
	rawExp, hashExp := NewGrantToken()
	if _, err := db.CreateGrant(ctx, Grant{ExpiresAt: past(), MaxUses: 1, CreatedBy: "a"}, hashExp); err != nil {
		t.Fatal(err)
	}
	if _, err := db.RedeemGrant(ctx, rawExp); !errors.Is(err, ErrGrantInvalid) {
		t.Errorf("expired redeem err = %v", err)
	}

	// Revoked grant cannot be redeemed.
	rawRev, hashRev := NewGrantToken()
	id, _ := db.CreateGrant(ctx, Grant{ExpiresAt: future(), MaxUses: 5, CreatedBy: "a"}, hashRev)
	if err := db.RevokeGrant(ctx, id); err != nil {
		t.Fatal(err)
	}
	if _, err := db.RedeemGrant(ctx, rawRev); !errors.Is(err, ErrGrantInvalid) {
		t.Errorf("revoked redeem err = %v", err)
	}
	g, _ := db.GetGrant(ctx, id)
	if g.Status() != "revoked" {
		t.Errorf("status = %q, want revoked", g.Status())
	}
}

func TestGrantConcurrentRedeemNoDoubleSpend(t *testing.T) {
	ctx := context.Background()
	db := newGrantDB(t)

	raw, hash := NewGrantToken()
	if _, err := db.CreateGrant(ctx, Grant{ExpiresAt: future(), MaxUses: 1, CreatedBy: "a"}, hash); err != nil {
		t.Fatal(err)
	}

	const n = 12
	var wg sync.WaitGroup
	var mu sync.Mutex
	wins := 0
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := db.RedeemGrant(ctx, raw); err == nil {
				mu.Lock()
				wins++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if wins != 1 {
		t.Fatalf("concurrent redemptions succeeded %d times, want exactly 1", wins)
	}
}
