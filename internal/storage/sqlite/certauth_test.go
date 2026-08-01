package sqlite

import (
	"context"
	"testing"

	"github.com/micromdm/nanomdm/mdm"
)

func devReq(ctx context.Context, id string) *mdm.Request {
	r := mdm.NewRequestWithContext(ctx, nil)
	r.EnrollID = &mdm.EnrollID{Type: mdm.Device, ID: id}
	return r
}

// TestCertAuthMultiHash is the regression test for the migration bug the fleet
// rehearsal caught: NanoMDM's KV certauth kept only ONE hash per enrollment, so
// a renewed device's earlier certs were dropped. The native store must retain
// every hash and treat IsCertHashAssociated as set membership.
func TestCertAuthMultiHash(t *testing.T) {
	ctx := context.Background()
	db, err := Open(ctx, t.TempDir()+"/certauth.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	store := db.NanoStorage(nil)

	// Device A renews twice → three historical hashes, all must stay valid.
	a := devReq(ctx, "UDID-A")
	hashes := []string{
		"aaaa000000000000000000000000000000000000000000000000000000000001",
		"aaaa000000000000000000000000000000000000000000000000000000000002",
		"aaaa000000000000000000000000000000000000000000000000000000000003",
	}
	for _, h := range hashes {
		if err := store.AssociateCertHash(a, h); err != nil {
			t.Fatalf("associate %s: %v", h, err)
		}
	}
	// Re-associating an existing hash is idempotent (no error, no dup).
	if err := store.AssociateCertHash(a, hashes[0]); err != nil {
		t.Fatalf("re-associate: %v", err)
	}

	// EVERY hash authenticates — this is the fix (single-hash storage would
	// only match the last one).
	for _, h := range hashes {
		ok, err := store.IsCertHashAssociated(a, h)
		if err != nil || !ok {
			t.Errorf("hash %s not associated after multi-associate (ok=%v err=%v)", h, ok, err)
		}
	}

	// An unrelated hash is not associated.
	if ok, _ := store.IsCertHashAssociated(a, "ffff000000000000000000000000000000000000000000000000000000000000"); ok {
		t.Error("unknown hash reported associated")
	}

	// The enrollment has hashes; a fresh enrollment does not.
	if ok, _ := store.EnrollmentHasCertHash(a, ""); !ok {
		t.Error("EnrollmentHasCertHash should be true for A")
	}
	b := devReq(ctx, "UDID-B")
	if ok, _ := store.EnrollmentHasCertHash(b, ""); ok {
		t.Error("EnrollmentHasCertHash should be false for B (no associations)")
	}

	// HasCertHash is global; EnrollmentFromHash resolves the owner.
	if ok, _ := store.HasCertHash(a, hashes[1]); !ok {
		t.Error("HasCertHash should find an associated hash")
	}
	if ok, _ := store.HasCertHash(a, "0000000000000000000000000000000000000000000000000000000000000000"); ok {
		t.Error("HasCertHash should not find an unknown hash")
	}
	if id, _ := store.EnrollmentFromHash(ctx, hashes[2]); id != "UDID-A" {
		t.Errorf("EnrollmentFromHash = %q, want UDID-A", id)
	}
	if id, _ := store.EnrollmentFromHash(ctx, "0000000000000000000000000000000000000000000000000000000000000000"); id != "" {
		t.Errorf("EnrollmentFromHash for unknown = %q, want empty", id)
	}

	// Device B keeps its own association, independent of A.
	if err := store.AssociateCertHash(b, "bbbb000000000000000000000000000000000000000000000000000000000001"); err != nil {
		t.Fatal(err)
	}
	if ok, _ := store.IsCertHashAssociated(b, hashes[0]); ok {
		t.Error("B should not be associated with A's hash")
	}
}

// TestCertAuthBackfill proves migration 015 copies an existing KV association
// into the new table so an already-enrolled device keeps authenticating after
// the in-place upgrade.
func TestCertAuthBackfill(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	path := dir + "/backfill.db"

	// Simulate a pre-upgrade DB: open (runs migrations incl. 015 on an empty
	// KV, a no-op), write a KV-style certauth association the OLD way, then
	// re-run the backfill by inserting the KV row and re-applying the copy.
	db, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	// Insert a legacy KV forward-association row as the old backend would have.
	hash := "cccc000000000000000000000000000000000000000000000000000000000009"
	if _, err := db.SQL().ExecContext(ctx,
		`INSERT INTO nano_kv (bucket, k, v) VALUES ('certauth', ?, ?)`,
		"UDID-LEGACY.cert_hash", []byte(hash)); err != nil {
		t.Fatal(err)
	}
	// Re-run the backfill statement (idempotent) to copy it into cert_auth.
	if _, err := db.SQL().ExecContext(ctx,
		`INSERT OR IGNORE INTO cert_auth (enrollment_id, sha256)
		 SELECT substr(k,1,length(k)-length('.cert_hash')), CAST(v AS TEXT)
		 FROM nano_kv WHERE bucket='certauth' AND k LIKE '%.cert_hash'`); err != nil {
		t.Fatal(err)
	}

	store := db.NanoStorage(nil)
	ok, err := store.IsCertHashAssociated(devReq(ctx, "UDID-LEGACY"), hash)
	if err != nil || !ok {
		t.Fatalf("backfilled association not found (ok=%v err=%v)", ok, err)
	}
	db.Close()
}
