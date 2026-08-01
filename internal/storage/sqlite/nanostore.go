package sqlite

import (
	"context"
	"io"
	"log/slog"

	"github.com/micromdm/nanolib/storage/kv/kvtxn"
	"github.com/micromdm/nanomdm/mdm"
	"github.com/micromdm/nanomdm/storage"
	nanokv "github.com/micromdm/nanomdm/storage/kv"
)

// nanoStore is the KV-backed AllStorage with the certauth methods overridden by
// a native multi-hash SQLite implementation (see certauth.go). NanoMDM's KV
// certauth keeps only one hash per enrollment, which drops a renewed device's
// earlier certs on migration; the override keeps them all.
type nanoStore struct {
	*nanokv.KV
	ca *certAuthStore
}

func (s *nanoStore) HasCertHash(r *mdm.Request, hash string) (bool, error) {
	return s.ca.HasCertHash(r, hash)
}
func (s *nanoStore) EnrollmentHasCertHash(r *mdm.Request, hash string) (bool, error) {
	return s.ca.EnrollmentHasCertHash(r, hash)
}
func (s *nanoStore) IsCertHashAssociated(r *mdm.Request, hash string) (bool, error) {
	return s.ca.IsCertHashAssociated(r, hash)
}
func (s *nanoStore) AssociateCertHash(r *mdm.Request, hash string) error {
	return s.ca.AssociateCertHash(r, hash)
}
func (s *nanoStore) EnrollmentFromHash(ctx context.Context, hash string) (string, error) {
	return s.ca.EnrollmentFromHash(ctx, hash)
}

// NanoStorage returns a NanoMDM storage.AllStorage backed by this SQLite
// database. It composes the six NanoMDM buckets over the shared nano_kv table,
// each wrapped in kvtxn for the (best-effort) transaction semantics NanoMDM's
// kv layer expects.
//
// The transaction wrapper does not provide crash-atomicity across multiple keys
// — the same caveat NanoMDM's own inmem and diskv backends carry. With a
// single-writer SQLite pool the operations serialize, which is sufficient at
// the scale Cairn targets. A future backend can implement native SQLite
// transactions if a larger deployment needs stronger guarantees.
func (db *DB) NanoStorage(log *slog.Logger) storage.AllStorage {
	if log == nil {
		log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	bucket := func(name string) *kvBucket {
		return &kvBucket{db: db.sql, name: name, log: log}
	}
	kv := nanokv.New(
		kvtxn.New(bucket("users")),
		kvtxn.New(bucket("certauth")), // retained for backfill only; certauth
		kvtxn.New(bucket("queue")),    // methods are overridden below
		kvtxn.New(bucket("pushcert")),
		kvtxn.New(bucket("devices")),
		kvtxn.New(bucket("enrollments")),
	)
	return &nanoStore{KV: kv, ca: &certAuthStore{db: db.sql}}
}

// ensure the wrapper still satisfies AllStorage.
var _ storage.AllStorage = (*nanoStore)(nil)
