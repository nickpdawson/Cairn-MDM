package sqlite

import (
	"io"
	"log/slog"

	"github.com/micromdm/nanolib/storage/kv/kvtxn"
	"github.com/micromdm/nanomdm/storage"
	nanokv "github.com/micromdm/nanomdm/storage/kv"
)

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
	return nanokv.New(
		kvtxn.New(bucket("users")),
		kvtxn.New(bucket("certauth")),
		kvtxn.New(bucket("queue")),
		kvtxn.New(bucket("pushcert")),
		kvtxn.New(bucket("devices")),
		kvtxn.New(bucket("enrollments")),
	)
}
