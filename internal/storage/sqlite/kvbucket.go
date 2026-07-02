package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"

	nkv "github.com/micromdm/nanolib/storage/kv"
)

// kvBucket is a single named partition of the nano_kv table exposed as a
// NanoLib KeysPrefixTraversingBucket. Wrapping one of these in kvtxn yields the
// transactional bucket NanoMDM's kv storage layer expects; six of them compose
// into a full storage.AllStorage (see nanostore.go).
//
// It deliberately implements only the plain (non-transactional) operations —
// kvtxn layers best-effort transaction semantics on top, exactly as NanoMDM's
// inmem and diskv backends do.
type kvBucket struct {
	db   *sql.DB
	name string
	log  *slog.Logger
}

// compile-time assertion that kvBucket satisfies the interface kvtxn wraps.
var _ nkv.KeysPrefixTraversingBucket = (*kvBucket)(nil)

func (b *kvBucket) Has(ctx context.Context, key string) (bool, error) {
	var one int
	err := b.db.QueryRowContext(ctx,
		`SELECT 1 FROM nano_kv WHERE bucket = ? AND k = ?`, b.name, key).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

func (b *kvBucket) Get(ctx context.Context, key string) ([]byte, error) {
	var v []byte
	err := b.db.QueryRowContext(ctx,
		`SELECT v FROM nano_kv WHERE bucket = ? AND k = ?`, b.name, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		// NanoLib callers test for this specific sentinel in the error chain.
		return nil, nkv.ErrKeyNotFound
	}
	if err != nil {
		return nil, err
	}
	return v, nil
}

func (b *kvBucket) Set(ctx context.Context, key string, value []byte) error {
	_, err := b.db.ExecContext(ctx,
		`INSERT INTO nano_kv (bucket, k, v) VALUES (?, ?, ?)
		 ON CONFLICT (bucket, k) DO UPDATE SET v = excluded.v`,
		b.name, key, value)
	return err
}

func (b *kvBucket) Delete(ctx context.Context, key string) error {
	// The interface says Delete of a missing key is not an error; DELETE is a
	// no-op on no match, so this is already satisfied.
	_, err := b.db.ExecContext(ctx,
		`DELETE FROM nano_kv WHERE bucket = ? AND k = ?`, b.name, key)
	return err
}

func (b *kvBucket) Keys(ctx context.Context, cancel <-chan struct{}) <-chan string {
	return b.streamKeys(ctx, cancel, "")
}

func (b *kvBucket) KeysPrefix(ctx context.Context, prefix string, cancel <-chan struct{}) <-chan string {
	return b.streamKeys(ctx, cancel, prefix)
}

// streamKeys reads all matching keys into memory first (releasing the database
// connection immediately) and then streams them. Buffering avoids holding a
// query cursor open while the consumer performs writes — which, with a
// single-writer SQLite pool, would otherwise deadlock. At homelab/SMB scale the
// key set is small enough that this is a non-issue.
//
// An empty prefix streams every key in the bucket. Prefix matching is
// byte-exact and case-sensitive (SQLite's default BINARY collation), done via
// substr rather than LIKE/GLOB to avoid pattern-escaping and case-folding.
func (b *kvBucket) streamKeys(ctx context.Context, cancel <-chan struct{}, prefix string) <-chan string {
	ch := make(chan string)

	keys, err := b.collectKeys(ctx, prefix)
	go func() {
		defer close(ch)
		if err != nil {
			// The interface offers no error return on iteration; NanoMDM's own
			// backends have the same limitation. Log so failures aren't silent.
			b.log.Error("kv key iteration failed", "bucket", b.name, "err", err)
			return
		}
		for _, k := range keys {
			select {
			case <-ctx.Done():
				return
			case <-cancel:
				return
			case ch <- k:
			}
		}
	}()
	return ch
}

func (b *kvBucket) collectKeys(ctx context.Context, prefix string) ([]string, error) {
	var (
		rows *sql.Rows
		err  error
	)
	if prefix == "" {
		rows, err = b.db.QueryContext(ctx,
			`SELECT k FROM nano_kv WHERE bucket = ?`, b.name)
	} else {
		rows, err = b.db.QueryContext(ctx,
			`SELECT k FROM nano_kv WHERE bucket = ? AND substr(k, 1, length(?)) = ?`,
			b.name, prefix, prefix)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var keys []string
	for rows.Next() {
		var k string
		if err := rows.Scan(&k); err != nil {
			return nil, err
		}
		keys = append(keys, k)
	}
	return keys, rows.Err()
}
