// Package sqlite is the default persistence backend for Cairn.
//
// Phase 0 establishes the connection lifecycle and schema migration path. Later
// phases implement nanomdm's storage.AllStorage interface and Cairn's own app
// tables against this same *sql.DB. The schema is deliberately modeled on
// nanomdm's MySQL schema so migrating an existing deployment is a table copy.
package sqlite

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"io/fs"
	"sort"
	"strings"

	_ "modernc.org/sqlite" // pure-Go driver; keeps cross-compiles CGO-free
)

//go:embed schema/*.sql
var schemaFS embed.FS

// DB wraps the SQLite handle and Cairn's schema lifecycle.
type DB struct {
	sql *sql.DB
}

// Open opens (creating if necessary) the SQLite database at path, applies
// pragmas suited to a concurrent MDM check-in workload, and runs migrations.
func Open(ctx context.Context, path string) (*DB, error) {
	// WAL + busy_timeout + foreign_keys via the driver's connection DSN pragmas.
	dsn := path + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(ON)&_pragma=synchronous(NORMAL)"
	sqldb, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite %q: %w", path, err)
	}
	// SQLite tolerates one writer at a time; a small pool with WAL readers is
	// the right shape. A single connection avoids "database is locked" churn on
	// writes while WAL still allows concurrent reads.
	sqldb.SetMaxOpenConns(1)

	if err := sqldb.PingContext(ctx); err != nil {
		sqldb.Close()
		return nil, fmt.Errorf("ping sqlite %q: %w", path, err)
	}

	db := &DB{sql: sqldb}
	if err := db.migrate(ctx); err != nil {
		sqldb.Close()
		return nil, err
	}
	return db, nil
}

// SQL exposes the underlying handle for the storage implementations in later
// phases.
func (db *DB) SQL() *sql.DB { return db.sql }

// Ping verifies the database is reachable (used by the readiness probe).
func (db *DB) Ping(ctx context.Context) error { return db.sql.PingContext(ctx) }

// Close closes the database.
func (db *DB) Close() error { return db.sql.Close() }

// migrate applies any embedded schema files not yet recorded in schema_migrations.
// Migrations are plain .sql files named "NNN_description.sql" and applied in
// lexical order, each in its own transaction. This is intentionally a tiny
// runner rather than a dependency; it is enough for an append-only schema and
// keeps the binary self-contained.
func (db *DB) migrate(ctx context.Context) error {
	if _, err := db.sql.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version TEXT PRIMARY KEY,
		applied_at TEXT NOT NULL DEFAULT (datetime('now'))
	)`); err != nil {
		return fmt.Errorf("create schema_migrations: %w", err)
	}

	applied := map[string]bool{}
	rows, err := db.sql.QueryContext(ctx, `SELECT version FROM schema_migrations`)
	if err != nil {
		return fmt.Errorf("read schema_migrations: %w", err)
	}
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			rows.Close()
			return err
		}
		applied[v] = true
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()

	entries, err := fs.ReadDir(schemaFS, "schema")
	if err != nil {
		return fmt.Errorf("read embedded schema: %w", err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".sql") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)

	for _, name := range names {
		version := strings.TrimSuffix(name, ".sql")
		if applied[version] {
			continue
		}
		body, err := schemaFS.ReadFile("schema/" + name)
		if err != nil {
			return fmt.Errorf("read migration %s: %w", name, err)
		}
		tx, err := db.sql.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, string(body)); err != nil {
			tx.Rollback()
			return fmt.Errorf("apply migration %s: %w", name, err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations (version) VALUES (?)`, version); err != nil {
			tx.Rollback()
			return fmt.Errorf("record migration %s: %w", name, err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("commit migration %s: %w", name, err)
		}
	}
	return nil
}
