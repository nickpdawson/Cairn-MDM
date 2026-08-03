package main

import (
	"context"
	"database/sql"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/dzsec/cairn-mdm/internal/config"

	_ "modernc.org/sqlite"
)

// runBackup makes a consistent single-file copy of the SQLite database using
// SQLite's online `VACUUM INTO`, which is safe to run while the server is live
// (no torn WAL state) and emits a compact backup with no -wal/-shm sidecars.
// See docs/backup-restore.md for the full procedure (config + certs are backed
// up separately by that runbook).
func runBackup(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("backup", flag.ExitOnError)
	configPath := fs.String("config", defaultConfigPath, "path to cairn.toml")
	out := fs.String("out", "", "destination backup file (required)")
	verify := fs.Bool("verify", true, "run PRAGMA integrity_check on the backup")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *out == "" {
		return fmt.Errorf("-out <file> is required")
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	if cfg.Storage.Driver != config.DriverSQLite {
		return fmt.Errorf("backup supports the sqlite driver only (driver is %q)", cfg.Storage.Driver)
	}
	if _, err := os.Stat(*out); err == nil {
		return fmt.Errorf("destination %s already exists; choose a new path", *out)
	}
	if dir := filepath.Dir(*out); dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
	}

	// Open the live DB read-only-ish (we only issue VACUUM INTO, which reads the
	// source). A short busy timeout tolerates a concurrent writer.
	src, err := sql.Open("sqlite", cfg.Storage.Path+"?_pragma=busy_timeout(10000)")
	if err != nil {
		return fmt.Errorf("open source db: %w", err)
	}
	defer src.Close()
	if err := src.PingContext(ctx); err != nil {
		return fmt.Errorf("source db unreachable: %w", err)
	}

	// VACUUM INTO writes a fully consistent snapshot to the destination path.
	if _, err := src.ExecContext(ctx, `VACUUM INTO ?`, *out); err != nil {
		return fmt.Errorf("vacuum into %s: %w", *out, err)
	}
	if err := os.Chmod(*out, 0o600); err != nil {
		return fmt.Errorf("tighten backup perms: %w", err)
	}

	fi, _ := os.Stat(*out)
	fmt.Printf("backup written: %s", *out)
	if fi != nil {
		fmt.Printf(" (%d bytes)", fi.Size())
	}
	fmt.Println()

	if *verify {
		bak, err := sql.Open("sqlite", *out)
		if err != nil {
			return fmt.Errorf("reopen backup: %w", err)
		}
		defer bak.Close()
		var result string
		if err := bak.QueryRowContext(ctx, `PRAGMA integrity_check`).Scan(&result); err != nil {
			return fmt.Errorf("integrity check: %w", err)
		}
		if result != "ok" {
			return fmt.Errorf("backup integrity check FAILED: %s", result)
		}
		fmt.Println("integrity check: ok")
	}

	fmt.Println("\nAlso back up config + certs (see docs/backup-restore.md):")
	fmt.Printf("  %s + /etc/cairn/sign.{crt,key} + external CA chain/challenge\n", *configPath)
	return nil
}
