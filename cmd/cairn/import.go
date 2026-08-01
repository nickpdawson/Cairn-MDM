package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/dzsec/cairn/internal/config"
	"github.com/dzsec/cairn/internal/importer"
	"github.com/dzsec/cairn/internal/storage/sqlite"
	"github.com/dzsec/cairn/internal/version"
)

// runImport migrates a v1 NanoMDM MySQL deployment into Cairn's storage.
func runImport(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("import", flag.ExitOnError)
	configPath := fs.String("config", defaultConfigPath, "path to cairn.toml")
	fromMySQL := fs.String("from-mysql", "", "source DSN, e.g. nanomdm:pass@tcp(host:3306)/nanomdm (visible in process listings — prefer -from-mysql-file)")
	fromMySQLFile := fs.String("from-mysql-file", "", "path to a mode-0600 file containing the source DSN (preferred over -from-mysql)")
	dryRun := fs.Bool("dry-run", false, "read + validate the source, write nothing (does not open the destination)")
	allowPending := fs.Bool("allow-pending", false, "proceed even if the source queue is not drained (queued commands are NOT migrated)")
	allowExceptions := fs.String("allow-exceptions", "", "path to a file listing enrollment IDs the operator explicitly accepts skipping (one per line)")
	force := fs.Bool("force", false, "allow importing into a destination that already contains devices (default: refuse, to protect a live DB)")
	evidencePath := fs.String("evidence", "", "path to write the JSON evidence bundle (default: alongside the destination DB)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	dsn, err := resolveDSN(*fromMySQL, *fromMySQLFile)
	if err != nil {
		return err
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	if cfg.Storage.Driver != config.DriverSQLite {
		return fmt.Errorf("storage driver %q not yet implemented (Phase 4)", cfg.Storage.Driver)
	}

	// Exception list: hash the file for the evidence record and build the
	// accepted-skip set. Only IDs named here may be skipped without failing.
	allowed := map[string]bool{}
	exceptionSHA := ""
	if *allowExceptions != "" {
		allowed, exceptionSHA, err = loadExceptions(*allowExceptions)
		if err != nil {
			return err
		}
	}

	src, err := importer.OpenMySQL(dsn)
	if err != nil {
		return err
	}
	defer src.Close()
	if err := src.Ping(ctx); err != nil {
		return fmt.Errorf("source unreachable: %w", err)
	}

	opts := importer.Options{
		DryRun:              *dryRun,
		AllowPending:        *allowPending,
		AllowedExceptions:   allowed,
		ExceptionFileSHA256: exceptionSHA,
	}
	log := version.NewLogger(cfg.Log.Format, cfg.Log.Level)

	// Dry-run is truly non-mutating: it never opens (and therefore never
	// migrates) the destination DB — opening it would run schema migrations,
	// which are writes. Validate the source only, with a nil destination.
	if *dryRun {
		im := importer.New(nil, nil, log)
		rep, err := im.Run(ctx, src, opts)
		if err != nil {
			return err
		}
		fmt.Print(rep.Summary())
		return nil
	}

	db, err := sqlite.Open(ctx, cfg.Storage.Path)
	if err != nil {
		return err
	}
	defer db.Close()

	// Don't clobber a live DB: the cutover imports into a fresh/staging DB. If
	// the destination already has devices, refuse unless -force is given.
	if total, _, err := db.DeviceCounts(ctx); err != nil {
		return fmt.Errorf("precheck destination device count: %w", err)
	} else if total > 0 && !*force {
		return fmt.Errorf("destination %s already contains %d device(s); import into a fresh/staging DB, or pass -force to import anyway", cfg.Storage.Path, total)
	}

	started := time.Now()
	im := importer.New(db.NanoStorage(log), db, log)
	rep, err := im.Run(ctx, src, opts)
	if err != nil {
		return err
	}
	finished := time.Now()

	// Evidence bundle: an auditable record of what the run did.
	evPath := *evidencePath
	if evPath == "" {
		evPath = cfg.Storage.Path + ".import-evidence.json"
	}
	if err := importer.WriteEvidence(evPath, importer.BuildEvidence(rep, started, finished)); err != nil {
		return err
	}

	fmt.Print(rep.Summary())
	fmt.Printf("\nEvidence written to %s\n", evPath)
	if !rep.Ok() {
		return fmt.Errorf("import verification failed (%d mismatches, %d disable failures, %d unaccepted skips)",
			len(rep.Mismatches), len(rep.DisableFailures), unacceptedSkips(rep))
	}
	return nil
}

// resolveDSN picks the source DSN, preferring the file form (which keeps the
// credential out of argv/process listings). Exactly one source must be given.
func resolveDSN(inline, file string) (string, error) {
	switch {
	case file != "" && inline != "":
		// File wins; warn that the inline form is exposed.
		fmt.Fprintln(os.Stderr, "warning: both -from-mysql and -from-mysql-file given; using -from-mysql-file (the -from-mysql value is visible in process listings/shell history)")
		fallthrough
	case file != "":
		return readDSNFile(file)
	case inline != "":
		fmt.Fprintln(os.Stderr, "warning: -from-mysql puts the DSN (with password) in process listings and shell history; prefer -from-mysql-file with a mode-0600 file")
		return inline, nil
	default:
		return "", fmt.Errorf("one of -from-mysql or -from-mysql-file is required")
	}
}

// readDSNFile reads a DSN from a file that must not be group/other-readable.
func readDSNFile(path string) (string, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("read DSN file: %w", err)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return "", fmt.Errorf("DSN file %s is group/other-accessible (mode %#o); chmod 600 it", path, fi.Mode().Perm())
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read DSN file: %w", err)
	}
	dsn := strings.TrimSpace(string(b))
	if dsn == "" {
		return "", fmt.Errorf("DSN file %s is empty", path)
	}
	return dsn, nil
}

// loadExceptions reads an exception file (one enrollment ID per line, blank
// lines and "#" comments ignored), returning the accepted-ID set and the
// file's sha256 (hex) for the evidence record.
func loadExceptions(path string) (map[string]bool, string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, "", fmt.Errorf("read exception file: %w", err)
	}
	sum := sha256.Sum256(b)
	set := map[string]bool{}
	sc := bufio.NewScanner(strings.NewReader(string(b)))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		set[line] = true
	}
	if err := sc.Err(); err != nil {
		return nil, "", fmt.Errorf("scan exception file: %w", err)
	}
	return set, hex.EncodeToString(sum[:]), nil
}

// unacceptedSkips counts skipped rows the operator did not accept.
func unacceptedSkips(rep *importer.Report) int {
	n := 0
	for _, s := range rep.Skipped {
		if !s.Accepted {
			n++
		}
	}
	return n
}
