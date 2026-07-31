package main

import (
	"context"
	"flag"
	"fmt"

	"github.com/dzsec/cairn/internal/config"
	"github.com/dzsec/cairn/internal/importer"
	"github.com/dzsec/cairn/internal/storage/sqlite"
	"github.com/dzsec/cairn/internal/version"
)

// runImport migrates a v1 NanoMDM MySQL deployment into Cairn's storage.
func runImport(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("import", flag.ExitOnError)
	configPath := fs.String("config", defaultConfigPath, "path to cairn.toml")
	fromMySQL := fs.String("from-mysql", "", "source DSN, e.g. nanomdm:pass@tcp(host:3306)/nanomdm (required)")
	dryRun := fs.Bool("dry-run", false, "read + validate the source, write nothing")
	allowPending := fs.Bool("allow-pending", false, "proceed even if the source queue is not drained (queued commands are NOT migrated)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *fromMySQL == "" {
		return fmt.Errorf("-from-mysql is required")
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	if cfg.Storage.Driver != config.DriverSQLite {
		return fmt.Errorf("storage driver %q not yet implemented (Phase 4)", cfg.Storage.Driver)
	}

	src, err := importer.OpenMySQL(*fromMySQL)
	if err != nil {
		return err
	}
	defer src.Close()
	if err := src.Ping(ctx); err != nil {
		return fmt.Errorf("source unreachable: %w", err)
	}

	db, err := sqlite.Open(ctx, cfg.Storage.Path)
	if err != nil {
		return err
	}
	defer db.Close()

	log := version.NewLogger(cfg.Log.Format, cfg.Log.Level)
	im := importer.New(db.NanoStorage(log), db, log)
	rep, err := im.Run(ctx, src, importer.Options{DryRun: *dryRun, AllowPending: *allowPending})
	if err != nil {
		return err
	}

	mode := "imported"
	if rep.DryRun {
		mode = "validated (dry run)"
	}
	fmt.Printf("Migration %s:\n", mode)
	fmt.Printf("  devices:            %d\n", rep.Devices)
	fmt.Printf("  users:              %d\n", rep.Users)
	fmt.Printf("  enrollments:        %d (%d disabled)\n", rep.Enrollments, rep.Disabled)
	fmt.Printf("  cert associations:  %d\n", rep.Associations)
	fmt.Printf("  push certificates:  %d\n", rep.PushCerts)
	for _, s := range rep.Skipped {
		fmt.Printf("  SKIPPED: %s\n", s)
	}
	if !rep.DryRun {
		if rep.Ok() {
			fmt.Printf("\nVerification PASSED: every enabled enrollment is pushable and every\n")
			fmt.Printf("certificate association is in place. Safe to point mdm DNS at Cairn.\n")
		} else {
			fmt.Printf("\nVerification FAILED — DO NOT CUT OVER:\n")
			for _, m := range rep.Mismatches {
				fmt.Printf("  MISMATCH: %s\n", m)
			}
			return fmt.Errorf("import verification failed with %d mismatches", len(rep.Mismatches))
		}
	}
	return nil
}
