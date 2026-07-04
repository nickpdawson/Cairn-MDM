package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/dzsec/cairn/internal/ca"
	"github.com/dzsec/cairn/internal/config"
	"github.com/dzsec/cairn/internal/storage/sqlite"
)

func runCA(ctx context.Context, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: cairn ca export [-out <file>] [-config <file>]")
	}
	switch args[0] {
	case "export":
		return runCAExport(ctx, args[1:])
	default:
		return fmt.Errorf("unknown ca subcommand %q (want: export)", args[0])
	}
}

// runCAExport writes the CA certificate (PEM) to a file or stdout, so operators
// can distribute the root for out-of-band trust. Applies to generate/import
// modes; in external mode the root comes from your existing CA.
func runCAExport(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("ca export", flag.ExitOnError)
	configPath := fs.String("config", defaultConfigPath, "path to cairn.toml")
	out := fs.String("out", "", "output file (default: stdout)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	if !cfg.CA.Mode.Embedded() {
		return fmt.Errorf("ca.mode=%s does not have a Cairn-managed CA to export; the root lives in your external CA", cfg.CA.Mode)
	}
	if cfg.Storage.Driver != config.DriverSQLite {
		return fmt.Errorf("storage driver %q not yet implemented (Phase 4)", cfg.Storage.Driver)
	}

	db, err := sqlite.Open(ctx, cfg.Storage.Path)
	if err != nil {
		return err
	}
	defer db.Close()

	authority, err := ca.Ensure(ctx, db.SQL(), ca.Options{})
	if err != nil {
		return err
	}
	pemBytes := authority.RootPEM()

	if *out == "" {
		_, err = os.Stdout.Write(pemBytes)
		return err
	}
	if err := os.WriteFile(*out, pemBytes, 0o644); err != nil {
		return err
	}
	fmt.Printf("CA certificate written to %s\n", *out)
	return nil
}
