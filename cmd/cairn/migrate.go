package main

import (
	"context"
	"flag"
	"fmt"

	"github.com/nickpdawson/cairn-mdm/internal/config"
	"github.com/nickpdawson/cairn-mdm/internal/storage/sqlite"
)

func runMigrate(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("migrate", flag.ExitOnError)
	configPath := fs.String("config", defaultConfigPath, "path to cairn.toml")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	if cfg.Storage.Driver != config.DriverSQLite {
		return fmt.Errorf("storage driver %q not yet implemented (Phase 4)", cfg.Storage.Driver)
	}

	// Open runs pending migrations as part of startup.
	db, err := sqlite.Open(ctx, cfg.Storage.Path)
	if err != nil {
		return err
	}
	defer db.Close()

	fmt.Printf("migrations applied; database ready at %s\n", cfg.Storage.Path)
	return nil
}
