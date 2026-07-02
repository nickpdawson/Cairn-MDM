package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/dzsec/cairn/internal/config"
	"github.com/dzsec/cairn/internal/mdmcore"
	"github.com/dzsec/cairn/internal/push"
	"github.com/dzsec/cairn/internal/storage/sqlite"
	"github.com/dzsec/cairn/internal/version"
	"github.com/micromdm/nanomdm/mdm"
)

func runEnqueue(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("enqueue", flag.ExitOnError)
	configPath := fs.String("config", defaultConfigPath, "path to cairn.toml")
	id := fs.String("id", "", "target enrollment ID / device UDID")
	reqType := fs.String("type", "DeviceInformation", "command: DeviceInformation | InstallProfile")
	profilePath := fs.String("profile", "", "profile file (required for InstallProfile)")
	noPush := fs.Bool("no-push", false, "enqueue without sending an APNs push")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *id == "" {
		return fmt.Errorf("-id (enrollment ID / UDID) is required")
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	if cfg.Storage.Driver != config.DriverSQLite {
		return fmt.Errorf("storage driver %q not yet implemented (Phase 4)", cfg.Storage.Driver)
	}

	var cmd *mdm.Command
	switch *reqType {
	case "DeviceInformation":
		cmd, err = mdmcore.DeviceInformationCommand()
	case "InstallProfile":
		if *profilePath == "" {
			return fmt.Errorf("-profile is required for InstallProfile")
		}
		var data []byte
		if data, err = os.ReadFile(*profilePath); err == nil {
			cmd, err = mdmcore.InstallProfileCommand(data)
		}
	default:
		return fmt.Errorf("unsupported command type %q", *reqType)
	}
	if err != nil {
		return err
	}

	log := version.NewLogger(cfg.Log.Format, cfg.Log.Level)
	db, err := sqlite.Open(ctx, cfg.Storage.Path)
	if err != nil {
		return err
	}
	defer db.Close()

	store := db.NanoStorage(log)
	var pusher = push.NewPusher(store, mdmcore.NewLogAdapter(log))
	if *noPush {
		pusher = nil
	}

	if err := mdmcore.Enqueue(ctx, store, pusher, []string{*id}, cmd); err != nil {
		return err
	}
	fmt.Printf("enqueued %s (%s) for %s\n", cmd.Command.RequestType, cmd.CommandUUID, *id)
	if !*noPush {
		fmt.Printf("APNs push sent.\n")
	}
	return nil
}
