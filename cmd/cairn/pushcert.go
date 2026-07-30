package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/dzsec/cairn/internal/config"
	"github.com/dzsec/cairn/internal/push"
	"github.com/dzsec/cairn/internal/storage/sqlite"
)

func runPushcert(ctx context.Context, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: cairn pushcert <request|decrypt|import> [flags]")
	}
	switch args[0] {
	case "request":
		return runPushcertRequest(ctx, args[1:])
	case "decrypt":
		return runPushcertDecrypt(ctx, args[1:])
	case "import":
		return runPushcertImport(ctx, args[1:])
	default:
		return fmt.Errorf("unknown pushcert subcommand %q (want: request, decrypt, import)", args[0])
	}
}

func runPushcertImport(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("pushcert import", flag.ExitOnError)
	configPath := fs.String("config", defaultConfigPath, "path to cairn.toml")
	certFile := fs.String("cert", "", "APNs push certificate (PEM)")
	keyFile := fs.String("key", "", "APNs push private key (PEM)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *certFile == "" || *keyFile == "" {
		return fmt.Errorf("-cert and -key are required")
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	if cfg.Storage.Driver != config.DriverSQLite {
		return fmt.Errorf("storage driver %q not yet implemented (Phase 4)", cfg.Storage.Driver)
	}

	pemCert, err := os.ReadFile(*certFile)
	if err != nil {
		return fmt.Errorf("read cert: %w", err)
	}
	pemKey, err := os.ReadFile(*keyFile)
	if err != nil {
		return fmt.Errorf("read key: %w", err)
	}

	db, err := sqlite.Open(ctx, cfg.Storage.Path)
	if err != nil {
		return err
	}
	defer db.Close()

	store := db.NanoStorage(nil)
	topic, notAfter, err := push.LoadCert(ctx, store, db, pemCert, pemKey)
	if err != nil {
		return err
	}

	fmt.Printf("APNs push certificate imported.\n")
	fmt.Printf("  topic:     %s\n", topic)
	if !notAfter.IsZero() {
		fmt.Printf("  expires:   %s\n", notAfter.Format("2006-01-02"))
	}
	fmt.Printf("\nIMPORTANT: this topic is baked into every enrolled device. When you\n")
	fmt.Printf("renew, renew the SAME certificate under the SAME Apple Account so the\n")
	fmt.Printf("topic does not change — a changed topic orphans every enrollment.\n")
	return nil
}
