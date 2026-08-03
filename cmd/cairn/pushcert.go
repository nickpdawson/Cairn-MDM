package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/dzsec/cairn-mdm/internal/config"
	"github.com/dzsec/cairn-mdm/internal/push"
	"github.com/dzsec/cairn-mdm/internal/storage/sqlite"
	"github.com/micromdm/nanomdm/cryptoutil"
)

func runPushcert(ctx context.Context, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: cairn pushcert <request|decrypt|import|check> [flags]")
	}
	switch args[0] {
	case "request":
		return runPushcertRequest(ctx, args[1:])
	case "decrypt":
		return runPushcertDecrypt(ctx, args[1:])
	case "import":
		return runPushcertImport(ctx, args[1:])
	case "check":
		return runPushcertCheck(ctx, args[1:])
	default:
		return fmt.Errorf("unknown pushcert subcommand %q (want: request, decrypt, import, check)", args[0])
	}
}

func runPushcertImport(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("pushcert import", flag.ExitOnError)
	configPath := fs.String("config", defaultConfigPath, "path to cairn.toml")
	certFile := fs.String("cert", "", "APNs push certificate (PEM)")
	keyFile := fs.String("key", "", "APNs push private key (PEM)")
	loadedBy := fs.String("by", "", "operator recorded as having imported the cert")
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

	// Record per-topic metadata so the console can track every fleet's expiry
	// independently (MDM-APNS-001). LoadCert already validated and stored the
	// certificate, so this only fails on a database error.
	subject := ""
	if cert, cerr := cryptoutil.DecodePEMCertificate(pemCert); cerr == nil {
		subject = cert.Subject.String()
	}
	if err := db.UpsertAPNSTopic(ctx, topic, notAfter.UTC().Format(time.RFC3339), subject, *loadedBy); err != nil {
		return fmt.Errorf("record topic metadata: %w", err)
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

// runPushcertCheck reports every recorded APNs topic with its expiry and
// renewal tier. It reads the apns_topics table (table-only; it does not open a
// live APNs socket) so it works offline and surfaces each fleet's expiry — the
// visibility MDM-APNS-001 was about.
func runPushcertCheck(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("pushcert check", flag.ExitOnError)
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

	db, err := sqlite.Open(ctx, cfg.Storage.Path)
	if err != nil {
		return err
	}
	defer db.Close()

	topics, err := db.ListAPNSTopics(ctx)
	if err != nil {
		return err
	}
	if len(topics) == 0 {
		fmt.Println("No APNs push certificates recorded. Run: cairn pushcert import ...")
		return nil
	}

	fmt.Printf("%-45s  %-12s  %-6s  %s\n", "TOPIC", "EXPIRES", "DAYS", "STATUS")
	for _, t := range topics {
		exp := t.NotAfter
		var days int
		status := "unknown"
		if parsed, perr := time.Parse(time.RFC3339, t.NotAfter); perr == nil {
			exp = parsed.Format("2006-01-02")
			var sev string
			days, sev, status = push.RenewalTier(parsed)
			status = fmt.Sprintf("%s (%s)", status, sev)
		}
		fmt.Printf("%-45s  %-12s  %-6d  %s\n", t.Topic, exp, days, status)
	}
	return nil
}
