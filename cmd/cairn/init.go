package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/dzsec/cairn/internal/auth"
	"github.com/dzsec/cairn/internal/ca"
	"github.com/dzsec/cairn/internal/config"
	"github.com/dzsec/cairn/internal/storage/sqlite"
)

// runInit is the single get-up-and-running command. It writes a config file,
// initializes the database + CA, creates the first admin, and prints the
// enrollment URL and the one remaining manual step (the APNs push certificate).
//
// Everything can be supplied by flag for non-interactive use; missing required
// values are prompted for when stdin is a terminal.
func runInit(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	outConfig := fs.String("config", defaultConfigPath, "path to write cairn.toml")
	publicURL := fs.String("public-url", "", "public https base URL, e.g. https://mdm.example.org (required)")
	dataDir := fs.String("data-dir", "", "directory for the database + state (default: platform data dir)")
	caMode := fs.String("ca-mode", "generate", "generate | import | external")
	caCert := fs.String("ca-cert", "", "CA certificate PEM (import mode)")
	caKey := fs.String("ca-key", "", "CA private key PEM (import mode)")
	scepURL := fs.String("scep-url", "", "external SCEP URL (external mode)")
	caChain := fs.String("ca-chain", "", "external CA chain PEM file (external mode)")
	tlsMode := fs.String("tls", "acme", "acme | files | proxy")
	acmeEmail := fs.String("acme-email", "", "contact email for ACME (tls=acme)")
	adminUser := fs.String("admin-user", "admin", "initial admin username")
	adminPass := fs.String("admin-password", "", "initial admin password (prompted/generated if empty)")
	force := fs.Bool("force", false, "overwrite an existing config file")
	if err := fs.Parse(args); err != nil {
		return err
	}

	in := bufio.NewReader(os.Stdin)
	interactive := isTerminal()

	if *publicURL == "" {
		if interactive {
			*publicURL = prompt(in, "Public HTTPS URL (e.g. https://mdm.example.org)")
		}
		if *publicURL == "" {
			return fmt.Errorf("-public-url is required")
		}
	}
	if !strings.HasPrefix(*publicURL, "https://") {
		return fmt.Errorf("public-url must be an https:// URL")
	}

	if *dataDir == "" {
		*dataDir = defaultDataDir()
	}
	dbPath := filepath.Join(*dataDir, "cairn.db")

	// Refuse to clobber an existing config unless forced.
	if _, err := os.Stat(*outConfig); err == nil && !*force {
		return fmt.Errorf("config %s already exists (use -force to overwrite)", *outConfig)
	}

	// Build the config.
	cfg := config.Default()
	cfg.Server.PublicURL = *publicURL
	cfg.Server.Listen = ":443"
	cfg.Storage.Path = dbPath
	cfg.Server.TLS.Mode = config.TLSMode(*tlsMode)
	cfg.Server.TLS.ACMEEmail = *acmeEmail
	cfg.CA.Mode = config.CAMode(*caMode)
	cfg.CA.Import.CertFile = *caCert
	cfg.CA.Import.KeyFile = *caKey
	cfg.CA.External.SCEPURL = *scepURL
	cfg.CA.External.CAChainFile = *caChain
	if cfg.Server.TLS.Mode == config.TLSACME && cfg.Server.TLS.ACMEEmail == "" && interactive {
		cfg.Server.TLS.ACMEEmail = prompt(in, "ACME contact email")
	}

	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("configuration incomplete:\n%w", err)
	}

	// Admin password: use provided, else generate a strong one and print it.
	generatedPass := ""
	if *adminPass == "" {
		if interactive {
			*adminPass = prompt(in, fmt.Sprintf("Password for admin %q (blank to auto-generate)", *adminUser))
		}
		if *adminPass == "" {
			*adminPass = randomPassword()
			generatedPass = *adminPass
		}
	}

	// Create the data dir and database.
	if err := os.MkdirAll(*dataDir, 0o750); err != nil {
		return fmt.Errorf("create data dir: %w", err)
	}
	db, err := sqlite.Open(ctx, dbPath)
	if err != nil {
		return err
	}
	defer db.Close()

	// Initialize the CA (generate or import). External mode has no local CA.
	if cfg.CA.Mode.Embedded() {
		opts := ca.Options{
			CommonName:   "Cairn CA (" + publicHost(*publicURL) + ")",
			Organization: "Cairn",
		}
		if cfg.CA.Mode == config.CAImport {
			certPEM, rerr := os.ReadFile(*caCert)
			if rerr != nil {
				return fmt.Errorf("read -ca-cert: %w", rerr)
			}
			keyPEM, rerr := os.ReadFile(*caKey)
			if rerr != nil {
				return fmt.Errorf("read -ca-key: %w", rerr)
			}
			opts.ImportCertPEM, opts.ImportKeyPEM = certPEM, keyPEM
		}
		if _, err := ca.Ensure(ctx, db.SQL(), opts); err != nil {
			return err
		}
	}

	// Create the admin account.
	users := auth.NewLocalStore(db.SQL())
	if err := users.CreateUser(ctx, *adminUser, *adminPass, auth.RoleAdmin, ""); err != nil {
		return err
	}

	// Write the config file last, once everything else succeeded.
	if err := os.MkdirAll(filepath.Dir(*outConfig), 0o750); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}
	if err := os.WriteFile(*outConfig, []byte(renderTOML(cfg)), 0o640); err != nil {
		return fmt.Errorf("write config: %w", err)
	}

	printInitSummary(cfg, *outConfig, *adminUser, generatedPass)
	return nil
}

func printInitSummary(cfg config.Config, configPath, adminUser, generatedPass string) {
	fmt.Printf("\n✓ Cairn is initialized.\n\n")
	fmt.Printf("  config:      %s\n", configPath)
	fmt.Printf("  database:    %s\n", cfg.Storage.Path)
	fmt.Printf("  CA mode:     %s\n", cfg.CA.Mode)
	fmt.Printf("  admin user:  %s\n", adminUser)
	if generatedPass != "" {
		fmt.Printf("  admin pass:  %s   (generated — save this now)\n", generatedPass)
	}
	fmt.Printf("\nNext steps:\n")
	fmt.Printf("  1. Get an APNs push certificate (free via mdmcert.download, or ABM) and load it:\n")
	fmt.Printf("       cairn pushcert import -config %s -cert push.pem -key push.key\n", configPath)
	fmt.Printf("  2. Start the server:\n")
	fmt.Printf("       cairn serve -config %s\n", configPath)
	fmt.Printf("  3. Enroll devices at:  %s/enroll\n", cfg.Server.PublicURL)
	if cfg.CA.Mode == config.CAGenerate {
		fmt.Printf("     (Distribute the CA for offline trust with:  cairn ca export -config %s)\n", configPath)
	}
	fmt.Println()
}

func prompt(in *bufio.Reader, label string) string {
	fmt.Printf("%s: ", label)
	line, _ := in.ReadString('\n')
	return strings.TrimSpace(line)
}

func randomPassword() string {
	var b [18]byte
	_, _ = rand.Read(b[:])
	return base64.RawURLEncoding.EncodeToString(b[:])
}

func isTerminal() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}
