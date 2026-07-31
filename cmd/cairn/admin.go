package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"

	"golang.org/x/term"

	"github.com/dzsec/cairn/internal/auth"
	"github.com/dzsec/cairn/internal/config"
	"github.com/dzsec/cairn/internal/storage/sqlite"
	"github.com/dzsec/cairn/internal/version"
)

// runAdmin manages local console accounts: add, passwd, list, del.
func runAdmin(ctx context.Context, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: cairn admin <add|passwd|list|del> [flags]")
	}
	switch args[0] {
	case "add":
		return runAdminAdd(ctx, args[1:])
	case "passwd":
		return runAdminPasswd(ctx, args[1:])
	case "list":
		return runAdminList(ctx, args[1:])
	case "del":
		return runAdminDel(ctx, args[1:])
	case "testauth":
		return runAdminTestAuth(ctx, args[1:])
	default:
		return fmt.Errorf("unknown admin subcommand %q (want: add, passwd, list, del, testauth)", args[0])
	}
}

// runAdminTestAuth exercises the full login chain (LDAP + local) from the CLI
// so directory config can be verified without a browser.
func runAdminTestAuth(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("admin testauth", flag.ExitOnError)
	configPath := fs.String("config", defaultConfigPath, "path to cairn.toml")
	username := fs.String("username", "", "login to test (required)")
	password := fs.String("password", "", "password (or set CAIRN_TEST_PASSWORD)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *username == "" {
		return fmt.Errorf("-username is required")
	}
	pw := *password
	if pw == "" {
		pw = os.Getenv("CAIRN_TEST_PASSWORD")
	}
	if pw == "" {
		return fmt.Errorf("provide -password or CAIRN_TEST_PASSWORD")
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	db, err := sqlite.Open(ctx, cfg.Storage.Path)
	if err != nil {
		return err
	}
	defer db.Close()
	authn, err := buildAuthenticator(cfg, db, version.NewLogger(cfg.Log.Format, cfg.Log.Level))
	if err != nil {
		return err
	}

	id, err := authn.Authenticate(ctx, *username, pw)
	if err != nil {
		return fmt.Errorf("authentication FAILED: %w", err)
	}
	fmt.Printf("authentication OK\n  username: %s\n  display:  %s\n  role:     %s\n  provider: %s\n",
		id.Username, id.DisplayName, id.Role, id.Provider)
	return nil
}

// openLocalStore loads config and opens the local-account store.
func openLocalStore(ctx context.Context, configPath string) (*auth.LocalStore, *sqlite.DB, error) {
	cfg, err := config.Load(configPath)
	if err != nil {
		return nil, nil, err
	}
	if cfg.Storage.Driver != config.DriverSQLite {
		return nil, nil, fmt.Errorf("storage driver %q not yet implemented (Phase 4)", cfg.Storage.Driver)
	}
	db, err := sqlite.Open(ctx, cfg.Storage.Path)
	if err != nil {
		return nil, nil, err
	}
	local := auth.NewLocalStore(db.SQL())
	local.SetMinPasswordLen(cfg.Auth.Login.WithDefaults().MinPasswordLen)
	return local, db, nil
}

func runAdminAdd(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("admin add", flag.ExitOnError)
	configPath := fs.String("config", defaultConfigPath, "path to cairn.toml")
	username := fs.String("username", "", "account name (required)")
	role := fs.String("role", "admin", "role: admin | operator | user")
	password := fs.String("password", "", "password (generated if empty)")
	display := fs.String("display-name", "", "display name (optional)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *username == "" {
		return fmt.Errorf("-username is required")
	}
	r := auth.Role(strings.ToLower(*role))
	if !r.Valid() {
		return fmt.Errorf("invalid role %q (want: admin, operator, user)", *role)
	}

	pw := *password
	generated := false
	switch {
	case *password != "":
		warnPasswordOnCLI()
	case isTerminal():
		p, perr := readPasswordConfirm(fmt.Sprintf("Password for %q", *username))
		if perr != nil {
			return perr
		}
		pw = p
	default:
		// Non-interactive with no password supplied: generate one and print it.
		pw = randomPassword()
		generated = true
	}

	local, db, err := openLocalStore(ctx, *configPath)
	if err != nil {
		return err
	}
	defer db.Close()

	if err := local.CreateUser(ctx, *username, pw, r, *display); err != nil {
		return err
	}
	fmt.Printf("user %q created with role %s\n", *username, r)
	if generated {
		fmt.Printf("password: %s\n", pw)
	}
	return nil
}

func runAdminPasswd(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("admin passwd", flag.ExitOnError)
	configPath := fs.String("config", defaultConfigPath, "path to cairn.toml")
	username := fs.String("username", "", "account name (required)")
	password := fs.String("password", "", "new password (generated if empty)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *username == "" {
		return fmt.Errorf("-username is required")
	}
	pw := *password
	generated := false
	switch {
	case *password != "":
		warnPasswordOnCLI()
	case isTerminal():
		p, perr := readPasswordConfirm(fmt.Sprintf("New password for %q", *username))
		if perr != nil {
			return perr
		}
		pw = p
	default:
		// Non-interactive with no password supplied: generate one and print it.
		pw = randomPassword()
		generated = true
	}

	local, db, err := openLocalStore(ctx, *configPath)
	if err != nil {
		return err
	}
	defer db.Close()

	if err := local.SetPassword(ctx, *username, pw); err != nil {
		return err
	}
	fmt.Printf("password reset for %q\n", *username)
	if generated {
		fmt.Printf("password: %s\n", pw)
	}

	// Invalidate the user's existing sessions so the old password can't outlive
	// the reset (best-effort; a failure here doesn't undo the password change).
	sessions := auth.NewSessionStore(db.SQL(), 0)
	if n, err := sessions.DeleteByUsername(ctx, *username); err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not revoke existing sessions for %q: %v\n", *username, err)
	} else if n > 0 {
		fmt.Printf("revoked %d active session(s) for %q\n", n, *username)
	}
	return nil
}

func runAdminList(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("admin list", flag.ExitOnError)
	configPath := fs.String("config", defaultConfigPath, "path to cairn.toml")
	if err := fs.Parse(args); err != nil {
		return err
	}
	local, db, err := openLocalStore(ctx, *configPath)
	if err != nil {
		return err
	}
	defer db.Close()

	users, err := local.ListUsers(ctx)
	if err != nil {
		return err
	}
	for _, u := range users {
		name := u.Username
		if u.DisplayName != "" {
			name += " (" + u.DisplayName + ")"
		}
		fmt.Printf("%-10s %-30s created %s\n", u.Role, name, u.CreatedAt)
	}
	return nil
}

func runAdminDel(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("admin del", flag.ExitOnError)
	configPath := fs.String("config", defaultConfigPath, "path to cairn.toml")
	username := fs.String("username", "", "account name (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *username == "" {
		return fmt.Errorf("-username is required")
	}
	local, db, err := openLocalStore(ctx, *configPath)
	if err != nil {
		return err
	}
	defer db.Close()

	if err := local.DeleteUser(ctx, *username); err != nil {
		return err
	}
	fmt.Printf("user %q deleted (their sessions are revoked)\n", *username)
	return nil
}

// warnPasswordOnCLI notes on stderr that a password passed via -password can be
// captured in shell history and is visible to anyone who can run `ps`. Prefer
// the interactive no-echo prompt.
func warnPasswordOnCLI() {
	fmt.Fprintln(os.Stderr, "warning: -password on the command line may be visible in shell history and process listings (ps); prefer the interactive prompt")
}

// readPasswordConfirm reads a non-empty password twice from the terminal without
// echoing it, and requires the two entries to match. Prompts go to stderr so
// stdout stays clean for scripted consumers.
func readPasswordConfirm(label string) (string, error) {
	fmt.Fprintf(os.Stderr, "%s: ", label)
	first, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", fmt.Errorf("read password: %w", err)
	}
	fmt.Fprintf(os.Stderr, "%s (again): ", label)
	second, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", fmt.Errorf("read password: %w", err)
	}
	if string(first) != string(second) {
		return "", fmt.Errorf("passwords do not match")
	}
	if len(first) == 0 {
		return "", fmt.Errorf("password must not be empty")
	}
	return string(first), nil
}

// readOptionalPasswordConfirm reads a password without echo, allowing an empty
// entry (the caller treats empty as "auto-generate"). A non-empty entry is
// confirmed by re-entry.
func readOptionalPasswordConfirm(label string) (string, error) {
	fmt.Fprintf(os.Stderr, "%s: ", label)
	first, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", fmt.Errorf("read password: %w", err)
	}
	if len(first) == 0 {
		return "", nil
	}
	fmt.Fprintf(os.Stderr, "%s (again): ", label)
	second, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", fmt.Errorf("read password: %w", err)
	}
	if string(first) != string(second) {
		return "", fmt.Errorf("passwords do not match")
	}
	return string(first), nil
}
