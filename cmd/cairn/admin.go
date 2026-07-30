package main

import (
	"context"
	"flag"
	"fmt"
	"strings"

	"github.com/dzsec/cairn/internal/auth"
	"github.com/dzsec/cairn/internal/config"
	"github.com/dzsec/cairn/internal/storage/sqlite"
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
	default:
		return fmt.Errorf("unknown admin subcommand %q (want: add, passwd, list, del)", args[0])
	}
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
	return auth.NewLocalStore(db.SQL()), db, nil
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
	if pw == "" {
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
	if pw == "" {
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
