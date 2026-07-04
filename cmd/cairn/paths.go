package main

import (
	"os"
	"path/filepath"
	"runtime"
)

func userHomeDir() (string, error) { return os.UserHomeDir() }

// defaultConfigPath is the per-platform default location of cairn.toml. It can
// always be overridden with -config.
var defaultConfigPath = func() string {
	switch runtime.GOOS {
	case "freebsd":
		return "/usr/local/etc/cairn/cairn.toml"
	case "darwin":
		return "/opt/homebrew/etc/cairn/cairn.toml"
	default: // linux and others
		return "/etc/cairn/cairn.toml"
	}
}()

// defaultDataDir is the per-platform default directory for the database and
// state (CA keys, ACME cache).
func defaultDataDir() string {
	switch runtime.GOOS {
	case "freebsd":
		return "/var/db/cairn"
	case "darwin":
		return filepath.Join(homeOr("/usr/local/var"), "Library", "Application Support", "cairn")
	default:
		return "/var/lib/cairn"
	}
}

func homeOr(fallback string) string {
	if h, err := userHomeDir(); err == nil && h != "" {
		return h
	}
	return fallback
}
