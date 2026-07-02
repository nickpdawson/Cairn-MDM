package main

import "runtime"

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
