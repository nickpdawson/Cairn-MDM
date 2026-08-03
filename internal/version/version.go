// Package version exposes build metadata injected at link time via -ldflags.
package version

import "runtime"

// These are set by the linker during release builds:
//
//	-ldflags "-X github.com/dzsec/cairn-mdm/internal/version.Version=v0.1.0 ..."
var (
	Version = "dev"
	Commit  = "none"
	Date    = "unknown"
)

// Info is a human-readable one-line build descriptor.
func Info() string {
	return "cairn " + Version + " (" + Commit + ", " + Date + ", " + runtime.Version() + ")"
}
