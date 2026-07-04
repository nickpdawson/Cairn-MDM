// Command cairn is a single-binary Apple MDM server for homelabs, small
// businesses, non-profits, and families.
//
// Usage:
//
//	cairn <command> [flags]
//
// Commands:
//
//	serve      run the MDM server
//	init       interactive first-run setup wizard (Phase 2)
//	migrate    apply database migrations and exit
//	import     import an existing NanoMDM MySQL deployment (Phase 3)
//	admin      administrative helpers, e.g. reset-password (Phase 2)
//	pushcert   manage the APNs push certificate (Phase 1)
//	version    print build information
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/dzsec/cairn/internal/version"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	cmd := os.Args[1]
	args := os.Args[2:]

	var err error
	switch cmd {
	case "serve":
		err = runServe(ctx, args)
	case "migrate":
		err = runMigrate(ctx, args)
	case "pushcert":
		err = runPushcert(ctx, args)
	case "enqueue":
		err = runEnqueue(ctx, args)
	case "ca":
		err = runCA(ctx, args)
	case "version", "-v", "--version":
		fmt.Println(version.Info())
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "cairn: unknown command %q\n\n", cmd)
		usage()
		os.Exit(2)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "cairn %s: %v\n", cmd, err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `cairn — single-binary Apple MDM server

Usage:
  cairn <command> [flags]

Commands:
  serve      run the MDM server
  migrate    apply database migrations and exit
  pushcert   manage the APNs push certificate (import)
  enqueue    queue a command for a device and push
  ca         manage the certificate authority (export)
  version    print build information
  help       show this help

Run "cairn <command> -h" for command-specific flags.
`)
}
