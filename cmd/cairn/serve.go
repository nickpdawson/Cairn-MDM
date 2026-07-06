package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/dzsec/cairn/internal/assign"
	"github.com/dzsec/cairn/internal/auth"
	"github.com/dzsec/cairn/internal/config"
	"github.com/dzsec/cairn/internal/mdmcore"
	"github.com/dzsec/cairn/internal/push"
	"github.com/dzsec/cairn/internal/server"
	"github.com/dzsec/cairn/internal/storage/sqlite"
	"github.com/dzsec/cairn/internal/version"
	"github.com/dzsec/cairn/internal/web"
)

func runServe(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	configPath := fs.String("config", defaultConfigPath, "path to cairn.toml")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}

	log := version.NewLogger(cfg.Log.Format, cfg.Log.Level)
	log.Info("starting", "build", version.Info(), "public_url", cfg.Server.PublicURL)

	// Storage.
	if cfg.Storage.Driver != config.DriverSQLite {
		return fmt.Errorf("storage driver %q not yet implemented (Phase 4)", cfg.Storage.Driver)
	}
	db, err := sqlite.Open(ctx, cfg.Storage.Path)
	if err != nil {
		return err
	}
	defer db.Close()
	log.Info("storage ready", "driver", cfg.Storage.Driver, "path", cfg.Storage.Path)

	// Assemble the embedded NanoMDM service over our storage. The SQLite DB is
	// the device-inventory projector — enrollments update the inventory as they
	// happen (no polling).
	nanoStore := db.NanoStorage(log)
	core := mdmcore.New(nanoStore, mdmcore.NewLogAdapter(log), db, db, log)
	log.Info("mdm service ready", "path", cfg.Server.MDMPath)

	deps := server.Deps{MDM: core.Handler()}

	// Configure SCEP + enrollment per ca.mode (generate | import | external).
	if _, err := wirePKI(ctx, cfg, db.SQL(), db, log, &deps); err != nil {
		return err
	}

	// Admin console.
	pusher := push.NewPusher(nanoStore, mdmcore.NewLogAdapter(log))
	commander := mdmcore.NewCommander(nanoStore, pusher).WithRecorder(db, log)
	sessions := auth.NewSessionStore(db.SQL(), 12*time.Hour)

	// Session cleanup: purge expired rows hourly.
	go func() {
		t := time.NewTicker(time.Hour)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if n, err := sessions.DeleteExpired(ctx); err != nil {
					log.Warn("session cleanup failed", "err", err)
				} else if n > 0 {
					log.Info("session cleanup", "purged", n)
				}
			}
		}
	}()
	// Assignment reconciler: pushes assigned profiles when devices enroll and
	// when admins change groups/assignments. Event-driven — no polling loop.
	reconciler := assign.New(db, commander, log)
	core.OnPushable(reconciler.DeviceNowPushable)

	console, err := web.New(sessions, auth.NewLocalStore(db.SQL()), db, commander, reconciler,
		web.Config{PublicURL: cfg.Server.PublicURL}, log)
	if err != nil {
		return err
	}
	deps.UI = console
	log.Info("admin console ready", "path", "/admin")

	srv := server.New(cfg, log, db, deps)
	httpSrv := &http.Server{
		Addr:              cfg.Server.Listen,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	serveTLS, err := configureTLS(cfg, httpSrv, log)
	if err != nil {
		return err
	}

	errCh := make(chan error, 1)
	go func() {
		log.Info("listening", "addr", cfg.Server.Listen, "tls", cfg.Server.TLS.Mode)
		if err := serveTLS(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case <-ctx.Done():
		log.Info("shutdown signal received")
	case err := <-errCh:
		return err
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := httpSrv.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("graceful shutdown: %w", err)
	}
	log.Info("stopped")
	return nil
}

// publicHost extracts the host from the configured public URL for use in the CA
// subject. It falls back to the raw value if parsing fails (validation has
// already ensured it is a URL, so this is defensive).
func publicHost(publicURL string) string {
	if u, err := url.Parse(publicURL); err == nil && u.Host != "" {
		return u.Hostname()
	}
	return publicURL
}
