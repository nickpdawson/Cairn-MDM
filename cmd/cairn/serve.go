package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/dzsec/cairn/internal/ca"
	"github.com/dzsec/cairn/internal/config"
	"github.com/dzsec/cairn/internal/enroll"
	"github.com/dzsec/cairn/internal/mdmcore"
	"github.com/dzsec/cairn/internal/push"
	"github.com/dzsec/cairn/internal/server"
	"github.com/dzsec/cairn/internal/storage/sqlite"
	"github.com/dzsec/cairn/internal/version"
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

	// Assemble the embedded NanoMDM service over our storage.
	nanoStore := db.NanoStorage(log)
	core := mdmcore.New(nanoStore, mdmcore.NewLogAdapter(log))
	log.Info("mdm service ready", "path", cfg.Server.MDMPath)

	deps := server.Deps{MDM: core.Handler()}

	// Embedded SCEP CA (external-CA mode wires enrollment to a third-party SCEP
	// server instead and is handled in a later phase).
	if cfg.CA.Mode == config.CAEmbedded {
		host := publicHost(cfg.Server.PublicURL)
		authority, err := ca.Ensure(ctx, db.SQL(), ca.Options{
			CommonName:   "Cairn CA (" + host + ")",
			Organization: "Cairn",
			Challenge:    cfg.CA.External.Challenge, // reused as the static challenge if set
		})
		if err != nil {
			return err
		}
		scepHandler, err := authority.SCEPHandler()
		if err != nil {
			return err
		}
		deps.SCEP = scepHandler
		log.Info("embedded CA ready", "scep_path", "/scep", "ca_cn", authority.Certificate().Subject.CommonName)

		// Enrollment profile handler (embedded-CA mode). External-CA mode wires
		// its own SCEP URL/challenge in a later phase.
		deps.Enroll = enroll.New(enroll.Config{
			Organization:  "cairn." + host,
			CADER:         authority.Certificate().Raw,
			SCEPURL:       cfg.Server.PublicURL + "/scep",
			Challenge:     cfg.CA.External.Challenge,
			MDMServerURL:  cfg.Server.PublicURL + cfg.Server.MDMPath,
			SubjectPrefix: "devices." + host,
		}, db, push.SettingTopic, log)
		log.Info("enrollment endpoint ready", "path", "/enroll")
	}

	// TLS beyond plaintext proxy mode arrives in Phase 2; fail loudly rather
	// than silently serving cleartext where TLS was requested.
	if cfg.Server.TLS.Mode != config.TLSProxy {
		return fmt.Errorf("tls.mode %q not yet implemented (Phase 2); use tls.mode=proxy behind a terminating reverse proxy for now", cfg.Server.TLS.Mode)
	}

	srv := server.New(cfg, log, db, deps)
	httpSrv := &http.Server{
		Addr:              cfg.Server.Listen,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		log.Info("listening", "addr", cfg.Server.Listen, "tls", cfg.Server.TLS.Mode)
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
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
