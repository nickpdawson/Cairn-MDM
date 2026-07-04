package main

import (
	"fmt"
	"log/slog"
	"net/http"
	"path/filepath"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"

	"github.com/dzsec/cairn/internal/config"
)

// configureTLS sets up the listener according to tls.mode and returns a function
// that starts serving (blocking). Supported modes:
//
//	acme  — built-in Let's Encrypt via autocert; auto-obtains and renews a cert
//	        for the public_url host. A helper :80 listener answers HTTP-01
//	        challenges and redirects to HTTPS. The turnkey default.
//	files — operator-supplied cert/key (internal CA, DigiCert, etc.).
//	proxy — plaintext; TLS is terminated by a fronting reverse proxy.
func configureTLS(cfg config.Config, srv *http.Server, log *slog.Logger) (func() error, error) {
	switch cfg.Server.TLS.Mode {
	case config.TLSProxy:
		return srv.ListenAndServe, nil

	case config.TLSFiles:
		cert, key := cfg.Server.TLS.CertFile, cfg.Server.TLS.KeyFile
		return func() error { return srv.ListenAndServeTLS(cert, key) }, nil

	case config.TLSACME:
		host := publicHost(cfg.Server.PublicURL)
		cacheDir := cfg.Server.TLS.ACMECacheDir
		if cacheDir == "" {
			cacheDir = filepath.Join(filepath.Dir(cfg.Storage.Path), "acme")
		}
		m := &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			Cache:      autocert.DirCache(cacheDir),
			HostPolicy: autocert.HostWhitelist(host),
			Email:      cfg.Server.TLS.ACMEEmail,
		}
		if dir := cfg.Server.TLS.ACMEDirectory; dir != "" {
			m.Client = &acme.Client{DirectoryURL: dir}
		}
		srv.TLSConfig = m.TLSConfig()

		// HTTP-01 challenge + redirect helper on :80.
		go func() {
			log.Info("acme http-01 helper listening", "addr", ":80")
			if err := http.ListenAndServe(":80", m.HTTPHandler(nil)); err != nil {
				log.Warn("acme http helper stopped", "err", err)
			}
		}()

		log.Info("acme enabled", "host", host, "cache", cacheDir)
		return func() error { return srv.ListenAndServeTLS("", "") }, nil

	default:
		return nil, fmt.Errorf("unsupported tls.mode %q", cfg.Server.TLS.Mode)
	}
}
