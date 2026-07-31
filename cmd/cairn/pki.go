package main

import (
	"context"
	"database/sql"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net/http"
	"os"

	"github.com/dzsec/cairn/internal/ca"
	"github.com/dzsec/cairn/internal/config"
	"github.com/dzsec/cairn/internal/enroll"
	"github.com/dzsec/cairn/internal/push"
	"github.com/dzsec/cairn/internal/server"
)

// wirePKI configures the SCEP and enrollment handlers according to ca.mode:
//
//	generate/import — Cairn runs the embedded SCEP CA and mounts /scep; the
//	                  enrollment profile installs Cairn's CA and points SCEP at
//	                  <public_url>/scep.
//	external        — no /scep; the enrollment profile installs the configured
//	                  trust chain and points SCEP at ca.external.scep_url.
//
// It mutates deps and returns a summary of the wired PKI so other parts of the
// binary (the console's profile builders, future profile signing) can reuse the
// SCEP endpoint, challenge, and trust anchors without re-deriving them.
type pkiResult struct {
	Authority *ca.CA // nil in external mode
	Org       string // reverse-DNS identifier root, e.g. "cairn.mdm.example.org"
	SCEPURL   string
	Challenge string
	Anchors   [][]byte // trust-anchor certs (DER)
}

func wirePKI(ctx context.Context, cfg config.Config, db *sql.DB, topics enroll.TopicProvider, redeemer enroll.Redeemer, log *slog.Logger, deps *server.Deps) (*pkiResult, error) {
	host := publicHost(cfg.Server.PublicURL)
	org := "cairn." + host

	// mountEnroll builds the enroll handler and mounts both the grant route
	// (GET /e/{token}) and the bare /enroll route (default-denied unless
	// enrollment.allow_open).
	mountEnroll := func(c enroll.Config) {
		c.AllowOpen = cfg.Enrollment.AllowOpen
		h := enroll.New(c, topics, redeemer, push.SettingTopic, log)
		deps.Enroll = h
		deps.EnrollGrant = http.HandlerFunc(h.ServeGrant)
	}

	if cfg.CA.Mode.Embedded() {
		opts := ca.Options{
			CommonName:   "Cairn CA (" + host + ")",
			Organization: "Cairn",
			Challenge:    cfg.CA.External.Challenge, // static challenge if configured
		}
		if cfg.CA.Mode == config.CAImport {
			certPEM, err := os.ReadFile(cfg.CA.Import.CertFile)
			if err != nil {
				return nil, fmt.Errorf("read ca.import.cert_file: %w", err)
			}
			keyPEM, err := os.ReadFile(cfg.CA.Import.KeyFile)
			if err != nil {
				return nil, fmt.Errorf("read ca.import.key_file: %w", err)
			}
			opts.ImportCertPEM = certPEM
			opts.ImportKeyPEM = keyPEM
		}

		authority, err := ca.Ensure(ctx, db, opts)
		if err != nil {
			return nil, err
		}
		scepHandler, err := authority.SCEPHandler()
		if err != nil {
			return nil, err
		}
		deps.SCEP = scepHandler
		mountEnroll(enroll.Config{
			Organization:  org,
			CAAnchorsDER:  [][]byte{authority.Certificate().Raw},
			SCEPURL:       cfg.Server.PublicURL + "/scep",
			Challenge:     cfg.CA.External.Challenge,
			MDMServerURL:  cfg.Server.PublicURL + cfg.Server.MDMPath,
			SubjectPrefix: "devices." + host,
		})

		deps.CA = caDownloadHandler([][]byte{authority.Certificate().Raw})
		log.Info("embedded CA ready", "mode", cfg.CA.Mode, "scep_path", "/scep",
			"ca_cn", authority.Certificate().Subject.CommonName)
		log.Info("enrollment endpoint ready", "grant_path", "/e/{token}", "open", cfg.Enrollment.AllowOpen)
		return &pkiResult{
			Authority: authority,
			Org:       org,
			SCEPURL:   cfg.Server.PublicURL + "/scep",
			Challenge: cfg.CA.External.Challenge,
			Anchors:   [][]byte{authority.Certificate().Raw},
		}, nil
	}

	// external mode: delegate SCEP to a third-party server (OpenXPKI, NDES).
	chainPEM, err := os.ReadFile(cfg.CA.External.CAChainFile)
	if err != nil {
		return nil, fmt.Errorf("read ca.external.ca_chain_file: %w", err)
	}
	anchors, err := ca.TrustAnchorsDER(chainPEM)
	if err != nil {
		return nil, err
	}
	mountEnroll(enroll.Config{
		Organization:  org,
		CAAnchorsDER:  anchors,
		SCEPURL:       cfg.CA.External.SCEPURL,
		Challenge:     cfg.CA.External.Challenge,
		MDMServerURL:  cfg.Server.PublicURL + cfg.Server.MDMPath,
		SubjectPrefix: "devices." + host,
	})

	deps.CA = caDownloadHandler(anchors)
	log.Info("external SCEP configured", "scep_url", cfg.CA.External.SCEPURL, "trust_anchors", len(anchors))
	log.Info("enrollment endpoint ready", "grant_path", "/e/{token}", "open", cfg.Enrollment.AllowOpen)
	return &pkiResult{
		Org:       org,
		SCEPURL:   cfg.CA.External.SCEPURL,
		Challenge: cfg.CA.External.Challenge,
		Anchors:   anchors,
	}, nil
}

// caDownloadHandler serves the trust anchors as a PEM bundle at GET /ca, so a
// device can install the root out-of-band before enrolling (needed for
// fully-offline / private-TLS deployments).
func caDownloadHandler(anchorsDER [][]byte) http.Handler {
	var buf []byte
	for _, der := range anchorsDER {
		buf = append(buf, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/x-pem-file")
		w.Header().Set("Content-Disposition", `attachment; filename="cairn-ca.pem"`)
		_, _ = w.Write(buf)
	})
}
