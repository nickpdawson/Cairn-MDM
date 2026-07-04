// Package ca provides Cairn's embedded SCEP certificate authority: it bootstraps
// (or loads) a CA keypair stored in SQLite and serves a SCEP endpoint that
// issues device identity certificates. Deployments that use an external CA
// (e.g. OpenXPKI) do not construct this; their enrollment profiles point at the
// external SCEP URL instead.
package ca

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"

	kitlog "github.com/go-kit/kit/log"
	scepdepot "github.com/micromdm/scep/v2/depot"
	scepserver "github.com/micromdm/scep/v2/server"
)

// Options configures CA bootstrap.
type Options struct {
	CommonName   string // CA subject CommonName
	Organization string // CA subject Organization
	KeyBits      int    // CA RSA key size (default 4096)
	Years        int    // CA validity in years (default 10)

	// ImportCertPEM / ImportKeyPEM, when both set, seed the CA from an existing
	// keypair (import mode — e.g. a subordinate CA from Microsoft AD CS) instead
	// of generating one. Ignored once a CA is already persisted.
	ImportCertPEM []byte
	ImportKeyPEM  []byte

	// LeafValidityDays is the lifetime of issued device certs (default 365).
	LeafValidityDays int
	// AllowRenewalDays lets a device re-enroll this many days before expiry
	// (default 14).
	AllowRenewalDays int
	// Challenge, when non-empty, requires this static SCEP challenge password.
	// One-time per-enrollment challenges replace this in a later phase.
	Challenge string
}

// CA is the embedded certificate authority.
type CA struct {
	cert  *x509.Certificate
	key   *rsa.PrivateKey
	depot *sqlDepot
	opts  Options
}

// Ensure loads the CA from the database, generating and persisting a new one on
// first run.
func Ensure(ctx context.Context, db *sql.DB, opts Options) (*CA, error) {
	if opts.KeyBits == 0 {
		opts.KeyBits = 4096
	}
	if opts.Years == 0 {
		opts.Years = 10
	}
	if opts.LeafValidityDays == 0 {
		opts.LeafValidityDays = 365
	}
	if opts.AllowRenewalDays == 0 {
		opts.AllowRenewalDays = 14
	}

	cert, key, err := loadCA(ctx, db)
	if errors.Is(err, sql.ErrNoRows) {
		if len(opts.ImportCertPEM) > 0 || len(opts.ImportKeyPEM) > 0 {
			cert, key, err = importCA(ctx, db, opts.ImportCertPEM, opts.ImportKeyPEM)
		} else {
			cert, key, err = generateCA(ctx, db, opts)
		}
	}
	if err != nil {
		return nil, err
	}

	return &CA{
		cert:  cert,
		key:   key,
		depot: &sqlDepot{db: db, caCert: cert, caKey: key},
		opts:  opts,
	}, nil
}

func loadCA(ctx context.Context, db *sql.DB) (*x509.Certificate, *rsa.PrivateKey, error) {
	var certPEM, keyPEM []byte
	err := db.QueryRowContext(ctx, `SELECT cert_pem, key_pem FROM ca WHERE id = 1`).Scan(&certPEM, &keyPEM)
	if err != nil {
		return nil, nil, err
	}
	cb, _ := pem.Decode(certPEM)
	kb, _ := pem.Decode(keyPEM)
	if cb == nil || kb == nil {
		return nil, nil, errors.New("ca: stored CA PEM is malformed")
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("ca: parse stored cert: %w", err)
	}
	key, err := x509.ParsePKCS1PrivateKey(kb.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("ca: parse stored key: %w", err)
	}
	return cert, key, nil
}

func generateCA(ctx context.Context, db *sql.DB, opts Options) (*x509.Certificate, *rsa.PrivateKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, opts.KeyBits)
	if err != nil {
		return nil, nil, fmt.Errorf("ca: generate key: %w", err)
	}

	caTmpl := scepdepot.NewCACert(
		scepdepot.WithCommonName(opts.CommonName),
		scepdepot.WithOrganization(opts.Organization),
		scepdepot.WithYears(opts.Years),
	)
	der, err := caTmpl.SelfSign(rand.Reader, &key.PublicKey, key)
	if err != nil {
		return nil, nil, fmt.Errorf("ca: self-sign: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, fmt.Errorf("ca: parse new cert: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if _, err := db.ExecContext(ctx,
		`INSERT INTO ca (id, cert_pem, key_pem) VALUES (1, ?, ?)`, certPEM, keyPEM); err != nil {
		return nil, nil, fmt.Errorf("ca: persist: %w", err)
	}
	return cert, key, nil
}

// importCA seeds the CA table from an existing certificate + RSA key (PEM). The
// key must be RSA (the SCEP depot signs with RSA). Accepts PKCS#1 or PKCS#8 keys.
func importCA(ctx context.Context, db *sql.DB, certPEM, keyPEM []byte) (*x509.Certificate, *rsa.PrivateKey, error) {
	if len(certPEM) == 0 || len(keyPEM) == 0 {
		return nil, nil, errors.New("ca: import requires both cert and key PEM")
	}
	cb, _ := pem.Decode(certPEM)
	if cb == nil {
		return nil, nil, errors.New("ca: import cert is not valid PEM")
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("ca: parse import cert: %w", err)
	}
	if !cert.IsCA {
		return nil, nil, errors.New("ca: import certificate is not a CA (BasicConstraints CA=false)")
	}

	key, err := parseRSAKey(keyPEM)
	if err != nil {
		return nil, nil, err
	}

	// Persist in the normalized PKCS#1 form loadCA expects.
	normCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	normKey := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if _, err := db.ExecContext(ctx, `INSERT INTO ca (id, cert_pem, key_pem) VALUES (1, ?, ?)`, normCert, normKey); err != nil {
		return nil, nil, fmt.Errorf("ca: persist imported CA: %w", err)
	}
	return cert, key, nil
}

// parseRSAKey decodes an RSA private key from PEM in either PKCS#1 or PKCS#8.
func parseRSAKey(keyPEM []byte) (*rsa.PrivateKey, error) {
	kb, _ := pem.Decode(keyPEM)
	if kb == nil {
		return nil, errors.New("ca: import key is not valid PEM")
	}
	if key, err := x509.ParsePKCS1PrivateKey(kb.Bytes); err == nil {
		return key, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(kb.Bytes)
	if err != nil {
		return nil, fmt.Errorf("ca: parse import key (PKCS#1 and PKCS#8 both failed): %w", err)
	}
	rsaKey, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("ca: import key must be RSA, got %T", parsed)
	}
	return rsaKey, nil
}

// RootPEM returns the CA certificate in PEM form, for embedding as a trust
// anchor in enrollment profiles.
func (c *CA) RootPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.cert.Raw})
}

// Certificate returns the CA certificate.
func (c *CA) Certificate() *x509.Certificate { return c.cert }

// SCEPHandler builds the SCEP HTTP handler (GetCACert / GetCACaps / PKIOperation)
// to mount at the SCEP path.
func (c *CA) SCEPHandler() (http.Handler, error) {
	signerOpts := []scepdepot.Option{
		scepdepot.WithValidityDays(c.opts.LeafValidityDays),
		scepdepot.WithAllowRenewalDays(c.opts.AllowRenewalDays),
	}
	var signer scepserver.CSRSignerContext = scepserver.SignCSRAdapter(scepdepot.NewSigner(c.depot, signerOpts...))
	if c.opts.Challenge != "" {
		signer = scepserver.StaticChallengeMiddleware(c.opts.Challenge, signer)
	}

	svc, err := scepserver.NewService(c.cert, c.key, signer)
	if err != nil {
		return nil, fmt.Errorf("ca: new scep service: %w", err)
	}
	e := scepserver.MakeServerEndpoints(svc)
	return scepserver.MakeHTTPHandler(e, svc, kitlog.NewNopLogger()), nil
}
