package profile

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"time"
)

// LoadSigner loads and validates a profile-signing identity from PEM files.
// certFile may contain a full chain (leaf first, intermediates after); the leaf
// signs and the intermediates are included so the device can build the chain.
// It fails if the cert and key do not match or the cert is expired/not-yet-valid.
func LoadSigner(certFile, keyFile string) (*Signer, error) {
	// tls.LoadX509KeyPair verifies the private key matches the leaf certificate.
	pair, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("profile: load signing keypair: %w", err)
	}
	if len(pair.Certificate) == 0 {
		return nil, fmt.Errorf("profile: signing cert file has no certificates")
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("profile: parse signing leaf: %w", err)
	}

	now := time.Now()
	if now.Before(leaf.NotBefore) {
		return nil, fmt.Errorf("profile: signing cert not valid until %s", leaf.NotBefore.Format(time.RFC3339))
	}
	if now.After(leaf.NotAfter) {
		return nil, fmt.Errorf("profile: signing cert expired %s", leaf.NotAfter.Format(time.RFC3339))
	}

	var chain []*x509.Certificate
	for _, der := range pair.Certificate[1:] {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("profile: parse signing chain: %w", err)
		}
		chain = append(chain, c)
	}

	return &Signer{Cert: leaf, Key: pair.PrivateKey, Chain: chain}, nil
}

// Fingerprint returns a short human-readable identity for the signer (CN +
// SHA-256 prefix + expiry) for operator display/logging.
func (s Signer) Fingerprint() string {
	if s.Cert == nil {
		return "(none)"
	}
	sum := sha256.Sum256(s.Cert.Raw)
	hexsum := hex.EncodeToString(sum[:])
	return fmt.Sprintf("%s (sha256:%s…, expires %s)",
		s.Cert.Subject.CommonName, hexsum[:16], s.Cert.NotAfter.Format("2006-01-02"))
}

// DaysUntilExpiry returns whole days until the signing cert expires (negative if
// already expired).
func (s Signer) DaysUntilExpiry() int {
	if s.Cert == nil {
		return 0
	}
	return int(time.Until(s.Cert.NotAfter).Hours() / 24)
}
