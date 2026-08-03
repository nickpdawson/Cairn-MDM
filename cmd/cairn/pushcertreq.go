package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/dzsec/cairn-mdm/internal/config"
	"github.com/smallstep/pkcs7"
)

// mdmcert.download is the community MDM-vendor CSR-signing service (run by the
// MicroMDM maintainer; free, no SLA). The API key is the service's published
// client key, the same one shipped in micromdm's mdmctl.
var mdmcertRequestURL = "https://mdmcert.download/api/v1/signrequest"

const mdmcertAPIKey = "f847aea2ba06b41264d587b229e2712c89b1490a1208b7ff1aafab5bb40d47bc"

// signRequest is mdmcert.download's request body.
type signRequest struct {
	CSR     string `json:"csr"`     // base64 of the PEM push CSR
	Email   string `json:"email"`   // must be pre-registered at mdmcert.download
	Key     string `json:"key"`     // service API key
	Encrypt string `json:"encrypt"` // base64 of the PEM encryption cert (reply is encrypted to it)
}

// pushcertDir is where request artifacts live, next to the database.
func pushcertDir(cfg config.Config) string {
	return filepath.Join(filepath.Dir(cfg.Storage.Path), "pushcert")
}

func runPushcertRequest(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("pushcert request", flag.ExitOnError)
	configPath := fs.String("config", defaultConfigPath, "path to cairn.toml")
	email := fs.String("email", "", "email registered at mdmcert.download (required)")
	country := fs.String("country", "US", "CSR country code")
	cn := fs.String("cn", "", "CSR common name (default: mdm-push.<email domain>)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *email == "" || !strings.Contains(*email, "@") {
		return fmt.Errorf("-email is required (register it first at https://mdmcert.download/registration)")
	}
	commonName := *cn
	if commonName == "" {
		commonName = "mdm-push." + (*email)[strings.Index(*email, "@")+1:]
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	dir := pushcertDir(cfg)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}

	// The push key: the private half of the eventual APNs certificate. Keep it —
	// pushcert import pairs it with the cert Apple issues.
	pushKey, csrPEM, err := newPushCSR(commonName, *country, *email)
	if err != nil {
		return err
	}
	if err := writeKeyPEM(filepath.Join(dir, "push.key"), pushKey); err != nil {
		return err
	}

	// The encryption identity: mdmcert.download encrypts its emailed reply to
	// this throwaway self-signed cert so only this machine can read it.
	encKey, encCertPEM, err := newEncryptionCert(commonName + " (mdmcert decrypt)")
	if err != nil {
		return err
	}
	if err := writeKeyPEM(filepath.Join(dir, "encrypt.key"), encKey); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "encrypt.crt"), encCertPEM, 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "push.csr"), csrPEM, 0o600); err != nil {
		return err
	}

	body, err := json.Marshal(&signRequest{
		CSR:     base64.StdEncoding.EncodeToString(csrPEM),
		Email:   *email,
		Key:     mdmcertAPIKey,
		Encrypt: base64.StdEncoding.EncodeToString(encCertPEM),
	})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, mdmcertRequestURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "cairn/pushcert")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("mdmcert.download request: %w", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("mdmcert.download returned %s: %s\n(is %q registered at https://mdmcert.download/registration ?)",
			resp.Status, strings.TrimSpace(string(respBody)), *email)
	}

	fmt.Printf("Request submitted to mdmcert.download.\n\n")
	fmt.Printf("Artifacts saved in %s (keep push.key — it pairs with the final certificate).\n\n", dir)
	fmt.Printf("Next steps:\n")
	fmt.Printf("  1. Check %s for a mail from mdmcert.download with a .p7 attachment.\n", *email)
	fmt.Printf("  2. cairn pushcert decrypt -config %s -in <attachment.p7>\n", *configPath)
	fmt.Printf("  3. Upload the decrypted request at https://identity.apple.com (dedicated Apple ID!),\n")
	fmt.Printf("     download the push certificate (.pem).\n")
	fmt.Printf("  4. cairn pushcert import -config %s -cert <downloaded.pem> -key %s\n",
		*configPath, filepath.Join(dir, "push.key"))
	return nil
}

func runPushcertDecrypt(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("pushcert decrypt", flag.ExitOnError)
	configPath := fs.String("config", defaultConfigPath, "path to cairn.toml")
	in := fs.String("in", "", "the .p7 attachment emailed by mdmcert.download (required)")
	out := fs.String("out", "", "output path (default: <pushcert dir>/push_request.plist)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *in == "" {
		return fmt.Errorf("-in is required")
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	dir := pushcertDir(cfg)
	if *out == "" {
		*out = filepath.Join(dir, "push_request.plist")
	}

	encCert, encKey, err := loadEncryptionIdentity(dir)
	if err != nil {
		return err
	}

	// The attachment is a hex-encoded PKCS7 envelope encrypted to encrypt.crt.
	hexBytes, err := os.ReadFile(*in)
	if err != nil {
		return err
	}
	p7Bytes, err := hex.DecodeString(strings.TrimSpace(string(hexBytes)))
	if err != nil {
		return fmt.Errorf("attachment is not hex-encoded as expected: %w", err)
	}
	p7, err := pkcs7.Parse(p7Bytes)
	if err != nil {
		return fmt.Errorf("parse PKCS7: %w", err)
	}
	content, err := p7.Decrypt(encCert, encKey)
	if err != nil {
		return fmt.Errorf("decrypt (was 'pushcert request' run on this machine?): %w", err)
	}
	if err := os.WriteFile(*out, content, 0o600); err != nil {
		return err
	}

	fmt.Printf("Decrypted push-certificate request written to %s\n\n", *out)
	fmt.Printf("Next steps:\n")
	fmt.Printf("  1. Sign in at https://identity.apple.com with your DEDICATED MDM Apple ID.\n")
	fmt.Printf("  2. Create a certificate (or RENEW the existing one — never create a second\n")
	fmt.Printf("     one for a live fleet, the topic must not change) and upload %s.\n", filepath.Base(*out))
	fmt.Printf("  3. Download the resulting .pem, then:\n")
	fmt.Printf("     cairn pushcert import -config %s -cert <downloaded.pem> -key %s\n",
		*configPath, filepath.Join(dir, "push.key"))
	return nil
}

// newPushCSR generates the APNs keypair and a PEM CSR carrying the email.
func newPushCSR(commonName, country, email string) (*rsa.PrivateKey, []byte, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: commonName,
			Country:    []string{country},
		},
		EmailAddresses: []string{email},
	}, key)
	if err != nil {
		return nil, nil, err
	}
	return key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), nil
}

// newEncryptionCert generates a short-lived self-signed cert used only so
// mdmcert.download can encrypt its reply to us.
func newEncryptionCert(commonName string) (*rsa.PrivateKey, []byte, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(0, 3, 0), // plenty for an email round-trip
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	return key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}

// loadEncryptionIdentity reads encrypt.crt/encrypt.key written by request.
func loadEncryptionIdentity(dir string) (*x509.Certificate, *rsa.PrivateKey, error) {
	certPEM, err := os.ReadFile(filepath.Join(dir, "encrypt.crt"))
	if err != nil {
		return nil, nil, fmt.Errorf("read encryption cert (run 'pushcert request' first): %w", err)
	}
	keyPEM, err := os.ReadFile(filepath.Join(dir, "encrypt.key"))
	if err != nil {
		return nil, nil, err
	}
	cb, _ := pem.Decode(certPEM)
	if cb == nil {
		return nil, nil, fmt.Errorf("encrypt.crt is not PEM")
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, nil, err
	}
	kb, _ := pem.Decode(keyPEM)
	if kb == nil {
		return nil, nil, fmt.Errorf("encrypt.key is not PEM")
	}
	key, err := x509.ParsePKCS1PrivateKey(kb.Bytes)
	if err != nil {
		if k8, err8 := x509.ParsePKCS8PrivateKey(kb.Bytes); err8 == nil {
			if rk, ok := k8.(*rsa.PrivateKey); ok {
				return cert, rk, nil
			}
		}
		return nil, nil, err
	}
	return cert, key, nil
}

func writeKeyPEM(path string, key *rsa.PrivateKey) error {
	return os.WriteFile(path,
		pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), 0o600)
}
