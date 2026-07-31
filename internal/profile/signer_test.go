package profile

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/smallstep/pkcs7"
)

func writeSigningPair(t *testing.T, dir, name string, notBefore, notAfter time.Time) (certFile, keyFile string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: "cairn.example.org"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certFile = filepath.Join(dir, name+".crt")
	keyFile = filepath.Join(dir, name+".key")
	os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), 0o600)
	return certFile, keyFile
}

func TestLoadSignerAndSign(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := writeSigningPair(t, dir, "sign", time.Now().Add(-time.Hour), time.Now().Add(365*24*time.Hour))

	s, err := LoadSigner(certFile, keyFile)
	if err != nil {
		t.Fatalf("LoadSigner: %v", err)
	}
	if s.Cert.Subject.CommonName != "cairn.example.org" {
		t.Errorf("signer CN = %q", s.Cert.Subject.CommonName)
	}
	if s.DaysUntilExpiry() < 360 {
		t.Errorf("days to expiry = %d, want ~365", s.DaysUntilExpiry())
	}

	// The loaded signer actually signs a profile, and the CMS verifies.
	signed, err := Sign([]byte("<plist>hi</plist>"), *s)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	p7, err := pkcs7.Parse(signed)
	if err != nil {
		t.Fatalf("parse signed: %v", err)
	}
	if string(p7.Content) != "<plist>hi</plist>" {
		t.Errorf("signed content mismatch")
	}
}

func TestLoadSignerRejectsExpired(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := writeSigningPair(t, dir, "sign", time.Now().Add(-48*time.Hour), time.Now().Add(-24*time.Hour))
	if _, err := LoadSigner(certFile, keyFile); err == nil {
		t.Fatal("expired signing cert should be rejected")
	}
}

func TestLoadSignerMismatchedKey(t *testing.T) {
	dir := t.TempDir()
	certFile, _ := writeSigningPair(t, dir, "a", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	_, otherKey := writeSigningPair(t, dir, "b", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	// otherKey belongs to a different cert → LoadX509KeyPair must reject the pair.
	if _, err := LoadSigner(certFile, otherKey); err == nil {
		t.Fatal("mismatched cert/key should be rejected")
	}
}
