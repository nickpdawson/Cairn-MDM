package ca

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	scepdepot "github.com/micromdm/scep/v2/depot"
	scep "github.com/smallstep/scep"

	"github.com/dzsec/cairn-mdm/internal/storage/sqlite"
)

// makeCACertPEM builds a self-signed CA cert+key and returns them PEM-encoded,
// standing in for an operator-supplied CA (e.g. a Microsoft AD CS subordinate).
func makeCACertPEM(t *testing.T, cn string) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(42),
		Subject:               pkix.Name{CommonName: cn, Organization: []string{"Contoso"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(5, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	return certPEM, keyPEM
}

func TestImportCAIssuesFromSuppliedRoot(t *testing.T) {
	certPEM, keyPEM := makeCACertPEM(t, "Contoso Issuing CA")

	db, err := sqlite.Open(context.Background(), t.TempDir()+"/imp.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	authority, err := Ensure(context.Background(), db.SQL(), Options{
		ImportCertPEM: certPEM,
		ImportKeyPEM:  keyPEM,
	})
	if err != nil {
		t.Fatalf("ensure import CA: %v", err)
	}
	if authority.Certificate().Subject.CommonName != "Contoso Issuing CA" {
		t.Errorf("CA CN = %q, want the imported CA", authority.Certificate().Subject.CommonName)
	}

	// A device cert issued now must chain to the imported CA, so devices trust
	// the corporate root — the "hybrid" story.
	signer := scepdepot.NewSigner(authority.depot)
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	csrDER, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "laptop.devices.contoso.com"},
	}, key)
	csr, _ := x509.ParseCertificateRequest(csrDER)
	leaf, err := signer.SignCSR(&scep.CSRReqMessage{CSR: csr})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := leaf.CheckSignatureFrom(authority.Certificate()); err != nil {
		t.Errorf("issued cert does not chain to the imported CA: %v", err)
	}

	// Re-Ensure without import args loads the persisted imported CA.
	again, err := Ensure(context.Background(), db.SQL(), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if !again.Certificate().Equal(authority.Certificate()) {
		t.Error("re-ensure did not load the persisted imported CA")
	}
}

func TestImportRejectsNonCACert(t *testing.T) {
	// A leaf (non-CA) cert must be rejected.
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "leaf"}, NotAfter: time.Now().Add(time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})

	db, _ := sqlite.Open(context.Background(), t.TempDir()+"/imp2.db")
	defer db.Close()
	if _, err := Ensure(context.Background(), db.SQL(), Options{ImportCertPEM: certPEM, ImportKeyPEM: keyPEM}); err == nil {
		t.Fatal("expected import of a non-CA certificate to fail")
	}
}

func TestTrustAnchorsDER(t *testing.T) {
	c1, _ := makeCACertPEM(t, "Root A")
	c2, _ := makeCACertPEM(t, "Root B")
	bundle := append(append([]byte{}, c1...), c2...)

	anchors, err := TrustAnchorsDER(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if len(anchors) != 2 {
		t.Fatalf("got %d anchors, want 2", len(anchors))
	}
	if _, err := TrustAnchorsDER([]byte("not pem")); err == nil {
		t.Error("expected error on non-PEM input")
	}
}
