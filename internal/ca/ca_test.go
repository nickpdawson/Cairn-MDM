package ca

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	scepdepot "github.com/micromdm/scep/v2/depot"
	scep "github.com/smallstep/scep"

	"github.com/nickpdawson/cairn-mdm/internal/storage/sqlite"
)

func testCA(t *testing.T) (*CA, *sqlite.DB) {
	t.Helper()
	db, err := sqlite.Open(context.Background(), t.TempDir()+"/ca.db")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	ca, err := Ensure(context.Background(), db.SQL(), Options{
		CommonName:   "Cairn Test CA",
		Organization: "Cairn",
		KeyBits:      2048, // smaller key keeps the test fast
	})
	if err != nil {
		t.Fatalf("ensure CA: %v", err)
	}
	return ca, db
}

func TestCABootstrapAndPersist(t *testing.T) {
	ca, db := testCA(t)

	if !ca.cert.IsCA {
		t.Error("issued CA cert is not marked IsCA")
	}
	if ca.cert.Subject.CommonName != "Cairn Test CA" {
		t.Errorf("CN = %q, want Cairn Test CA", ca.cert.Subject.CommonName)
	}
	// A self-signed CA verifies against itself.
	if err := ca.cert.CheckSignatureFrom(ca.cert); err != nil {
		t.Errorf("CA is not self-signed: %v", err)
	}

	// Re-running Ensure must load the same persisted CA, not mint a new one.
	ca2, err := Ensure(context.Background(), db.SQL(), Options{CommonName: "ignored"})
	if err != nil {
		t.Fatalf("re-ensure: %v", err)
	}
	if ca2.cert.SerialNumber.Cmp(ca.cert.SerialNumber) != 0 || !ca2.cert.Equal(ca.cert) {
		t.Error("re-ensure returned a different CA; persistence broken")
	}
}

func TestDepotIssuance(t *testing.T) {
	ca, db := testCA(t)

	// Build the signer exactly as SCEPHandler does.
	signer := scepdepot.NewSigner(ca.depot, scepdepot.WithValidityDays(90))

	// Generate a device keypair + CSR.
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "device-1.devices.example.com"},
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		t.Fatal(err)
	}

	leaf, err := signer.SignCSR(&scep.CSRReqMessage{CSR: csr})
	if err != nil {
		t.Fatalf("sign CSR: %v", err)
	}

	// The issued leaf must chain to the CA.
	if err := leaf.CheckSignatureFrom(ca.cert); err != nil {
		t.Errorf("issued cert does not verify against CA: %v", err)
	}
	if leaf.Subject.CommonName != "device-1.devices.example.com" {
		t.Errorf("leaf CN = %q", leaf.Subject.CommonName)
	}

	// Serials increment.
	s1, _ := ca.depot.Serial()
	s2, _ := ca.depot.Serial()
	if s2.Cmp(s1) <= 0 {
		t.Errorf("serials not monotonic: %s then %s", s1, s2)
	}

	// The issued cert was recorded.
	var count int
	if err := db.SQL().QueryRow(`SELECT count(*) FROM scep_certs`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count == 0 {
		t.Error("issued cert was not recorded in scep_certs")
	}
}

func TestSCEPGetCACert(t *testing.T) {
	ca, _ := testCA(t)

	h, err := ca.SCEPHandler()
	if err != nil {
		t.Fatalf("scep handler: %v", err)
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	resp, err := http.Get(srv.URL + "/scep?operation=GetCACert")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GetCACert status = %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	// With a single CA (no RA chain) SCEP returns the raw DER certificate.
	got, err := x509.ParseCertificate(body)
	if err != nil {
		t.Fatalf("GetCACert body is not a DER certificate: %v", err)
	}
	if !got.Equal(ca.cert) {
		t.Error("GetCACert returned a certificate that is not our CA")
	}
}
