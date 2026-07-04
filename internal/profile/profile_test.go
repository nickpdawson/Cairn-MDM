package profile

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/micromdm/plist"
	"github.com/smallstep/pkcs7"
)

func sampleParams() EnrollmentParams {
	return EnrollmentParams{
		Organization:  "cairn.example.com",
		CAAnchorsDER:  [][]byte{[]byte("dummy-der-bytes")},
		SCEPURL:       "https://mdm.example.com/scep",
		SubjectCN:     "host1.devices.example.com",
		Challenge:     "s3cr3t",
		MDMServerURL:  "https://mdm.example.com/mdm",
		MDMCheckInURL: "https://mdm.example.com/mdm",
		Topic:         "com.apple.mgmt.External.abc-123",
	}
}

func TestBuildEnrollmentStructure(t *testing.T) {
	prof, err := BuildEnrollment(sampleParams())
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	xml, err := Marshal(prof)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	// Round-trip through the plist parser to confirm it is well-formed and to
	// inspect the resulting structure the way a device would.
	var back map[string]any
	if err := plist.Unmarshal(xml, &back); err != nil {
		t.Fatalf("unmarshal: %v\n%s", err, xml)
	}
	if back["PayloadType"] != "Configuration" {
		t.Errorf("top PayloadType = %v", back["PayloadType"])
	}
	content, ok := back["PayloadContent"].([]any)
	if !ok || len(content) != 3 {
		t.Fatalf("PayloadContent should have 3 payloads, got %#v", back["PayloadContent"])
	}

	types := map[string]map[string]any{}
	for _, c := range content {
		p := c.(map[string]any)
		types[p["PayloadType"].(string)] = p
	}
	for _, want := range []string{"com.apple.security.root", "com.apple.security.scep", "com.apple.mdm"} {
		if _, ok := types[want]; !ok {
			t.Errorf("missing payload %s", want)
		}
	}

	// The MDM payload must reference the SCEP payload's UUID as its identity,
	// and carry the enrollment invariants.
	mdm := types["com.apple.mdm"]
	scep := types["com.apple.security.scep"]
	if mdm["IdentityCertificateUUID"] != scep["PayloadUUID"] {
		t.Error("MDM IdentityCertificateUUID does not reference the SCEP payload UUID")
	}
	if mdm["ServerURL"] != "https://mdm.example.com/mdm" {
		t.Errorf("ServerURL = %v", mdm["ServerURL"])
	}
	if mdm["Topic"] != "com.apple.mgmt.External.abc-123" {
		t.Errorf("Topic = %v", mdm["Topic"])
	}
	if mdm["SignMessage"] != true {
		t.Errorf("SignMessage = %v, want true", mdm["SignMessage"])
	}
}

func TestBuildEnrollmentRequiresTopic(t *testing.T) {
	p := sampleParams()
	p.Topic = ""
	if _, err := BuildEnrollment(p); err == nil {
		t.Fatal("expected error when Topic is empty")
	}
}

func TestSignProducesVerifiablePKCS7(t *testing.T) {
	prof, _ := BuildEnrollment(sampleParams())
	xml, _ := Marshal(prof)

	// A throwaway self-signed signing identity.
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Cairn Profile Signer"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)

	signed, err := Sign(xml, Signer{Cert: cert, Key: key})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	p7, err := pkcs7.Parse(signed)
	if err != nil {
		t.Fatalf("parse signed: %v", err)
	}
	// The signed content must be exactly the profile XML we handed in.
	if string(p7.Content) != string(xml) {
		t.Error("signed content does not match the original profile")
	}
	// And the signature must verify against the embedded signer cert.
	p7.Certificates = []*x509.Certificate{cert}
	if err := p7.Verify(); err != nil {
		t.Errorf("signature does not verify: %v", err)
	}
}
