package sqlite

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/dzsec/cairn/internal/push"
)

// oidUID is the UserID attribute OID Apple stuffs the APNs topic into.
var oidUID = asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 1}

func openTestDB(t *testing.T) *DB {
	t.Helper()
	db, err := Open(context.Background(), t.TempDir()+"/apns.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// genPushCert builds a self-signed cert carrying topic in the UID OID, valid
// between notBefore/notAfter. It returns the cert PEM, the matching key PEM, and
// an unrelated key PEM (for the mismatch case).
func genPushCert(t *testing.T, topic string, notBefore, notAfter time.Time) (certPEM, keyPEM, otherKeyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "APSP: Cairn test",
			ExtraNames: []pkix.AttributeTypeAndValue{{Type: oidUID, Value: topic}},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = marshalKey(t, key)

	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherKeyPEM = marshalKey(t, other)
	return certPEM, keyPEM, otherKeyPEM
}

func marshalKey(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

func TestUpsertAndListAPNSTopics(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	near := time.Now().AddDate(0, 3, 0).UTC().Format(time.RFC3339) // ~November-cliff analogue
	far := time.Now().AddDate(1, 6, 0).UTC().Format(time.RFC3339)  // 2027 test topic

	if err := db.UpsertAPNSTopic(ctx, "com.apple.mgmt.External.far", far, "CN=far", "nick"); err != nil {
		t.Fatal(err)
	}
	if err := db.UpsertAPNSTopic(ctx, "com.apple.mgmt.External.near", near, "CN=near", "nick"); err != nil {
		t.Fatal(err)
	}

	got, err := db.ListAPNSTopics(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d topics, want 2", len(got))
	}
	// Nearest expiry must sort first, so the sooner cliff never hides behind
	// the later date.
	if got[0].Topic != "com.apple.mgmt.External.near" {
		t.Errorf("ordering: got[0]=%q, want the nearer-expiry topic first", got[0].Topic)
	}
	if got[0].Subject != "CN=near" || got[0].LoadedBy != "nick" {
		t.Errorf("metadata not preserved: %+v", got[0])
	}

	// Upsert must replace the existing row, not add a second.
	newFar := time.Now().AddDate(2, 0, 0).UTC().Format(time.RFC3339)
	if err := db.UpsertAPNSTopic(ctx, "com.apple.mgmt.External.far", newFar, "CN=far-renewed", "alice"); err != nil {
		t.Fatal(err)
	}
	got, err = db.ListAPNSTopics(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("after upsert got %d topics, want 2 (replace, not insert)", len(got))
	}
	for _, tp := range got {
		if tp.Topic == "com.apple.mgmt.External.far" {
			if tp.NotAfter != newFar {
				t.Errorf("upsert did not replace not_after: got %q, want %q", tp.NotAfter, newFar)
			}
			if tp.Subject != "CN=far-renewed" || tp.LoadedBy != "alice" {
				t.Errorf("upsert did not replace metadata: %+v", tp)
			}
		}
	}
}

func TestLoadCertRejectsExpired(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	store := db.NanoStorage(nil)

	certPEM, keyPEM, _ := genPushCert(t, "com.apple.mgmt.External.test",
		time.Now().AddDate(-1, 0, 0), time.Now().AddDate(0, 0, -1))

	_, _, err := push.LoadCert(ctx, store, db, certPEM, keyPEM)
	if err == nil {
		t.Fatal("expected LoadCert to reject an expired certificate")
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Errorf("error = %v, want it to mention expiry", err)
	}
	// Nothing should have been cached for a rejected cert.
	if _, gerr := db.GetSetting(ctx, push.SettingTopic); !errors.Is(gerr, ErrSettingNotFound) {
		t.Errorf("expired cert must not populate the settings cache (GetSetting err = %v)", gerr)
	}
}

func TestLoadCertRejectsMismatchedKey(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	store := db.NanoStorage(nil)

	certPEM, _, otherKeyPEM := genPushCert(t, "com.apple.mgmt.External.test",
		time.Now().AddDate(0, 0, -1), time.Now().AddDate(1, 0, 0))

	_, _, err := push.LoadCert(ctx, store, db, certPEM, otherKeyPEM)
	if err == nil {
		t.Fatal("expected LoadCert to reject a key that does not match the certificate")
	}
	if _, gerr := db.GetSetting(ctx, push.SettingTopic); !errors.Is(gerr, ErrSettingNotFound) {
		t.Errorf("mismatched key must not populate the settings cache (GetSetting err = %v)", gerr)
	}
}

func TestLoadCertAcceptsValid(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	store := db.NanoStorage(nil)

	want := time.Now().AddDate(1, 0, 0)
	certPEM, keyPEM, _ := genPushCert(t, "com.apple.mgmt.External.test",
		time.Now().AddDate(0, 0, -1), want)

	topic, notAfter, err := push.LoadCert(ctx, store, db, certPEM, keyPEM)
	if err != nil {
		t.Fatalf("LoadCert rejected a valid cert: %v", err)
	}
	if topic != "com.apple.mgmt.External.test" {
		t.Errorf("topic = %q", topic)
	}
	if notAfter.Unix() != want.Unix() {
		t.Errorf("notAfter = %v, want %v", notAfter, want)
	}
	if v, gerr := db.GetSetting(ctx, push.SettingTopic); gerr != nil || v != topic {
		t.Errorf("settings cache not updated: v=%q err=%v", v, gerr)
	}
}
