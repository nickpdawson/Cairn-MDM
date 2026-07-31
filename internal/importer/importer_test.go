package importer

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"testing"
	"time"

	"github.com/dzsec/cairn/internal/storage/sqlite"
)

// memSource is an in-memory Source for tests.
type memSource struct {
	devices     []DeviceRow
	users       []UserRow
	enrollments []EnrollmentRow
	assocs      []CertAuthRow
	pushCerts   []PushCertRow
	pending     int
}

func (m *memSource) Devices(context.Context) ([]DeviceRow, error)         { return m.devices, nil }
func (m *memSource) Users(context.Context) ([]UserRow, error)             { return m.users, nil }
func (m *memSource) Enrollments(context.Context) ([]EnrollmentRow, error) { return m.enrollments, nil }
func (m *memSource) CertAuthAssociations(context.Context) ([]CertAuthRow, error) {
	return m.assocs, nil
}
func (m *memSource) PushCerts(context.Context) ([]PushCertRow, error) { return m.pushCerts, nil }
func (m *memSource) PendingCommands(context.Context) (int, error)     { return m.pending, nil }

const testTopic = "com.apple.mgmt.External.test-1234"

func authPlist(udid string) string {
	return fmt.Sprintf(`<?xml version="1.0"?><plist version="1.0"><dict>
	<key>MessageType</key><string>Authenticate</string>
	<key>UDID</key><string>%s</string>
	<key>SerialNumber</key><string>SER-%s</string>
	<key>DeviceName</key><string>Imported Mac</string>
	<key>Model</key><string>MacBookPro17,1</string>
	<key>Topic</key><string>%s</string>
</dict></plist>`, udid, udid, testTopic)
}

func tokenUpdatePlist(udid, magic string, token []byte) string {
	return fmt.Sprintf(`<?xml version="1.0"?><plist version="1.0"><dict>
	<key>MessageType</key><string>TokenUpdate</string>
	<key>UDID</key><string>%s</string>
	<key>Topic</key><string>%s</string>
	<key>PushMagic</key><string>%s</string>
	<key>Token</key><data>%s</data>
</dict></plist>`, udid, testTopic, magic, base64.StdEncoding.EncodeToString(token))
}

// pushCertPEM generates a self-signed cert whose subject UID carries the APNs
// topic (how real MDM push certs encode it).
func pushCertPEM(t *testing.T) (string, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	uidOID := asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 1}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(7),
		Subject: pkix.Name{
			CommonName: "APSP:test",
			ExtraNames: []pkix.AttributeTypeAndValue{{Type: uidOID, Value: testTopic}},
		},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	return string(certPEM), string(keyPEM)
}

func testSource(t *testing.T) *memSource {
	t.Helper()
	certPEM, keyPEM := pushCertPEM(t)
	tokenA := []byte{0xAA, 0xBB, 0xCC, 0x01}
	tokenB := []byte{0xDD, 0xEE, 0xFF, 0x02}
	return &memSource{
		devices: []DeviceRow{
			{ID: "UDID-A", Authenticate: authPlist("UDID-A"),
				TokenUpdate:       tokenUpdatePlist("UDID-A", "MAGIC-A", tokenA),
				BootstrapTokenB64: base64.StdEncoding.EncodeToString([]byte("bstoken-a"))},
			{ID: "UDID-B", Authenticate: authPlist("UDID-B"),
				TokenUpdate: tokenUpdatePlist("UDID-B", "MAGIC-B", tokenB)},
		},
		enrollments: []EnrollmentRow{
			{ID: "UDID-A", DeviceID: "UDID-A", Type: "Device", Topic: testTopic,
				PushMagic: "MAGIC-A", TokenHex: fmt.Sprintf("%x", tokenA), Enabled: true},
			{ID: "UDID-B", DeviceID: "UDID-B", Type: "Device", Topic: testTopic,
				PushMagic: "MAGIC-B", TokenHex: fmt.Sprintf("%x", tokenB), Enabled: false}, // checked out in v1
		},
		assocs: []CertAuthRow{
			{ID: "UDID-A", SHA256: "aa11223344556677889900aabbccddeeff00112233445566778899aabbccddee"},
			{ID: "UDID-B", SHA256: "bb11223344556677889900aabbccddeeff00112233445566778899aabbccddee"},
		},
		pushCerts: []PushCertRow{{Topic: testTopic, CertPEM: certPEM, KeyPEM: keyPEM}},
	}
}

func newImporter(t *testing.T) (*Importer, *sqlite.DB) {
	t.Helper()
	db, err := sqlite.Open(context.Background(), t.TempDir()+"/import.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	return New(db.NanoStorage(log), db, log), db
}

func TestImportMigratesAndVerifies(t *testing.T) {
	ctx := context.Background()
	im, db := newImporter(t)
	src := testSource(t)

	rep, err := im.Run(ctx, src, Options{})
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if !rep.Ok() {
		t.Fatalf("verification failed: %v", rep.Mismatches)
	}
	if rep.Devices != 2 || rep.Associations != 2 || rep.PushCerts != 1 || rep.Disabled != 1 {
		t.Errorf("report = %+v", rep)
	}

	// The migrated device is pushable with the source's exact routing data.
	store := db.NanoStorage(nil)
	infos, err := store.RetrievePushInfo(ctx, []string{"UDID-A"})
	if err != nil {
		t.Fatal(err)
	}
	p := infos["UDID-A"]
	if p == nil || p.PushMagic != "MAGIC-A" || p.Topic != testTopic || fmt.Sprintf("%x", []byte(p.Token)) != "aabbcc01" {
		t.Fatalf("push info wrong: %+v", p)
	}

	// The admin inventory was projected (name parsed from the raw plist).
	dev, err := db.GetDevice(ctx, "UDID-A")
	if err != nil {
		t.Fatal(err)
	}
	if dev.Name != "Imported Mac" || dev.Serial != "SER-UDID-A" || !dev.Enrolled() {
		t.Errorf("projected device wrong: %+v", dev)
	}
}

func TestImportRefusesPendingQueue(t *testing.T) {
	im, _ := newImporter(t)
	src := testSource(t)
	src.pending = 3

	if _, err := im.Run(context.Background(), src, Options{}); err == nil {
		t.Fatal("import should refuse a non-drained queue")
	}
	// Explicit override proceeds.
	if _, err := im.Run(context.Background(), src, Options{AllowPending: true}); err != nil {
		t.Fatalf("allow-pending run: %v", err)
	}
}

func TestImportDetectsTamperedToken(t *testing.T) {
	im, _ := newImporter(t)
	src := testSource(t)
	src.enrollments[0].TokenHex = "deadbeef" // source disagrees with raw plists

	rep, err := im.Run(context.Background(), src, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Ok() {
		t.Fatal("verification should have flagged the token mismatch")
	}
}

func TestImportDryRunWritesNothing(t *testing.T) {
	ctx := context.Background()
	im, db := newImporter(t)

	rep, err := im.Run(ctx, testSource(t), Options{DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Devices != 2 || !rep.DryRun {
		t.Errorf("dry-run report = %+v", rep)
	}
	if devs, _ := db.ListDevices(ctx); len(devs) != 0 {
		t.Error("dry run wrote to the inventory")
	}
	if infos, err := db.NanoStorage(nil).RetrievePushInfo(ctx, []string{"UDID-A"}); err == nil && infos["UDID-A"] != nil {
		t.Error("dry run wrote push info")
	}
}
