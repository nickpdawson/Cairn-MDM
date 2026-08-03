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
	"os"
	"testing"
	"time"

	"github.com/dzsec/cairn-mdm/internal/storage/sqlite"
	"github.com/micromdm/nanomdm/mdm"
	"github.com/micromdm/nanomdm/storage"
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

// badAuthDevice is a device whose Authenticate plist cannot be decoded, so the
// importer skips it.
func badAuthDevice(id string) DeviceRow {
	return DeviceRow{ID: id, Authenticate: `<?xml version="1.0"?><plist version="1.0"><dict></dict></plist>`}
}

// TestSkippedRowFailsOk: a skipped row makes the run fail-closed.
func TestSkippedRowFailsOk(t *testing.T) {
	im, _ := newImporter(t)
	src := testSource(t)
	src.devices = append(src.devices, badAuthDevice("UDID-C"))

	rep, err := im.Run(context.Background(), src, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Skipped) != 1 || rep.Skipped[0].ID != "UDID-C" {
		t.Fatalf("expected one skip for UDID-C, got %+v", rep.Skipped)
	}
	if rep.Ok() {
		t.Fatal("an unaccepted skip must fail the run")
	}
}

// TestAcceptedExceptionAllowsSkip: an accepted exception lets that one skip
// pass, but a second unlisted skip still fails the run.
func TestAcceptedExceptionAllowsSkip(t *testing.T) {
	im, _ := newImporter(t)
	src := testSource(t)
	src.devices = append(src.devices, badAuthDevice("UDID-C"))

	rep, err := im.Run(context.Background(), src, Options{
		AllowedExceptions: map[string]bool{"UDID-C": true},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !rep.Ok() {
		t.Fatalf("an accepted exception should pass: %+v", rep.Skipped)
	}
	if len(rep.Skipped) != 1 || !rep.Skipped[0].Accepted {
		t.Fatalf("skip should be marked accepted: %+v", rep.Skipped)
	}

	// A second, unlisted skip still fails even though UDID-C is accepted.
	im2, _ := newImporter(t)
	src.devices = append(src.devices, badAuthDevice("UDID-D"))
	rep2, err := im2.Run(context.Background(), src, Options{
		AllowedExceptions: map[string]bool{"UDID-C": true},
	})
	if err != nil {
		t.Fatal(err)
	}
	if rep2.Ok() {
		t.Fatal("a second unlisted skip must still fail the run")
	}
}

// disableFailStore wraps a real storage.AllStorage and forces Disable to fail
// for named IDs, to exercise the disable-failure path.
type disableFailStore struct {
	storage.AllStorage
	failIDs map[string]bool
}

func (s *disableFailStore) Disable(r *mdm.Request) error {
	if s.failIDs[r.ID] {
		return fmt.Errorf("simulated disable failure for %s", r.ID)
	}
	return s.AllStorage.Disable(r)
}

// TestDisableFailureFailsOk: a failed source-disable is recorded, is NOT
// counted as disabled, and fails the run.
func TestDisableFailureFailsOk(t *testing.T) {
	ctx := context.Background()
	db, err := sqlite.Open(ctx, t.TempDir()+"/import.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	store := &disableFailStore{AllStorage: db.NanoStorage(log), failIDs: map[string]bool{"UDID-B": true}}
	im := New(store, db, log)

	rep, err := im.Run(ctx, testSource(t), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.DisableFailures) != 1 {
		t.Fatalf("expected one disable failure, got %+v", rep.DisableFailures)
	}
	if rep.Disabled != 0 {
		t.Errorf("a failed disable must not be counted: Disabled=%d", rep.Disabled)
	}
	if rep.Ok() {
		t.Fatal("a disable failure must fail the run")
	}
}

// TestUserChannelDisableUsesUserRequest: user-channel rows disable through the
// user request shape (User type + parent device ID), device rows through the
// device shape.
func TestUserChannelDisableUsesUserRequest(t *testing.T) {
	ctx := context.Background()

	user := EnrollmentRow{ID: "USER-1", DeviceID: "UDID-A", Type: "User"}
	req := disableReq(ctx, user)
	if req.EnrollID.Type != mdm.User {
		t.Errorf("user row: type = %v, want User", req.EnrollID.Type)
	}
	if req.EnrollID.ParentID != "UDID-A" {
		t.Errorf("user row: parent = %q, want UDID-A", req.EnrollID.ParentID)
	}

	// user_id present but Type unset still resolves to the user channel.
	byUserID := EnrollmentRow{ID: "USER-2", DeviceID: "UDID-A", UserID: "u-2"}
	if !byUserID.isUserChannel() {
		t.Error("a row with user_id should be user-channel")
	}

	dev := EnrollmentRow{ID: "UDID-A", DeviceID: "UDID-A", Type: "Device"}
	dreq := disableReq(ctx, dev)
	if dreq.EnrollID.Type != mdm.Device || dreq.EnrollID.ParentID != "" {
		t.Errorf("device row resolved to wrong shape: %+v", dreq.EnrollID)
	}
}

// TestDryRunNeedsNoDestination: dry-run runs with a nil destination and creates
// no database file (the importer never opens a dest in dry-run).
func TestDryRunNeedsNoDestination(t *testing.T) {
	ctx := context.Background()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	dbPath := t.TempDir() + "/should-not-be-created.db"

	im := New(nil, nil, log) // nil destination is safe in dry-run
	rep, err := im.Run(ctx, testSource(t), Options{DryRun: true})
	if err != nil {
		t.Fatalf("dry-run with nil dest: %v", err)
	}
	if rep.Devices != 2 || !rep.DryRun {
		t.Errorf("dry-run report = %+v", rep)
	}
	if _, err := os.Stat(dbPath); !os.IsNotExist(err) {
		t.Errorf("dry run must not create a destination DB file (stat err=%v)", err)
	}
}

// TestEvidenceBundleContents: the evidence bundle carries the expected counts
// and the exception-file hash.
func TestEvidenceBundleContents(t *testing.T) {
	ctx := context.Background()
	im, _ := newImporter(t)

	rep, err := im.Run(ctx, testSource(t), Options{ExceptionFileSHA256: "deadbeefcafe"})
	if err != nil {
		t.Fatal(err)
	}
	if !rep.Ok() {
		t.Fatalf("baseline import should pass: %+v", rep.Mismatches)
	}

	started := time.Now().Add(-time.Minute)
	ev := BuildEvidence(rep, started, time.Now())

	if ev.CountsByType["Device"] != 2 {
		t.Errorf("counts by type = %+v, want Device=2", ev.CountsByType)
	}
	if ev.CountsByTopic[testTopic] != 2 {
		t.Errorf("counts by topic = %+v, want %s=2", ev.CountsByTopic, testTopic)
	}
	if ev.Source.Devices != 2 || ev.Source.PushCerts != 1 {
		t.Errorf("source row counts wrong: %+v", ev.Source)
	}
	if ev.ExceptionFileSHA256 != "deadbeefcafe" {
		t.Errorf("exception hash = %q", ev.ExceptionFileSHA256)
	}

	// Round-trips through the on-disk JSON form.
	path := t.TempDir() + "/evidence.json"
	if err := WriteEvidence(path, ev); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("evidence perms = %#o, want 0600", fi.Mode().Perm())
	}
}

// expiredPushCertPEM makes a push cert already past NotAfter.
func expiredPushCertPEM(t *testing.T) (string, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	uidOID := asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 1}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(9),
		Subject: pkix.Name{
			CommonName: "APSP:test",
			ExtraNames: []pkix.AttributeTypeAndValue{{Type: uidOID, Value: testTopic}},
		},
		NotBefore: time.Now().Add(-48 * time.Hour),
		NotAfter:  time.Now().Add(-24 * time.Hour),
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
}

func TestImportValidatesPushCertAndRecordsTopic(t *testing.T) {
	ctx := context.Background()

	// Valid cert → run succeeds and records the topic + expiry.
	im, _ := newImporter(t)
	rep, err := im.Run(ctx, testSource(t), Options{})
	if err != nil {
		t.Fatalf("import with valid push cert: %v", err)
	}
	if len(rep.PushTopics) != 1 || rep.PushTopics[0].Topic != testTopic || rep.PushTopics[0].NotAfter == "" {
		t.Fatalf("push topic metadata not recorded: %+v", rep.PushTopics)
	}

	// Expired push cert → the run fails closed (a migrated fleet with an
	// expired push cert can't be pushed).
	im2, _ := newImporter(t)
	src := testSource(t)
	cert, key := expiredPushCertPEM(t)
	src.pushCerts = []PushCertRow{{Topic: testTopic, CertPEM: cert, KeyPEM: key}}
	if _, err := im2.Run(ctx, src, Options{}); err == nil {
		t.Fatal("import should fail on an expired push cert")
	}
}
