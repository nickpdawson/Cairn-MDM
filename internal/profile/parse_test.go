package profile

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"strings"
	"testing"
	"time"
)

const testProfileXML = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>PayloadType</key><string>Configuration</string>
  <key>PayloadVersion</key><integer>1</integer>
  <key>PayloadIdentifier</key><string>com.example.wifi</string>
  <key>PayloadUUID</key><string>11111111-2222-3333-4444-555555555555</string>
  <key>PayloadDisplayName</key><string>Example Wi-Fi</string>
  <key>PayloadOrganization</key><string>Example Org</string>
  <key>PayloadContent</key><array>
    <dict>
      <key>PayloadType</key><string>com.apple.wifi.managed</string>
      <key>PayloadVersion</key><integer>1</integer>
      <key>PayloadIdentifier</key><string>com.example.wifi.1</string>
      <key>PayloadUUID</key><string>aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee</string>
      <key>SSID_STR</key><string>ExampleNet</string>
    </dict>
    <dict>
      <key>PayloadType</key><string>com.apple.security.root</string>
      <key>PayloadVersion</key><integer>1</integer>
      <key>PayloadIdentifier</key><string>com.example.wifi.ca</string>
      <key>PayloadUUID</key><string>ffffffff-0000-1111-2222-333333333333</string>
    </dict>
  </array>
</dict></plist>`

func TestParseInfoXML(t *testing.T) {
	info, err := ParseInfo([]byte(testProfileXML))
	if err != nil {
		t.Fatalf("ParseInfo: %v", err)
	}
	if info.Identifier != "com.example.wifi" || info.Name != "Example Wi-Fi" || info.Organization != "Example Org" {
		t.Errorf("metadata wrong: %+v", info)
	}
	want := "com.apple.security.root,com.apple.wifi.managed"
	if got := strings.Join(info.PayloadTypes, ","); got != want {
		t.Errorf("payload types = %q, want %q", got, want)
	}
}

func TestParseInfoRejectsNonProfile(t *testing.T) {
	if _, err := ParseInfo([]byte(`<?xml version="1.0"?><plist version="1.0"><dict>
	  <key>PayloadType</key><string>com.apple.wifi.managed</string>
	  <key>PayloadIdentifier</key><string>x</string></dict></plist>`)); err == nil {
		t.Error("non-Configuration plist should be rejected")
	}
	if _, err := ParseInfo([]byte("not a profile at all")); err == nil {
		t.Error("garbage should be rejected")
	}
}

func TestParseInfoSigned(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "signer.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)

	signed, err := Sign([]byte(testProfileXML), Signer{Cert: cert, Key: key})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	info, err := ParseInfo(signed)
	if err != nil {
		t.Fatalf("ParseInfo(signed): %v", err)
	}
	if info.Identifier != "com.example.wifi" {
		t.Errorf("signed profile metadata wrong: %+v", info)
	}
}
