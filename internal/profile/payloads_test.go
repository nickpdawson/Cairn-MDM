package profile

import (
	"testing"
)

func TestBuildWiFiPSK(t *testing.T) {
	prof, err := BuildWiFi(WiFiParams{
		Organization: "cairn.example.org", SSID: "HomeNet", Password: "hunter2hunter2", AutoJoin: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	data, err := Marshal(prof)
	if err != nil {
		t.Fatal(err)
	}
	info, err := ParseInfo(data)
	if err != nil {
		t.Fatalf("built profile does not parse: %v", err)
	}
	if info.Identifier != "cairn.example.org.wifi.homenet" {
		t.Errorf("identifier = %q", info.Identifier)
	}
	if len(info.PayloadTypes) != 1 || info.PayloadTypes[0] != "com.apple.wifi.managed" {
		t.Errorf("payload types = %v", info.PayloadTypes)
	}

	wifi := prof["PayloadContent"].([]any)[0].(Payload)
	if wifi["EncryptionType"] != "WPA" || wifi["Password"] != "hunter2hunter2" || wifi["AutoJoin"] != true {
		t.Errorf("wifi payload wrong: %v", wifi)
	}

	if _, err := BuildWiFi(WiFiParams{Organization: "o", SSID: "x"}); err == nil {
		t.Error("PSK without password should fail")
	}
}

func TestBuildWiFiEAPTLS(t *testing.T) {
	anchor := []byte{0x30, 0x82, 0x01, 0x00} // placeholder DER; builder never parses it
	prof, err := BuildWiFi(WiFiParams{
		Organization:       "cairn.example.org",
		SSID:               "Corp Net",
		AutoJoin:           true,
		Enterprise:         true,
		SCEPURL:            "https://mdm.example.org/scep",
		Challenge:          "secret",
		SubjectCN:          "%SerialNumber%.wifi.example.org",
		CAAnchorsDER:       [][]byte{anchor},
		TrustedServerNames: []string{"radius.example.org"},
	})
	if err != nil {
		t.Fatal(err)
	}

	payloads := prof["PayloadContent"].([]any)
	if len(payloads) != 3 { // root + scep + wifi
		t.Fatalf("got %d payloads, want 3 (root, scep, wifi)", len(payloads))
	}
	root := payloads[0].(Payload)
	scep := payloads[1].(Payload)
	wifi := payloads[2].(Payload)

	// The wifi payload must reference the SCEP payload as its identity and the
	// root payload as the RADIUS anchor — UUIDs resolve only within the same
	// profile, which is why everything ships together.
	if wifi["PayloadCertificateUUID"] != scep["PayloadUUID"] {
		t.Error("wifi PayloadCertificateUUID does not reference the SCEP payload")
	}
	eap := wifi["EAPClientConfiguration"].(map[string]any)
	anchors := eap["PayloadCertificateAnchorUUID"].([]any)
	if len(anchors) != 1 || anchors[0] != root["PayloadUUID"] {
		t.Error("EAP anchor UUID does not reference the root payload")
	}
	if types := eap["AcceptEAPTypes"].([]any); len(types) != 1 || types[0] != 13 {
		t.Errorf("AcceptEAPTypes = %v, want [13] (EAP-TLS)", types)
	}
	if wifi["EncryptionType"] != "WPA2" {
		t.Errorf("EncryptionType = %v, want WPA2 (enterprise)", wifi["EncryptionType"])
	}
	sc := scep["PayloadContent"].(map[string]any)
	if sc["URL"] != "https://mdm.example.org/scep" || sc["Challenge"] != "secret" || sc["Keysize"] != 2048 {
		t.Errorf("scep content wrong: %v", sc)
	}

	// Round-trips through the parser.
	data, err := Marshal(prof)
	if err != nil {
		t.Fatal(err)
	}
	info, err := ParseInfo(data)
	if err != nil {
		t.Fatal(err)
	}
	want := "com.apple.security.root,com.apple.security.scep,com.apple.wifi.managed"
	if got := joinTypes(info.PayloadTypes); got != want {
		t.Errorf("payload types = %q, want %q", got, want)
	}

	if _, err := BuildWiFi(WiFiParams{Organization: "o", SSID: "x", Enterprise: true, SCEPURL: "u", SubjectCN: "cn"}); err == nil {
		t.Error("EAP-TLS without anchors should fail")
	}
}

func TestBuildKerberosSSO(t *testing.T) {
	prof, err := BuildKerberosSSO(KerberosSSOParams{
		Organization:         "cairn.example.org",
		Realm:                "example.org", // lowercase in, uppercase out
		Hosts:                []string{".example.org", "intranet.example.org"},
		DefaultRealm:         true,
		UseSiteAutoDiscovery: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	sso := prof["PayloadContent"].([]any)[0].(Payload)
	if sso["Realm"] != "EXAMPLE.ORG" {
		t.Errorf("realm = %v, want EXAMPLE.ORG", sso["Realm"])
	}
	if sso["ExtensionIdentifier"] != "com.apple.AppSSOKerberos.KerberosExtension" ||
		sso["TeamIdentifier"] != "apple" || sso["Type"] != "Credential" {
		t.Errorf("extension identity wrong: %v", sso)
	}
	if hosts := sso["Hosts"].([]any); len(hosts) != 2 {
		t.Errorf("hosts = %v", hosts)
	}
	ext := sso["ExtensionData"].(map[string]any)
	if ext["isDefaultRealm"] != true || ext["useSiteAutoDiscovery"] != true || ext["syncLocalPassword"] != false {
		t.Errorf("extension data wrong: %v", ext)
	}

	data, err := Marshal(prof)
	if err != nil {
		t.Fatal(err)
	}
	info, err := ParseInfo(data)
	if err != nil {
		t.Fatal(err)
	}
	if info.Identifier != "cairn.example.org.sso.example.org" {
		t.Errorf("identifier = %q", info.Identifier)
	}

	if _, err := BuildKerberosSSO(KerberosSSOParams{Organization: "o", Realm: "R"}); err == nil {
		t.Error("no hosts should fail")
	}
}

func joinTypes(ts []string) string {
	out := ""
	for i, t := range ts {
		if i > 0 {
			out += ","
		}
		out += t
	}
	return out
}
