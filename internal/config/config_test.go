package config

import (
	"os"
	"path/filepath"
	"testing"
)

func writeTemp(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "cairn.toml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadMinimalProxy(t *testing.T) {
	p := writeTemp(t, `
[server]
public_url = "https://mdm.example.com"
listen = ":8443"
[server.tls]
mode = "proxy"
[storage]
driver = "sqlite"
path = "/tmp/x.db"
`)
	cfg, err := Load(p)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Server.MDMPath != "/mdm" {
		t.Errorf("MDMPath default = %q, want /mdm", cfg.Server.MDMPath)
	}
	if cfg.CA.Mode != CAGenerate {
		t.Errorf("CA.Mode default = %q, want generate", cfg.CA.Mode)
	}
}

func TestValidateRejectsNonHTTPSPublicURL(t *testing.T) {
	p := writeTemp(t, `
[server]
public_url = "http://insecure.example.com"
listen = ":8443"
[server.tls]
mode = "proxy"
`)
	if _, err := Load(p); err == nil {
		t.Fatal("expected error for non-https public_url, got nil")
	}
}

func TestACMERequiresEmail(t *testing.T) {
	p := writeTemp(t, `
[server]
public_url = "https://mdm.example.com"
listen = ":443"
[server.tls]
mode = "acme"
`)
	if _, err := Load(p); err == nil {
		t.Fatal("expected error: acme mode without acme_email")
	}
}

func TestEnvOverrideWins(t *testing.T) {
	p := writeTemp(t, `
[server]
public_url = "https://file.example.com"
listen = ":8443"
[server.tls]
mode = "proxy"
`)
	t.Setenv("CAIRN_PUBLIC_URL", "https://env.example.com")
	cfg, err := Load(p)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Server.PublicURL != "https://env.example.com" {
		t.Errorf("PublicURL = %q, want env override to win", cfg.Server.PublicURL)
	}
}

func TestSecretFromEnv(t *testing.T) {
	p := writeTemp(t, `
[server]
public_url = "https://mdm.example.com"
listen = ":8443"
[server.tls]
mode = "proxy"
[storage]
driver = "postgres"
dsn_env = "TEST_CAIRN_DSN"
`)
	t.Setenv("TEST_CAIRN_DSN", "postgres://u:p@h/db")
	cfg, err := Load(p)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Storage.DSN != "postgres://u:p@h/db" {
		t.Errorf("DSN = %q, want value resolved from env", cfg.Storage.DSN)
	}
}

func TestExternalCARequiresSCEPURL(t *testing.T) {
	p := writeTemp(t, `
[server]
public_url = "https://mdm.example.com"
listen = ":8443"
[server.tls]
mode = "proxy"
[ca]
mode = "external"
`)
	if _, err := Load(p); err == nil {
		t.Fatal("expected error: external CA without scep_url / ca_chain_file")
	}
}

func TestImportCARequiresCertAndKey(t *testing.T) {
	p := writeTemp(t, `
[server]
public_url = "https://mdm.example.com"
listen = ":8443"
[server.tls]
mode = "proxy"
[ca]
mode = "import"
`)
	if _, err := Load(p); err == nil {
		t.Fatal("expected error: import CA without cert_file/key_file")
	}
}

func TestGenerateCAIsDefault(t *testing.T) {
	p := writeTemp(t, `
[server]
public_url = "https://mdm.example.com"
listen = ":8443"
[server.tls]
mode = "proxy"
`)
	cfg, err := Load(p)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.CA.Mode != CAGenerate {
		t.Errorf("default CA mode = %q, want generate", cfg.CA.Mode)
	}
}
