package config

import (
	"os"
	"path/filepath"
	"strings"
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

// ldapConfig builds a minimal valid-except-for-transport LDAP config. The
// caller supplies the servers array literal and whether start_tls is set.
func ldapConfig(t *testing.T, serversTOML string, startTLS bool) string {
	t.Helper()
	t.Setenv("TEST_LDAP_BIND_PW", "secret")
	return `
[server]
public_url = "https://mdm.example.com"
listen = ":8443"
[server.tls]
mode = "proxy"
[auth.ldap]
enabled = true
servers = ` + serversTOML + `
start_tls = ` + boolStr(startTLS) + `
base_dn = "DC=example,DC=org"
bind_dn = "CN=svc,DC=example,DC=org"
bind_password_env = "TEST_LDAP_BIND_PW"
`
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func TestLDAPSPasses(t *testing.T) {
	p := writeTemp(t, ldapConfig(t, `["ldaps://dc1.example.org:636"]`, false))
	if _, err := Load(p); err != nil {
		t.Fatalf("ldaps:// should pass validation, got: %v", err)
	}
}

func TestLDAPWithStartTLSPasses(t *testing.T) {
	p := writeTemp(t, ldapConfig(t, `["ldap://dc1.example.org:389"]`, true))
	if _, err := Load(p); err != nil {
		t.Fatalf("ldap:// with start_tls should pass validation, got: %v", err)
	}
}

func TestLDAPPlaintextWithoutStartTLSFails(t *testing.T) {
	p := writeTemp(t, ldapConfig(t, `["ldap://dc1.example.org:389"]`, false))
	_, err := Load(p)
	if err == nil {
		t.Fatal("expected error: bare ldap:// without start_tls must be rejected")
	}
	if !strings.Contains(err.Error(), "start_tls") {
		t.Errorf("error should mention start_tls, got: %v", err)
	}
}

func TestLoginPolicyWithDefaults(t *testing.T) {
	// An entirely zero policy fills in every default.
	got := LoginPolicy{}.WithDefaults()
	want := LoginPolicy{
		MaxAttempts: 5, WindowSeconds: 300, LockoutSeconds: 900,
		MinPasswordLen: 8, IdleTimeoutMins: 60, MaxLifetimeMins: 720,
	}
	if got != want {
		t.Errorf("WithDefaults() = %+v, want %+v", got, want)
	}

	// Explicit values survive; only the zero fields are defaulted.
	partial := LoginPolicy{MaxAttempts: 10, MinPasswordLen: 16}.WithDefaults()
	if partial.MaxAttempts != 10 {
		t.Errorf("MaxAttempts = %d, want explicit 10", partial.MaxAttempts)
	}
	if partial.MinPasswordLen != 16 {
		t.Errorf("MinPasswordLen = %d, want explicit 16", partial.MinPasswordLen)
	}
	if partial.WindowSeconds != 300 {
		t.Errorf("WindowSeconds = %d, want default 300", partial.WindowSeconds)
	}
}

func TestValidateRejectsNegativeLoginPolicy(t *testing.T) {
	p := writeTemp(t, `
[server]
public_url = "https://mdm.example.com"
listen = ":8443"
[server.tls]
mode = "proxy"
[storage]
driver = "sqlite"
path = "/tmp/x.db"
[auth.login]
max_attempts = -1
`)
	_, err := Load(p)
	if err == nil {
		t.Fatal("expected error for negative auth.login.max_attempts")
	}
	if !strings.Contains(err.Error(), "max_attempts") {
		t.Errorf("error should mention max_attempts, got: %v", err)
	}
}

func TestLoginPolicyDefaultsWhenOmitted(t *testing.T) {
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
	if got := cfg.Auth.Login.WithDefaults().MaxAttempts; got != 5 {
		t.Errorf("omitted [auth.login] MaxAttempts default = %d, want 5", got)
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
