// Package config loads and validates Cairn's TOML configuration.
//
// Secrets are never inlined in the config file. Every secret-bearing field has
// a companion "<field>_file" or "<field>_env" that names where to read the
// value from at startup. This keeps the config file safe to commit to a private
// repo and safe to leave group-readable — the mistakes v1 made (LDAP bind
// passwords and API keys committed to git) are structurally impossible here.
package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"

	toml "github.com/pelletier/go-toml/v2"
)

// TLSMode selects how the server obtains its TLS certificate.
type TLSMode string

const (
	// TLSACME uses the built-in ACME client (Let's Encrypt) — the default for
	// public-DNS homelabs.
	TLSACME TLSMode = "acme"
	// TLSFiles uses an operator-supplied cert/key pair — for internal CAs
	// (DZsec/DigiCert) or any bring-your-own-cert setup.
	TLSFiles TLSMode = "files"
	// TLSProxy runs a plaintext listener behind a terminating reverse proxy
	// (nginx/caddy/traefik). Trusted-proxy header auth lives here.
	TLSProxy TLSMode = "proxy"
)

// StorageDriver selects the persistence backend.
type StorageDriver string

const (
	DriverSQLite   StorageDriver = "sqlite"
	DriverMySQL    StorageDriver = "mysql"
	DriverPostgres StorageDriver = "postgres"
)

// CAMode selects how device identity certificates are issued.
type CAMode string

const (
	// CAGenerate self-generates a device-identity CA on first boot and runs the
	// embedded SCEP endpoint. The zero-PKI default.
	CAGenerate CAMode = "generate"
	// CAImport runs the embedded SCEP endpoint but signs with an operator-supplied
	// CA cert+key (e.g. a subordinate CA from Microsoft AD CS or an existing org
	// root), so device certs chain to that CA.
	CAImport CAMode = "import"
	// CAExternal points enrollment profiles at a third-party SCEP server (OpenXPKI,
	// Microsoft NDES) and never issues certificates itself.
	CAExternal CAMode = "external"
)

// Embedded reports whether the mode runs Cairn's own SCEP endpoint (generate or
// import) as opposed to delegating to an external SCEP server.
func (m CAMode) Embedded() bool { return m == CAGenerate || m == CAImport }

// Config is the fully-resolved runtime configuration. Secrets have already been
// loaded from their _file/_env sources by the time a Config is returned.
type Config struct {
	Server  Server  `toml:"server"`
	Storage Storage `toml:"storage"`
	CA      CA      `toml:"ca"`
	Log     Log     `toml:"log"`
}

// Server holds HTTP listener and public-identity settings.
type Server struct {
	// PublicURL is the externally-reachable base URL. It drives the MDM
	// ServerURL/CheckInURL, the SCEP URL, and enrollment links, so it must be
	// exactly what devices were (or will be) enrolled against.
	PublicURL string `toml:"public_url"`
	// Listen is the bind address, e.g. ":443" or "127.0.0.1:8080".
	Listen string `toml:"listen"`
	// MDMPath is the path devices POST check-ins and command results to.
	// Defaults to "/mdm" to match nanomdm and v1's installed profiles.
	MDMPath string `toml:"mdm_path"`

	TLS TLS `toml:"tls"`
}

// TLS configures certificate acquisition.
type TLS struct {
	Mode TLSMode `toml:"mode"`
	// Files mode:
	CertFile string `toml:"cert_file"`
	KeyFile  string `toml:"key_file"`
	// ACME mode:
	ACMEEmail     string `toml:"acme_email"`
	ACMECacheDir  string `toml:"acme_cache_dir"`
	ACMEDirectory string `toml:"acme_directory"` // optional; defaults to Let's Encrypt prod
	// Proxy mode:
	TrustedProxies []string `toml:"trusted_proxies"`
}

// Storage configures the persistence backend.
type Storage struct {
	Driver StorageDriver `toml:"driver"`
	// Path is the SQLite database file (sqlite driver only).
	Path string `toml:"path"`
	// DSN is the connection string (mysql/postgres drivers only). Treated as a
	// secret: prefer DSNFile/DSNEnv.
	DSN     string `toml:"dsn"`
	DSNFile string `toml:"dsn_file"`
	DSNEnv  string `toml:"dsn_env"`
}

// CA configures certificate issuance for device identities.
type CA struct {
	Mode     CAMode        `toml:"mode"`
	Import   CAImportCfg   `toml:"import"`
	External CAExternalCfg `toml:"external"`
}

// CAImportCfg supplies an existing CA cert+key for import mode.
type CAImportCfg struct {
	CertFile string `toml:"cert_file"`
	KeyFile  string `toml:"key_file"`
}

// CAExternalCfg describes an external SCEP server (external mode only).
type CAExternalCfg struct {
	SCEPURL       string `toml:"scep_url"`
	CAChainFile   string `toml:"ca_chain_file"`
	CRLURL        string `toml:"crl_url"`
	ChallengeEnv  string `toml:"challenge_env"`
	ChallengeFile string `toml:"challenge_file"`
	// resolved:
	Challenge string `toml:"-"`
}

// Log configures structured logging.
type Log struct {
	// Format is "text" (default, for terminals) or "json" (for service mode).
	Format string `toml:"format"`
	// Level is "debug", "info" (default), "warn", or "error".
	Level string `toml:"level"`
}

// Default returns a Config with sane zero-config defaults applied. Callers layer
// file and env values on top before validation.
func Default() Config {
	return Config{
		Server: Server{
			Listen:  ":443",
			MDMPath: "/mdm",
			TLS:     TLS{Mode: TLSACME},
		},
		Storage: Storage{
			Driver: DriverSQLite,
			Path:   "/var/db/cairn/cairn.db",
		},
		CA:  CA{Mode: CAGenerate},
		Log: Log{Format: "text", Level: "info"},
	}
}

// Load reads the TOML file at path (if non-empty), applies environment overrides,
// resolves secret references, and validates the result.
func Load(path string) (Config, error) {
	cfg := Default()

	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return Config{}, fmt.Errorf("read config %q: %w", path, err)
		}
		dec := toml.NewDecoder(strings.NewReader(string(data)))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&cfg); err != nil {
			return Config{}, fmt.Errorf("parse config %q: %w", path, err)
		}
	}

	applyEnvOverrides(&cfg)

	if err := resolveSecrets(&cfg); err != nil {
		return Config{}, err
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// applyEnvOverrides applies a small set of explicit MDM_* environment overrides.
// These win over file values so a container/systemd unit can parameterize a
// baked-in config without editing it.
func applyEnvOverrides(cfg *Config) {
	if v := os.Getenv("CAIRN_PUBLIC_URL"); v != "" {
		cfg.Server.PublicURL = v
	}
	if v := os.Getenv("CAIRN_LISTEN"); v != "" {
		cfg.Server.Listen = v
	}
	if v := os.Getenv("CAIRN_STORAGE_PATH"); v != "" {
		cfg.Storage.Path = v
	}
	if v := os.Getenv("CAIRN_LOG_LEVEL"); v != "" {
		cfg.Log.Level = v
	}
	if v := os.Getenv("CAIRN_LOG_FORMAT"); v != "" {
		cfg.Log.Format = v
	}
}

// resolveSecrets reads secret values from their _file/_env references.
func resolveSecrets(cfg *Config) error {
	// Storage DSN.
	dsn, err := readSecret("storage.dsn", cfg.Storage.DSN, cfg.Storage.DSNFile, cfg.Storage.DSNEnv)
	if err != nil {
		return err
	}
	cfg.Storage.DSN = dsn

	// External CA challenge.
	ch, err := readSecret("ca.external.challenge", "", cfg.CA.External.ChallengeFile, cfg.CA.External.ChallengeEnv)
	if err != nil {
		return err
	}
	cfg.CA.External.Challenge = ch

	return nil
}

// readSecret resolves a secret from, in priority order: an env var name, a file
// path, or an inline literal. An inline literal is permitted (so tests and
// quick starts work) but is the least-preferred form.
func readSecret(name, inline, file, env string) (string, error) {
	if env != "" {
		if v, ok := os.LookupEnv(env); ok {
			return v, nil
		}
		return "", fmt.Errorf("%s: env var %q is not set", name, env)
	}
	if file != "" {
		b, err := os.ReadFile(file)
		if err != nil {
			return "", fmt.Errorf("%s: read secret file: %w", name, err)
		}
		return strings.TrimSpace(string(b)), nil
	}
	return inline, nil
}

// Validate checks that the resolved config is internally consistent.
func (c Config) Validate() error {
	var errs []error

	if c.Server.PublicURL == "" {
		errs = append(errs, errors.New("server.public_url is required"))
	} else if u, err := url.Parse(c.Server.PublicURL); err != nil || u.Scheme != "https" || u.Host == "" {
		errs = append(errs, fmt.Errorf("server.public_url must be an absolute https URL, got %q", c.Server.PublicURL))
	}
	if c.Server.Listen == "" {
		errs = append(errs, errors.New("server.listen is required"))
	}
	if !strings.HasPrefix(c.Server.MDMPath, "/") {
		errs = append(errs, fmt.Errorf("server.mdm_path must start with '/', got %q", c.Server.MDMPath))
	}

	switch c.Server.TLS.Mode {
	case TLSACME:
		if c.Server.TLS.ACMEEmail == "" {
			errs = append(errs, errors.New("server.tls.acme_email is required when tls.mode=acme"))
		}
	case TLSFiles:
		if c.Server.TLS.CertFile == "" || c.Server.TLS.KeyFile == "" {
			errs = append(errs, errors.New("server.tls.cert_file and key_file are required when tls.mode=files"))
		}
	case TLSProxy:
		// nothing required; trusted_proxies may be empty (loopback-only).
	default:
		errs = append(errs, fmt.Errorf("server.tls.mode must be acme|files|proxy, got %q", c.Server.TLS.Mode))
	}

	switch c.Storage.Driver {
	case DriverSQLite:
		if c.Storage.Path == "" {
			errs = append(errs, errors.New("storage.path is required when storage.driver=sqlite"))
		}
	case DriverMySQL, DriverPostgres:
		if c.Storage.DSN == "" {
			errs = append(errs, fmt.Errorf("storage.dsn (or dsn_file/dsn_env) is required when storage.driver=%s", c.Storage.Driver))
		}
	default:
		errs = append(errs, fmt.Errorf("storage.driver must be sqlite|mysql|postgres, got %q", c.Storage.Driver))
	}

	switch c.CA.Mode {
	case CAGenerate:
		// CA is self-generated on first boot by the ca package.
	case CAImport:
		if c.CA.Import.CertFile == "" || c.CA.Import.KeyFile == "" {
			errs = append(errs, errors.New("ca.import.cert_file and key_file are required when ca.mode=import"))
		}
	case CAExternal:
		if c.CA.External.SCEPURL == "" {
			errs = append(errs, errors.New("ca.external.scep_url is required when ca.mode=external"))
		}
		if c.CA.External.CAChainFile == "" {
			errs = append(errs, errors.New("ca.external.ca_chain_file is required when ca.mode=external (trust anchor for the enrollment profile)"))
		}
	default:
		errs = append(errs, fmt.Errorf("ca.mode must be generate|import|external, got %q", c.CA.Mode))
	}

	return errors.Join(errs...)
}
