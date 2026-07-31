package profile

import (
	"fmt"
	"strings"
)

// WiFiParams describes a Wi-Fi profile. Personal (PSK) and Enterprise
// (EAP-TLS) modes share the network fields; Enterprise adds a SCEP identity
// payload and the RADIUS trust anchors — all inside the same profile, because
// Apple resolves PayloadCertificateUUID/AnchorUUID references only against
// payloads installed together (the root cause of v1's post-hoc trust failures).
type WiFiParams struct {
	Organization string // reverse-DNS identifier root
	DisplayName  string
	SSID         string
	Hidden       bool
	AutoJoin     bool

	// Personal (WPA/WPA2/WPA3 PSK):
	Password string

	// Enterprise (WPA2/WPA3 Enterprise, EAP-TLS):
	Enterprise         bool
	SCEPURL            string
	Challenge          string
	SubjectCN          string   // CN the device requests for its Wi-Fi identity
	KeySize            int      // default 2048
	CAAnchorsDER       [][]byte // RADIUS server CA chain (DER)
	TrustedServerNames []string // e.g. "radius.example.org" (optional but recommended)
}

// BuildWiFi assembles a Wi-Fi configuration profile.
func BuildWiFi(p WiFiParams) (map[string]any, error) {
	if p.Organization == "" || p.SSID == "" {
		return nil, fmt.Errorf("profile: organization and SSID are required")
	}
	slug := slugify(p.SSID)
	id := func(suffix string) string { return p.Organization + ".wifi." + slug + "." + suffix }

	wifi := Payload{
		"PayloadType":        "com.apple.wifi.managed",
		"PayloadVersion":     1,
		"PayloadIdentifier":  id("network"),
		"PayloadUUID":        newUUID(),
		"PayloadDisplayName": "Wi-Fi (" + p.SSID + ")",
		"SSID_STR":           p.SSID,
		"HIDDEN_NETWORK":     p.Hidden,
		"AutoJoin":           p.AutoJoin,
	}

	var payloads []any
	if !p.Enterprise {
		if p.Password == "" {
			return nil, fmt.Errorf("profile: PSK Wi-Fi needs a password")
		}
		wifi["EncryptionType"] = "WPA" // WPA/WPA2/WPA3 Personal
		wifi["Password"] = p.Password
		payloads = append(payloads, wifi)
	} else {
		if p.SCEPURL == "" || p.SubjectCN == "" {
			return nil, fmt.Errorf("profile: EAP-TLS Wi-Fi needs a SCEP URL and subject CN")
		}
		if len(p.CAAnchorsDER) == 0 {
			return nil, fmt.Errorf("profile: EAP-TLS Wi-Fi needs at least one RADIUS CA anchor")
		}
		if p.KeySize == 0 {
			p.KeySize = 2048
		}

		// RADIUS trust anchors, referenced by UUID from the EAP config.
		var anchorUUIDs []any
		for i, der := range p.CAAnchorsDER {
			u := newUUID()
			anchorUUIDs = append(anchorUUIDs, u)
			payloads = append(payloads, Payload{
				"PayloadType":        "com.apple.security.root",
				"PayloadVersion":     1,
				"PayloadIdentifier":  fmt.Sprintf("%s.wifi.%s.ca.%d", p.Organization, slug, i),
				"PayloadUUID":        u,
				"PayloadDisplayName": "RADIUS Certificate Authority",
				"PayloadContent":     der,
			})
		}

		// Device identity for EAP-TLS, issued via SCEP.
		scepUUID := newUUID()
		payloads = append(payloads, Payload{
			"PayloadType":        "com.apple.security.scep",
			"PayloadVersion":     1,
			"PayloadIdentifier":  id("identity"),
			"PayloadUUID":        scepUUID,
			"PayloadDisplayName": "Wi-Fi Identity (SCEP)",
			"PayloadContent": map[string]any{
				"URL":        p.SCEPURL,
				"Subject":    []any{[]any{[]any{"CN", p.SubjectCN}}},
				"Key Type":   "RSA",
				"Key Usage":  5, // digitalSignature(1) | keyEncipherment(4)
				"Keysize":    p.KeySize,
				"Challenge":  p.Challenge,
				"Retries":    3,
				"RetryDelay": 10,
			},
		})

		eap := map[string]any{
			"AcceptEAPTypes":               []any{13}, // EAP-TLS
			"PayloadCertificateAnchorUUID": anchorUUIDs,
		}
		if len(p.TrustedServerNames) > 0 {
			names := make([]any, len(p.TrustedServerNames))
			for i, n := range p.TrustedServerNames {
				names[i] = n
			}
			eap["TLSTrustedServerNames"] = names
		}
		wifi["EncryptionType"] = "WPA2" // Enterprise
		wifi["EAPClientConfiguration"] = eap
		wifi["PayloadCertificateUUID"] = scepUUID // the identity the supplicant presents
		payloads = append(payloads, wifi)
	}

	display := p.DisplayName
	if display == "" {
		display = "Wi-Fi: " + p.SSID
	}
	return map[string]any{
		"PayloadType":         "Configuration",
		"PayloadVersion":      1,
		"PayloadIdentifier":   p.Organization + ".wifi." + slug,
		"PayloadUUID":         newUUID(),
		"PayloadDisplayName":  display,
		"PayloadOrganization": p.Organization,
		"PayloadContent":      payloads,
	}, nil
}

// KerberosSSOParams describes a Kerberos Extensible SSO profile
// (com.apple.extensiblesso with Apple's built-in Kerberos extension).
type KerberosSSOParams struct {
	Organization string
	DisplayName  string
	Realm        string   // Kerberos realm; uppercased automatically
	Hosts        []string // host suffixes SSO applies to, e.g. ".example.org"

	DefaultRealm         bool
	SyncLocalPassword    bool // macOS only: keep the local account password in sync
	AllowAutomaticLogin  bool
	UseSiteAutoDiscovery bool
}

// BuildKerberosSSO assembles a Kerberos SSO extension profile.
//
// Do NOT include hosts that need to serve their own WWW-Authenticate flows to
// browsers (e.g. the MDM/enrollment host itself): the extension intercepts
// matching URLs, and Safari/WebKit does not apply the generated token for
// plain browser SPNEGO — keep those on server-side negotiation instead.
func BuildKerberosSSO(p KerberosSSOParams) (map[string]any, error) {
	if p.Organization == "" || p.Realm == "" {
		return nil, fmt.Errorf("profile: organization and realm are required")
	}
	if len(p.Hosts) == 0 {
		return nil, fmt.Errorf("profile: at least one host suffix is required")
	}
	realm := strings.ToUpper(strings.TrimSpace(p.Realm))
	hosts := make([]any, len(p.Hosts))
	for i, h := range p.Hosts {
		hosts[i] = strings.TrimSpace(h)
	}

	sso := Payload{
		"PayloadType":         "com.apple.extensiblesso",
		"PayloadVersion":      1,
		"PayloadIdentifier":   p.Organization + ".sso.kerberos",
		"PayloadUUID":         newUUID(),
		"PayloadDisplayName":  "Kerberos Single Sign-On",
		"ExtensionIdentifier": "com.apple.AppSSOKerberos.KerberosExtension",
		"TeamIdentifier":      "apple",
		// "Credential" (capitalized) per Apple's schema rangelist. macOS 27+
		// enforces the case strictly; the lowercase form older docs used is
		// rejected with "invalid value" at install time.
		"Type": "Credential",
		"Realm":               realm,
		"Hosts":               hosts,
		"ExtensionData": map[string]any{
			"isDefaultRealm":       p.DefaultRealm,
			"syncLocalPassword":    p.SyncLocalPassword,
			"allowAutomaticLogin":  p.AllowAutomaticLogin,
			"useSiteAutoDiscovery": p.UseSiteAutoDiscovery,
		},
	}

	display := p.DisplayName
	if display == "" {
		display = "Kerberos SSO (" + realm + ")"
	}
	return map[string]any{
		"PayloadType":         "Configuration",
		"PayloadVersion":      1,
		"PayloadIdentifier":   p.Organization + ".sso." + strings.ToLower(realm),
		"PayloadUUID":         newUUID(),
		"PayloadDisplayName":  display,
		"PayloadOrganization": p.Organization,
		"PayloadContent":      []any{sso},
	}, nil
}

// slugify reduces a free-form name to an identifier-safe token.
func slugify(s string) string {
	out := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			return r
		case r >= 'A' && r <= 'Z':
			return r + ('a' - 'A')
		case r == ' ', r == '-', r == '_', r == '.':
			return '-'
		default:
			return -1
		}
	}, s)
	out = strings.Trim(out, "-")
	if out == "" {
		out = "network"
	}
	return out
}
