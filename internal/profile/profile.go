// Package profile builds Apple configuration profiles (.mobileconfig). Phase 1
// covers the enrollment profile — the CA trust anchor, the SCEP identity
// payload, and the MDM enrollment payload — plus optional CMS/PKCS7 signing so
// devices display a verified signer. Additional payload types (Wi-Fi, VPN,
// Kerberos SSO, etc.) build on the same helpers in later phases.
package profile

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"fmt"

	"github.com/micromdm/plist"
	"github.com/smallstep/pkcs7"
)

// Payload is a single configuration payload. Modeled as a map so payload-type
// specific keys can be expressed directly; plist marshals maps with sorted keys,
// which Apple accepts.
type Payload map[string]any

// EnrollmentParams describes an enrollment profile to build.
type EnrollmentParams struct {
	Organization string // PayloadOrganization + reverse-DNS identifier root, e.g. "cairn.example.com"
	DisplayName  string // top-level profile display name

	CAAnchorsDER [][]byte // CA certificate(s) (DER) to install as trust anchors

	SCEPURL   string // SCEP endpoint, e.g. https://mdm.example.com/scep
	SCEPName  string // SCEP CA identifier (may be empty)
	SubjectCN string // CommonName the device requests, e.g. host.devices.example.com
	Challenge string // SCEP challenge password (empty if none)
	KeySize   int    // device key size (default 2048)

	MDMServerURL  string // com.apple.mdm ServerURL, e.g. https://mdm.example.com/mdm
	MDMCheckInURL string // com.apple.mdm CheckInURL (usually == ServerURL)
	Topic         string // APNs topic (com.apple.mgmt.External.<uuid>)
}

// BuildEnrollment assembles the enrollment profile plist (unsigned).
func BuildEnrollment(p EnrollmentParams) (map[string]any, error) {
	if p.Organization == "" {
		return nil, fmt.Errorf("profile: organization is required")
	}
	if p.Topic == "" {
		return nil, fmt.Errorf("profile: MDM Topic is required (load an APNs push certificate first)")
	}
	if p.KeySize == 0 {
		p.KeySize = 2048
	}

	id := func(suffix string) string { return p.Organization + "." + suffix }

	scepUUID := newUUID()
	mdmUUID := newUUID()

	// One com.apple.security.root payload per trust anchor (each holds one cert),
	// installed before the SCEP/MDM payloads that rely on the chain.
	var payloads []any
	for i, der := range p.CAAnchorsDER {
		payloads = append(payloads, Payload{
			"PayloadType":        "com.apple.security.root",
			"PayloadVersion":     1,
			"PayloadIdentifier":  fmt.Sprintf("%s.ca.%d", p.Organization, i),
			"PayloadUUID":        newUUID(),
			"PayloadDisplayName": "Certificate Authority",
			"PayloadContent":     der, // plist encodes []byte as <data>
		})
	}

	scep := Payload{
		"PayloadType":        "com.apple.security.scep",
		"PayloadVersion":     1,
		"PayloadIdentifier":  id("scep"),
		"PayloadUUID":        scepUUID,
		"PayloadDisplayName": "Device Identity (SCEP)",
		"PayloadContent": map[string]any{
			"URL":  p.SCEPURL,
			"Name": p.SCEPName,
			// Subject is an array of RDNs, each an array of [type, value] pairs.
			"Subject":    []any{[]any{[]any{"CN", p.SubjectCN}}},
			"Key Type":   "RSA",
			"Key Usage":  5, // digitalSignature(1) | keyEncipherment(4)
			"Keysize":    p.KeySize,
			"Challenge":  p.Challenge,
			"Retries":    3,
			"RetryDelay": 10,
		},
	}

	mdm := Payload{
		"PayloadType":             "com.apple.mdm",
		"PayloadVersion":          1,
		"PayloadIdentifier":       id("mdm"),
		"PayloadUUID":             mdmUUID,
		"PayloadDisplayName":      "Device Management",
		"IdentityCertificateUUID": scepUUID, // ties MDM identity to the SCEP payload
		"ServerURL":               p.MDMServerURL,
		"CheckInURL":              p.MDMCheckInURL,
		"Topic":                   p.Topic,
		"ServerCapabilities":      []any{"com.apple.mdm.per-user-connections"},
		"SignMessage":             true, // device signs check-ins (Mdm-Signature header)
		"AccessRights":            8191, // all rights
	}

	display := p.DisplayName
	if display == "" {
		display = "Cairn Enrollment"
	}

	payloads = append(payloads, scep, mdm)

	return map[string]any{
		"PayloadType":         "Configuration",
		"PayloadVersion":      1,
		"PayloadIdentifier":   id("enroll"),
		"PayloadUUID":         newUUID(),
		"PayloadDisplayName":  display,
		"PayloadOrganization": p.Organization,
		"PayloadContent":      payloads,
	}, nil
}

// Marshal renders a profile plist to XML bytes.
func Marshal(prof map[string]any) ([]byte, error) {
	return plist.MarshalIndent(prof, "\t")
}

// Signer holds the identity used to CMS-sign profiles.
type Signer struct {
	Cert  *x509.Certificate
	Key   crypto.PrivateKey
	Chain []*x509.Certificate // intermediates to include (optional)
}

// Sign wraps a marshaled profile in a PKCS7 (CMS) SignedData structure, so the
// device shows a verified signer instead of "Not Signed". Returns DER.
func Sign(plistXML []byte, s Signer) ([]byte, error) {
	sd, err := pkcs7.NewSignedData(plistXML)
	if err != nil {
		return nil, fmt.Errorf("profile: new signed data: %w", err)
	}
	if err := sd.AddSigner(s.Cert, s.Key, pkcs7.SignerInfoConfig{}); err != nil {
		return nil, fmt.Errorf("profile: add signer: %w", err)
	}
	for _, c := range s.Chain {
		sd.AddCertificate(c)
	}
	signed, err := sd.Finish()
	if err != nil {
		return nil, fmt.Errorf("profile: finish signing: %w", err)
	}
	return signed, nil
}

// newUUID returns a random RFC 4122 v4 UUID string, without pulling in a UUID
// dependency for this one use.
func newUUID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
