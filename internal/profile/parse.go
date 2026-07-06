package profile

import (
	"fmt"
	"sort"
	"strings"

	"github.com/micromdm/plist"
	"github.com/smallstep/pkcs7"
)

// Info is the metadata the library extracts from an uploaded .mobileconfig.
type Info struct {
	Identifier   string
	UUID         string
	Name         string
	Organization string
	PayloadTypes []string // inner payload types, sorted, deduplicated
}

// ParseInfo extracts library metadata from raw .mobileconfig bytes. It accepts
// both plain XML profiles and CMS/PKCS7-signed profiles (the signed wrapper is
// unwrapped for parsing only — the stored bytes stay as uploaded).
func ParseInfo(data []byte) (Info, error) {
	body := data
	if !looksLikeXML(body) {
		p7, err := pkcs7.Parse(body)
		if err != nil {
			return Info{}, fmt.Errorf("profile: not an XML plist and not a signed (CMS) profile: %w", err)
		}
		body = p7.Content
		if !looksLikeXML(body) {
			return Info{}, fmt.Errorf("profile: signed content is not an XML plist")
		}
	}

	var top struct {
		PayloadType         string
		PayloadIdentifier   string
		PayloadUUID         string
		PayloadDisplayName  string
		PayloadOrganization string
		PayloadContent      []map[string]any
	}
	if err := plist.Unmarshal(body, &top); err != nil {
		return Info{}, fmt.Errorf("profile: parse plist: %w", err)
	}
	if top.PayloadType != "Configuration" {
		return Info{}, fmt.Errorf("profile: top-level PayloadType is %q, want \"Configuration\"", top.PayloadType)
	}
	if top.PayloadIdentifier == "" {
		return Info{}, fmt.Errorf("profile: missing PayloadIdentifier")
	}

	seen := map[string]bool{}
	var types []string
	for _, p := range top.PayloadContent {
		if t, ok := p["PayloadType"].(string); ok && t != "" && !seen[t] {
			seen[t] = true
			types = append(types, t)
		}
	}
	sort.Strings(types)

	name := top.PayloadDisplayName
	if name == "" {
		name = top.PayloadIdentifier
	}
	return Info{
		Identifier:   top.PayloadIdentifier,
		UUID:         top.PayloadUUID,
		Name:         name,
		Organization: top.PayloadOrganization,
		PayloadTypes: types,
	}, nil
}

func looksLikeXML(b []byte) bool {
	s := strings.TrimLeft(string(b[:min(len(b), 64)]), " \t\r\n\uFEFF")
	return strings.HasPrefix(s, "<?xml") || strings.HasPrefix(s, "<!DOCTYPE") || strings.HasPrefix(s, "<plist")
}
