package ca

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

// TrustAnchorsDER parses a PEM bundle (one or more CERTIFICATE blocks) into a
// slice of DER certificate bytes, for use as enrollment-profile trust anchors in
// external-CA mode. Non-certificate PEM blocks are ignored.
func TrustAnchorsDER(pemBundle []byte) ([][]byte, error) {
	var anchors [][]byte
	rest := pemBundle
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			return nil, fmt.Errorf("ca: trust anchor is not a valid certificate: %w", err)
		}
		anchors = append(anchors, block.Bytes)
	}
	if len(anchors) == 0 {
		return nil, errors.New("ca: no CERTIFICATE blocks found in trust chain")
	}
	return anchors, nil
}
