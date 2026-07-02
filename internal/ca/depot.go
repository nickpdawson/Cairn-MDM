package ca

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"fmt"
	"math/big"
)

// sqlDepot implements github.com/micromdm/scep/v2/depot.Depot over SQLite: it
// hands the SCEP signer the CA key/cert, allocates monotonic serials, and
// records issued certificates. The Depot interface is:
//
//	CA(pass) ([]*x509.Certificate, *rsa.PrivateKey, error)
//	Put(name, *x509.Certificate) error
//	Serial() (*big.Int, error)
//	HasCN(cn, allowTime, cert, revokeOld) (bool, error)
type sqlDepot struct {
	db     *sql.DB
	caCert *x509.Certificate
	caKey  *rsa.PrivateKey
}

// CA returns the CA chain and key. The pass argument (for encrypted CA keys) is
// unused: the key is held in memory after bootstrap and protected at rest by the
// database file's permissions.
func (d *sqlDepot) CA(_ []byte) ([]*x509.Certificate, *rsa.PrivateKey, error) {
	return []*x509.Certificate{d.caCert}, d.caKey, nil
}

// Serial allocates the next certificate serial by inserting a row and returning
// its autoincrement id.
func (d *sqlDepot) Serial() (*big.Int, error) {
	res, err := d.db.ExecContext(context.Background(),
		`INSERT INTO scep_serials DEFAULT VALUES`)
	if err != nil {
		return nil, fmt.Errorf("allocate serial: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return nil, fmt.Errorf("read serial: %w", err)
	}
	return big.NewInt(id), nil
}

// Put records an issued certificate.
func (d *sqlDepot) Put(name string, crt *x509.Certificate) error {
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: crt.Raw})
	_, err := d.db.ExecContext(context.Background(),
		`INSERT INTO scep_certs (serial, name, cert_pem, not_after)
		 VALUES (?, ?, ?, ?)
		 ON CONFLICT (serial, name) DO UPDATE SET cert_pem = excluded.cert_pem`,
		crt.SerialNumber.String(), name, pemBytes, crt.NotAfter.UTC().Format("2006-01-02T15:04:05Z"))
	if err != nil {
		return fmt.Errorf("store issued cert: %w", err)
	}
	return nil
}

// HasCN is a no-op. The scep signer discards its boolean result (it only checks
// the error), using this hook for optional revocation bookkeeping. Cairn does
// not revoke-on-renewal at this layer, so there is nothing to do; each SCEP
// request issues a fresh certificate.
func (d *sqlDepot) HasCN(_ string, _ int, _ *x509.Certificate, _ bool) (bool, error) {
	return false, nil
}
