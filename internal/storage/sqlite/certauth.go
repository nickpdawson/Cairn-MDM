package sqlite

import (
	"context"
	"database/sql"
	"errors"

	"github.com/micromdm/nanomdm/mdm"
)

// certAuthStore is a native, multi-hash implementation of NanoMDM's
// CertAuthStore + CertAuthRetriever, backed by the cert_auth table
// (enrollment_id, sha256). It replaces NanoMDM's KV certauth backend, which
// stores only one hash per enrollment (each AssociateCertHash overwrites the
// last) — correct for live use but lossy for migration, where a renewed device
// carries several historical cert hashes that must all remain valid.
//
// Semantics (per NanoMDM's certauth service):
//   - AssociateCertHash     — ADD a hash to the enrollment's set (idempotent).
//   - IsCertHashAssociated  — is THIS hash in the enrollment's set?
//   - EnrollmentHasCertHash — does the enrollment have ANY hash? (hash ignored)
//   - HasCertHash           — has ANY enrollment ever had this hash?
//   - EnrollmentFromHash    — which enrollment does this hash belong to?
type certAuthStore struct{ db *sql.DB }

// AssociateCertHash adds hash to r.ID's associated set. Additive (not a
// replace) so a device accrues every cert it has ever authenticated with —
// exactly what the source MySQL backend records.
func (s *certAuthStore) AssociateCertHash(r *mdm.Request, hash string) error {
	_, err := s.db.ExecContext(r.Context(),
		`INSERT INTO cert_auth (enrollment_id, sha256) VALUES (?, ?)
		 ON CONFLICT (enrollment_id, sha256) DO NOTHING`, r.ID, hash)
	return err
}

// IsCertHashAssociated reports whether r.ID is associated with hash.
func (s *certAuthStore) IsCertHashAssociated(r *mdm.Request, hash string) (bool, error) {
	return s.exists(r.Context(),
		`SELECT 1 FROM cert_auth WHERE enrollment_id = ? AND sha256 = ? LIMIT 1`, r.ID, hash)
}

// EnrollmentHasCertHash reports whether r.ID has any hash associated (the hash
// argument is ignored, per the interface contract).
func (s *certAuthStore) EnrollmentHasCertHash(r *mdm.Request, _ string) (bool, error) {
	return s.exists(r.Context(),
		`SELECT 1 FROM cert_auth WHERE enrollment_id = ? LIMIT 1`, r.ID)
}

// HasCertHash reports whether hash has ever been associated to any enrollment.
func (s *certAuthStore) HasCertHash(r *mdm.Request, hash string) (bool, error) {
	return s.exists(r.Context(),
		`SELECT 1 FROM cert_auth WHERE sha256 = ? LIMIT 1`, hash)
}

// EnrollmentFromHash returns the enrollment ID a hash belongs to, or "".
func (s *certAuthStore) EnrollmentFromHash(ctx context.Context, hash string) (string, error) {
	var id string
	err := s.db.QueryRowContext(ctx,
		`SELECT enrollment_id FROM cert_auth WHERE sha256 = ? LIMIT 1`, hash).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return id, err
}

func (s *certAuthStore) exists(ctx context.Context, q string, args ...any) (bool, error) {
	var one int
	err := s.db.QueryRowContext(ctx, q, args...).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}
