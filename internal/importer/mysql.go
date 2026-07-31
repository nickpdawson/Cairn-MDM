package importer

import (
	"context"
	"database/sql"
	"fmt"

	_ "github.com/go-sql-driver/mysql" // pure-Go MySQL driver, import side only
)

// MySQLSource reads a v1 NanoMDM MySQL database (nanomdm's own schema).
// The connection is read-only in practice — the importer never writes to the
// source, which is what makes rollback trivial (the old stack just resumes).
type MySQLSource struct {
	db *sql.DB
}

// OpenMySQL connects to the source. DSN format is go-sql-driver's, e.g.
// "nanomdm:pass@tcp(10.15.15.117:3306)/nanomdm".
func OpenMySQL(dsn string) (*MySQLSource, error) {
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, fmt.Errorf("open mysql: %w", err)
	}
	return &MySQLSource{db: db}, nil
}

// Ping verifies connectivity.
func (s *MySQLSource) Ping(ctx context.Context) error { return s.db.PingContext(ctx) }

// Close closes the connection.
func (s *MySQLSource) Close() error { return s.db.Close() }

func (s *MySQLSource) Devices(ctx context.Context) ([]DeviceRow, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, authenticate, COALESCE(token_update, ''), COALESCE(bootstrap_token_b64, ''), COALESCE(serial_number, '')
		 FROM devices ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DeviceRow
	for rows.Next() {
		var d DeviceRow
		if err := rows.Scan(&d.ID, &d.Authenticate, &d.TokenUpdate, &d.BootstrapTokenB64, &d.SerialNumber); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func (s *MySQLSource) Users(ctx context.Context) ([]UserRow, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, device_id, COALESCE(token_update, ''), COALESCE(user_authenticate, ''), COALESCE(user_authenticate_digest, '')
		 FROM users ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []UserRow
	for rows.Next() {
		var u UserRow
		if err := rows.Scan(&u.ID, &u.DeviceID, &u.TokenUpdate, &u.UserAuthenticate, &u.UserAuthDigest); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

func (s *MySQLSource) Enrollments(ctx context.Context) ([]EnrollmentRow, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, device_id, type, topic, push_magic, token_hex, enabled FROM enrollments ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []EnrollmentRow
	for rows.Next() {
		var e EnrollmentRow
		if err := rows.Scan(&e.ID, &e.DeviceID, &e.Type, &e.Topic, &e.PushMagic, &e.TokenHex, &e.Enabled); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *MySQLSource) CertAuthAssociations(ctx context.Context) ([]CertAuthRow, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, sha256 FROM cert_auth_associations ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CertAuthRow
	for rows.Next() {
		var a CertAuthRow
		if err := rows.Scan(&a.ID, &a.SHA256); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *MySQLSource) PushCerts(ctx context.Context) ([]PushCertRow, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT topic, cert_pem, key_pem FROM push_certs ORDER BY topic`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PushCertRow
	for rows.Next() {
		var p PushCertRow
		if err := rows.Scan(&p.Topic, &p.CertPEM, &p.KeyPEM); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *MySQLSource) PendingCommands(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx,
		`SELECT count(*) FROM enrollment_queue WHERE active = 1`).Scan(&n)
	return n, err
}
