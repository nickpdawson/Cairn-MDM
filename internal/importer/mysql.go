package importer

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"strings"

	_ "github.com/go-sql-driver/mysql" // pure-Go MySQL driver, import side only
)

// MySQLSource reads a v1 NanoMDM MySQL database (nanomdm's own schema).
// The connection is read-only in practice — the importer never writes to the
// source, which is what makes rollback trivial (the old stack just resumes).
type MySQLSource struct {
	db *sql.DB
}

// OpenMySQL connects to the source. DSN format is go-sql-driver's, e.g.
// "nanomdm:pass@tcp(db.example.internal:3306)/nanomdm".
//
// The account behind this DSN should be a READ-ONLY MySQL user: the importer
// never writes to the source (that is what makes rollback trivial), so a
// SELECT-only grant both matches intent and limits blast radius.
//
// Transport security: if the DSN does not set a tls= parameter, OpenMySQL
// appends tls=preferred so a TLS-capable server is used over TLS while a
// plaintext localhost/socket migration still works. When TLS is not set at all
// (e.g. tls=false or a unix() socket) a warning is logged rather than failing —
// some localhost/socket migrations are legitimately non-TLS.
func OpenMySQL(dsn string) (*MySQLSource, error) {
	if !dsnHasTLS(dsn) {
		slog.Default().Warn("importer: source DSN has no tls= parameter; defaulting to tls=preferred (use tls=true for a remote source, and a read-only MySQL account)")
		dsn = appendDSNParam(dsn, "tls", "preferred")
	}
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, fmt.Errorf("open mysql: %w", err)
	}
	return &MySQLSource{db: db}, nil
}

// dsnHasTLS reports whether the DSN's parameter list already sets tls=.
func dsnHasTLS(dsn string) bool {
	q := dsn
	if i := strings.LastIndex(dsn, "?"); i >= 0 {
		q = dsn[i+1:]
	} else {
		return false
	}
	for _, kv := range strings.Split(q, "&") {
		if strings.HasPrefix(strings.ToLower(kv), "tls=") {
			return true
		}
	}
	return false
}

// appendDSNParam adds key=val to the DSN's query string, adding the "?" if the
// DSN has no parameter section yet.
func appendDSNParam(dsn, key, val string) string {
	sep := "&"
	if !strings.Contains(dsn, "?") {
		sep = "?"
	}
	return dsn + sep + key + "=" + val
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
		`SELECT id, device_id, COALESCE(user_id, ''), type, topic, push_magic, token_hex, enabled FROM enrollments ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []EnrollmentRow
	for rows.Next() {
		var e EnrollmentRow
		if err := rows.Scan(&e.ID, &e.DeviceID, &e.UserID, &e.Type, &e.Topic, &e.PushMagic, &e.TokenHex, &e.Enabled); err != nil {
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
