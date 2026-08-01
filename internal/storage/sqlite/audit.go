package sqlite

import "context"

// AuditEntry is a row of the audit_log table: one security-sensitive admin
// action. The table is append-only — Cairn only ever writes (AppendAudit) and
// reads (ListAudit) it, never updates or deletes a row.
type AuditEntry struct {
	ID       int64
	At       string // UTC timestamp (datetime('now'))
	Username string // actor; empty for anonymous/failed login
	Provider string // actor's auth provider (local/oidc/ldap/kerberos)
	Action   string // HTTP method
	Target   string // request path (no query string, no body — no secrets)
	Result   string // response status code
	Remote   string // client IP (host portion of RemoteAddr)
}

// AppendAudit inserts one audit row. `at` is left to the table default so the
// database stamps a consistent UTC time. The call is best-effort from the
// caller's perspective, but a returned error is surfaced for logging.
func (db *DB) AppendAudit(ctx context.Context, e AuditEntry) error {
	_, err := db.sql.ExecContext(ctx,
		`INSERT INTO audit_log (username, provider, action, target, result, remote)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		e.Username, e.Provider, e.Action, e.Target, e.Result, e.Remote)
	return err
}

// ListAudit returns recent audit rows, newest first. A non-positive limit falls
// back to 200.
func (db *DB) ListAudit(ctx context.Context, limit int) ([]AuditEntry, error) {
	if limit <= 0 {
		limit = 200
	}
	rows, err := db.sql.QueryContext(ctx,
		`SELECT id, at, COALESCE(username, ''), COALESCE(provider, ''),
		        action, COALESCE(target, ''), COALESCE(result, ''), COALESCE(remote, '')
		   FROM audit_log
		  ORDER BY id DESC
		  LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AuditEntry
	for rows.Next() {
		var e AuditEntry
		if err := rows.Scan(&e.ID, &e.At, &e.Username, &e.Provider,
			&e.Action, &e.Target, &e.Result, &e.Remote); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
