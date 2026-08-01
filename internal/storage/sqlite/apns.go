package sqlite

import "context"

// APNSTopic is a row of the apns_topics table: the per-topic metadata Cairn
// records for each imported APNs push certificate. Storing one row per topic
// (rather than a single global setting) lets the console surface every fleet's
// expiry independently — the fix for MDM-APNS-001.
type APNSTopic struct {
	Topic    string
	NotAfter string // RFC3339 certificate expiry
	Subject  string // certificate subject DN (informational; may be empty)
	LoadedAt string
	LoadedBy string // admin/CLI user that imported it (may be empty)
}

// UpsertAPNSTopic records (or replaces, on renewal) the metadata for one APNs
// topic. The topic is the primary key, so re-importing a renewed certificate
// for the same topic updates the expiry and load stamp in place.
func (db *DB) UpsertAPNSTopic(ctx context.Context, topic, notAfter, subject, loadedBy string) error {
	_, err := db.sql.ExecContext(ctx,
		`INSERT INTO apns_topics (topic, not_after, subject, loaded_at, loaded_by)
		 VALUES (?, ?, ?, datetime('now'), ?)
		 ON CONFLICT (topic) DO UPDATE SET
		   not_after = excluded.not_after,
		   subject   = excluded.subject,
		   loaded_at = datetime('now'),
		   loaded_by = excluded.loaded_by`,
		topic, notAfter, subject, loadedBy)
	return err
}

// ListAPNSTopics returns every recorded topic ordered by expiry, nearest first,
// so the renewal-soonest certificate leads the dashboard and no second fleet's
// expiry hides behind a later date.
func (db *DB) ListAPNSTopics(ctx context.Context) ([]APNSTopic, error) {
	rows, err := db.sql.QueryContext(ctx,
		`SELECT topic, not_after, COALESCE(subject, ''), COALESCE(loaded_at, ''), COALESCE(loaded_by, '')
		   FROM apns_topics
		  ORDER BY not_after ASC, topic ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []APNSTopic
	for rows.Next() {
		var t APNSTopic
		if err := rows.Scan(&t.Topic, &t.NotAfter, &t.Subject, &t.LoadedAt, &t.LoadedBy); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}
