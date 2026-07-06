package sqlite

import (
	"context"
	"database/sql"
	"strings"
)

// Profile is a row of the configuration-profile library.
type Profile struct {
	ID           int64
	Identifier   string
	UUID         string
	Name         string
	Organization string
	PayloadTypes string // comma-joined for display
	Source       string
	Data         []byte
	CreatedAt    string
	UpdatedAt    string
}

// Types splits PayloadTypes for display.
func (p Profile) Types() []string {
	if p.PayloadTypes == "" {
		return nil
	}
	return strings.Split(p.PayloadTypes, ",")
}

// SaveProfile upserts a profile keyed by its PayloadIdentifier (matching device
// semantics: same identifier = in-place replacement) and returns its row ID.
func (db *DB) SaveProfile(ctx context.Context, p Profile) (int64, error) {
	var id int64
	// updated_at uses millisecond resolution: the deploy reconciler re-arms on
	// any updated_at change, and second-resolution would miss a rapid re-upload.
	err := db.sql.QueryRowContext(ctx,
		`INSERT INTO profiles (identifier, uuid, name, organization, payload_types, source, data, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, strftime('%Y-%m-%d %H:%M:%f','now'))
		 ON CONFLICT (identifier) DO UPDATE SET
		   uuid          = excluded.uuid,
		   name          = excluded.name,
		   organization  = excluded.organization,
		   payload_types = excluded.payload_types,
		   source        = excluded.source,
		   data          = excluded.data,
		   updated_at    = strftime('%Y-%m-%d %H:%M:%f','now')
		 RETURNING id`,
		p.Identifier, p.UUID, p.Name, p.Organization, p.PayloadTypes, p.Source, p.Data).Scan(&id)
	return id, err
}

const profileCols = `id, identifier, uuid, name, organization, payload_types, source, data, created_at, updated_at`

func scanProfile(row interface{ Scan(...any) error }) (Profile, error) {
	var p Profile
	err := row.Scan(&p.ID, &p.Identifier, &p.UUID, &p.Name, &p.Organization,
		&p.PayloadTypes, &p.Source, &p.Data, &p.CreatedAt, &p.UpdatedAt)
	return p, err
}

// ListProfiles returns the library ordered by name.
func (db *DB) ListProfiles(ctx context.Context) ([]Profile, error) {
	rows, err := db.sql.QueryContext(ctx,
		`SELECT `+profileCols+` FROM profiles ORDER BY name COLLATE NOCASE`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Profile
	for rows.Next() {
		p, err := scanProfile(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// GetProfile returns one profile by row ID, or sql.ErrNoRows.
func (db *DB) GetProfile(ctx context.Context, id int64) (Profile, error) {
	return scanProfile(db.sql.QueryRowContext(ctx,
		`SELECT `+profileCols+` FROM profiles WHERE id = ?`, id))
}

// DeleteProfile removes a profile from the library. Devices that already have
// it installed keep it — removal from devices is a RemoveProfile command.
func (db *DB) DeleteProfile(ctx context.Context, id int64) error {
	res, err := db.sql.ExecContext(ctx, `DELETE FROM profiles WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	return nil
}
