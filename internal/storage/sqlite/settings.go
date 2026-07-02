package sqlite

import (
	"context"
	"database/sql"
	"errors"
)

// ErrSettingNotFound is returned by GetSetting when the key is absent.
var ErrSettingNotFound = errors.New("setting not found")

// SetSetting upserts a key/value into the settings table.
func (db *DB) SetSetting(ctx context.Context, key, value string) error {
	_, err := db.sql.ExecContext(ctx,
		`INSERT INTO settings (key, value) VALUES (?, ?)
		 ON CONFLICT (key) DO UPDATE SET value = excluded.value, updated_at = datetime('now')`,
		key, value)
	return err
}

// GetSetting returns the value for key, or ErrSettingNotFound.
func (db *DB) GetSetting(ctx context.Context, key string) (string, error) {
	var v string
	err := db.sql.QueryRowContext(ctx, `SELECT value FROM settings WHERE key = ?`, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrSettingNotFound
	}
	return v, err
}
