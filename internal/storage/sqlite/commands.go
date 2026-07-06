package sqlite

import (
	"context"
	"database/sql"

	"github.com/dzsec/cairn/internal/mdmcore"
)

// CommandEntry is a row of a device's command history.
type CommandEntry struct {
	CommandUUID string
	DeviceID    string
	RequestType string
	Status      string
	Error       string
	SentAt      string
	ResultAt    sql.NullString
}

// Pending reports whether the device has not yet answered.
func (c CommandEntry) Pending() bool { return c.Status == "Sent" || c.Status == "NotNow" }

// compile-time check that DB records command history.
var _ mdmcore.CommandRecorder = (*DB)(nil)

// CommandSent records a command at enqueue time (one row per target device).
func (db *DB) CommandSent(ctx context.Context, deviceID, commandUUID, requestType string) error {
	_, err := db.sql.ExecContext(ctx,
		`INSERT INTO command_history (command_uuid, device_id, request_type)
		 VALUES (?, ?, ?)
		 ON CONFLICT (command_uuid) DO NOTHING`,
		commandUUID, deviceID, requestType)
	return err
}

// CommandResult resolves a history row when the device reports at check-in.
// Results for commands not sent through Cairn (unknown UUIDs) are ignored.
func (db *DB) CommandResult(ctx context.Context, deviceID, commandUUID, status, errDesc string) error {
	_, err := db.sql.ExecContext(ctx,
		`UPDATE command_history
		 SET status = ?, error = ?, result_at = datetime('now')
		 WHERE command_uuid = ?`,
		status, errDesc, commandUUID)
	return err
}

// ListCommands returns the most recent history for a device.
func (db *DB) ListCommands(ctx context.Context, deviceID string, limit int) ([]CommandEntry, error) {
	if limit <= 0 {
		limit = 25
	}
	rows, err := db.sql.QueryContext(ctx,
		`SELECT command_uuid, device_id, request_type, status, error, sent_at, result_at
		 FROM command_history WHERE device_id = ?
		 ORDER BY sent_at DESC, command_uuid LIMIT ?`, deviceID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CommandEntry
	for rows.Next() {
		var c CommandEntry
		if err := rows.Scan(&c.CommandUUID, &c.DeviceID, &c.RequestType, &c.Status,
			&c.Error, &c.SentAt, &c.ResultAt); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}
