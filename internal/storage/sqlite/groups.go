package sqlite

import (
	"context"
	"database/sql"
)

// Group is a device group with display counts.
type Group struct {
	ID           int64
	Name         string
	Description  string
	CreatedAt    string
	DeviceCount  int
	ProfileCount int
}

// CreateGroup creates a group and returns its ID.
func (db *DB) CreateGroup(ctx context.Context, name, description string) (int64, error) {
	res, err := db.sql.ExecContext(ctx,
		`INSERT INTO groups (name, description) VALUES (?, ?)`, name, description)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

const groupCols = `g.id, g.name, g.description, g.created_at,
	(SELECT count(*) FROM group_devices  gd WHERE gd.group_id = g.id),
	(SELECT count(*) FROM group_profiles gp WHERE gp.group_id = g.id)`

// ListGroups returns all groups with membership counts, by name.
func (db *DB) ListGroups(ctx context.Context) ([]Group, error) {
	rows, err := db.sql.QueryContext(ctx,
		`SELECT `+groupCols+` FROM groups g ORDER BY g.name COLLATE NOCASE`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Group
	for rows.Next() {
		var g Group
		if err := rows.Scan(&g.ID, &g.Name, &g.Description, &g.CreatedAt, &g.DeviceCount, &g.ProfileCount); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// GetGroup returns one group, or sql.ErrNoRows.
func (db *DB) GetGroup(ctx context.Context, id int64) (Group, error) {
	var g Group
	err := db.sql.QueryRowContext(ctx,
		`SELECT `+groupCols+` FROM groups g WHERE g.id = ?`, id).
		Scan(&g.ID, &g.Name, &g.Description, &g.CreatedAt, &g.DeviceCount, &g.ProfileCount)
	return g, err
}

// DeleteGroup removes a group; memberships and assignments cascade.
func (db *DB) DeleteGroup(ctx context.Context, id int64) error {
	res, err := db.sql.ExecContext(ctx, `DELETE FROM groups WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// AddDeviceToGroup adds a device (idempotent).
func (db *DB) AddDeviceToGroup(ctx context.Context, groupID int64, deviceID string) error {
	_, err := db.sql.ExecContext(ctx,
		`INSERT INTO group_devices (group_id, device_id) VALUES (?, ?)
		 ON CONFLICT DO NOTHING`, groupID, deviceID)
	return err
}

// RemoveDeviceFromGroup removes a device. Profiles already installed stay on
// the device (removal is an explicit RemoveProfile command, never implicit).
func (db *DB) RemoveDeviceFromGroup(ctx context.Context, groupID int64, deviceID string) error {
	_, err := db.sql.ExecContext(ctx,
		`DELETE FROM group_devices WHERE group_id = ? AND device_id = ?`, groupID, deviceID)
	return err
}

// AssignProfile assigns a profile to a group (idempotent).
func (db *DB) AssignProfile(ctx context.Context, groupID, profileID int64) error {
	_, err := db.sql.ExecContext(ctx,
		`INSERT INTO group_profiles (group_id, profile_id) VALUES (?, ?)
		 ON CONFLICT DO NOTHING`, groupID, profileID)
	return err
}

// UnassignProfile removes an assignment (installed copies stay on devices).
func (db *DB) UnassignProfile(ctx context.Context, groupID, profileID int64) error {
	_, err := db.sql.ExecContext(ctx,
		`DELETE FROM group_profiles WHERE group_id = ? AND profile_id = ?`, groupID, profileID)
	return err
}

// GroupDevices lists the devices in a group.
func (db *DB) GroupDevices(ctx context.Context, groupID int64) ([]Device, error) {
	rows, err := db.sql.QueryContext(ctx,
		`SELECT d.id, d.udid, d.serial, d.name, d.model, d.product, d.os_version, d.build_version,
		        d.enrolled_at, d.last_seen, d.token_updated_at, d.checked_out_at
		 FROM devices d JOIN group_devices gd ON gd.device_id = d.id
		 WHERE gd.group_id = ? ORDER BY d.name COLLATE NOCASE`, groupID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Device
	for rows.Next() {
		var d Device
		if err := rows.Scan(&d.ID, &d.UDID, &d.Serial, &d.Name, &d.Model, &d.Product,
			&d.OSVersion, &d.BuildVersion, &d.EnrolledAt, &d.LastSeen, &d.TokenUpdatedAt, &d.CheckedOutAt); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// GroupProfiles lists the profiles assigned to a group.
func (db *DB) GroupProfiles(ctx context.Context, groupID int64) ([]Profile, error) {
	rows, err := db.sql.QueryContext(ctx,
		`SELECT `+prefixedProfileCols("p")+`
		 FROM profiles p JOIN group_profiles gp ON gp.profile_id = p.id
		 WHERE gp.group_id = ? ORDER BY p.name COLLATE NOCASE`, groupID)
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

// DeviceGroups lists the groups a device belongs to.
func (db *DB) DeviceGroups(ctx context.Context, deviceID string) ([]Group, error) {
	rows, err := db.sql.QueryContext(ctx,
		`SELECT `+groupCols+`
		 FROM groups g JOIN group_devices gd ON gd.group_id = g.id
		 WHERE gd.device_id = ? ORDER BY g.name COLLATE NOCASE`, deviceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Group
	for rows.Next() {
		var g Group
		if err := rows.Scan(&g.ID, &g.Name, &g.Description, &g.CreatedAt, &g.DeviceCount, &g.ProfileCount); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// GroupDeviceIDs returns the pushable devices in a group (enrolled with a
// push token) — the reconciler's fan-out set after an assignment change.
func (db *DB) GroupDeviceIDs(ctx context.Context, groupID int64) ([]string, error) {
	rows, err := db.sql.QueryContext(ctx,
		`SELECT d.id FROM devices d JOIN group_devices gd ON gd.device_id = d.id
		 WHERE gd.group_id = ? AND d.checked_out_at IS NULL AND d.token_updated_at IS NOT NULL`, groupID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// ProfilesToDeploy returns the assigned profiles a device is missing: no deploy
// record yet, or the profile changed since it was last sent. Failed deploys are
// not retried automatically — a re-upload (which bumps updated_at) re-arms them.
func (db *DB) ProfilesToDeploy(ctx context.Context, deviceID string) ([]Profile, error) {
	rows, err := db.sql.QueryContext(ctx,
		`SELECT `+prefixedProfileCols("p")+`
		 FROM profiles p
		 JOIN group_profiles gp ON gp.profile_id = p.id
		 JOIN group_devices  gd ON gd.group_id = gp.group_id
		 LEFT JOIN profile_deploys dep ON dep.profile_id = p.id AND dep.device_id = gd.device_id
		 WHERE gd.device_id = ?
		   AND (dep.profile_id IS NULL OR dep.profile_updated_at <> p.updated_at)
		 GROUP BY p.id`, deviceID)
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

// MarkDeploySent records that a profile version was sent to a device.
func (db *DB) MarkDeploySent(ctx context.Context, deviceID string, profileID int64, commandUUID, profileUpdatedAt string) error {
	_, err := db.sql.ExecContext(ctx,
		`INSERT INTO profile_deploys (device_id, profile_id, command_uuid, profile_updated_at, status, updated_at)
		 VALUES (?, ?, ?, ?, 'sent', datetime('now'))
		 ON CONFLICT (device_id, profile_id) DO UPDATE SET
		   command_uuid = excluded.command_uuid,
		   profile_updated_at = excluded.profile_updated_at,
		   status = 'sent',
		   updated_at = datetime('now')`,
		deviceID, profileID, commandUUID, profileUpdatedAt)
	return err
}

// prefixedProfileCols returns profileCols with a table alias prefix.
func prefixedProfileCols(alias string) string {
	return alias + ".id, " + alias + ".identifier, " + alias + ".uuid, " + alias + ".name, " +
		alias + ".organization, " + alias + ".payload_types, " + alias + ".source, " +
		alias + ".data, " + alias + ".created_at, " + alias + ".updated_at"
}
