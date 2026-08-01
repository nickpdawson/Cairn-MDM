package sqlite

import "context"

// DeviceDeploy is one profile deployed (via group assignment) to a device, with
// its current push status. It joins profile_deploys to the profile library.
type DeviceDeploy struct {
	ProfileID         int64
	ProfileName       string
	ProfileIdentifier string
	Status            string // sent | installed | failed
	UpdatedAt         string
}

// ProfileDeploy is one device a profile has been deployed to, with status.
type ProfileDeploy struct {
	DeviceID   string
	DeviceName string // display name (name, else serial, else id)
	Status     string
	UpdatedAt  string
}

// GroupProfileStatus rolls up the deploy status of one group-assigned profile
// across the group's member devices.
type GroupProfileStatus struct {
	ProfileID         int64
	ProfileName       string
	ProfileIdentifier string
	Installed         int
	Pending           int // status = 'sent' (queued, not yet acknowledged installed)
	Failed            int
}

// DeviceDeploys returns the profiles deployed to a device with status and the
// last update time, newest-updated first.
func (db *DB) DeviceDeploys(ctx context.Context, deviceID string) ([]DeviceDeploy, error) {
	rows, err := db.sql.QueryContext(ctx,
		`SELECT p.id, p.name, p.identifier, dep.status, dep.updated_at
		 FROM profile_deploys dep
		 JOIN profiles p ON p.id = dep.profile_id
		 WHERE dep.device_id = ?
		 ORDER BY dep.updated_at DESC, p.name COLLATE NOCASE`, deviceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DeviceDeploy
	for rows.Next() {
		var d DeviceDeploy
		if err := rows.Scan(&d.ProfileID, &d.ProfileName, &d.ProfileIdentifier, &d.Status, &d.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// ProfileDeploys returns the devices a profile is deployed to with status. It
// LEFT JOINs devices so a deploy row survives even if the device row is gone;
// the display name falls back to serial, then the raw device id.
func (db *DB) ProfileDeploys(ctx context.Context, profileID int64) ([]ProfileDeploy, error) {
	rows, err := db.sql.QueryContext(ctx,
		`SELECT dep.device_id,
		        COALESCE(NULLIF(d.name,''), NULLIF(d.serial,''), dep.device_id) AS display,
		        dep.status, dep.updated_at
		 FROM profile_deploys dep
		 LEFT JOIN devices d ON d.id = dep.device_id
		 WHERE dep.profile_id = ?
		 ORDER BY display COLLATE NOCASE`, profileID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ProfileDeploy
	for rows.Next() {
		var p ProfileDeploy
		if err := rows.Scan(&p.DeviceID, &p.DeviceName, &p.Status, &p.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// GroupDeployStatus returns, for each profile assigned to a group, the count of
// member devices whose deploy is installed / pending (sent) / failed. Devices
// with no deploy row yet count toward none of the three.
func (db *DB) GroupDeployStatus(ctx context.Context, groupID int64) ([]GroupProfileStatus, error) {
	rows, err := db.sql.QueryContext(ctx,
		`SELECT p.id, p.name, p.identifier,
		        COALESCE(SUM(CASE WHEN dep.status = 'installed' THEN 1 ELSE 0 END), 0) AS installed,
		        COALESCE(SUM(CASE WHEN dep.status = 'sent'      THEN 1 ELSE 0 END), 0) AS pending,
		        COALESCE(SUM(CASE WHEN dep.status = 'failed'    THEN 1 ELSE 0 END), 0) AS failed
		 FROM group_profiles gp
		 JOIN profiles p ON p.id = gp.profile_id
		 LEFT JOIN group_devices gd ON gd.group_id = gp.group_id
		 LEFT JOIN profile_deploys dep ON dep.profile_id = p.id AND dep.device_id = gd.device_id
		 WHERE gp.group_id = ?
		 GROUP BY p.id
		 ORDER BY p.name COLLATE NOCASE`, groupID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []GroupProfileStatus
	for rows.Next() {
		var s GroupProfileStatus
		if err := rows.Scan(&s.ProfileID, &s.ProfileName, &s.ProfileIdentifier, &s.Installed, &s.Pending, &s.Failed); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}
