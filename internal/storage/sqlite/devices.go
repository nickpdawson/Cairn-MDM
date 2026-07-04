package sqlite

import (
	"context"
	"database/sql"

	"github.com/dzsec/cairn/internal/mdmcore"
)

// Device is a row of the admin device inventory.
type Device struct {
	ID             string
	UDID           string
	Serial         string
	Name           string
	Model          string
	Product        string
	OSVersion      string
	BuildVersion   string
	EnrolledAt     sql.NullString
	LastSeen       sql.NullString
	TokenUpdatedAt sql.NullString
	CheckedOutAt   sql.NullString
}

// DisplayName is the device name if known, else the serial, else the ID.
func (d Device) DisplayName() string {
	switch {
	case d.Name != "":
		return d.Name
	case d.Serial != "":
		return d.Serial
	default:
		return d.ID
	}
}

// Enrolled reports whether the device is currently enrolled (not checked out).
func (d Device) Enrolled() bool { return !d.CheckedOutAt.Valid }

// compile-time check that DB satisfies the projector interface.
var _ mdmcore.DeviceProjector = (*DB)(nil)

// DeviceEnrolled upserts a device on Authenticate, stamping enrolled_at on first
// sight and clearing any prior checkout.
func (db *DB) DeviceEnrolled(ctx context.Context, d mdmcore.DeviceRecord) error {
	_, err := db.sql.ExecContext(ctx,
		`INSERT INTO devices
		   (id, udid, serial, name, model, product, os_version, build_version, enrolled_at, last_seen, checked_out_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'), NULL)
		 ON CONFLICT (id) DO UPDATE SET
		   udid          = excluded.udid,
		   serial        = CASE WHEN excluded.serial <> '' THEN excluded.serial ELSE devices.serial END,
		   name          = CASE WHEN excluded.name   <> '' THEN excluded.name   ELSE devices.name   END,
		   model         = CASE WHEN excluded.model  <> '' THEN excluded.model  ELSE devices.model  END,
		   product       = CASE WHEN excluded.product <> '' THEN excluded.product ELSE devices.product END,
		   os_version    = CASE WHEN excluded.os_version <> '' THEN excluded.os_version ELSE devices.os_version END,
		   build_version = CASE WHEN excluded.build_version <> '' THEN excluded.build_version ELSE devices.build_version END,
		   last_seen     = datetime('now'),
		   checked_out_at = NULL`,
		d.ID, d.UDID, d.Serial, d.Name, d.Model, d.Product, d.OSVersion, d.BuildVersion)
	return err
}

// DeviceTokenUpdated marks a token update (the device is now pushable).
func (db *DB) DeviceTokenUpdated(ctx context.Context, id string) error {
	_, err := db.sql.ExecContext(ctx,
		`UPDATE devices SET token_updated_at = datetime('now'), last_seen = datetime('now'), checked_out_at = NULL WHERE id = ?`, id)
	return err
}

// DeviceCheckedOut marks an unenrollment.
func (db *DB) DeviceCheckedOut(ctx context.Context, id string) error {
	_, err := db.sql.ExecContext(ctx,
		`UPDATE devices SET checked_out_at = datetime('now'), last_seen = datetime('now') WHERE id = ?`, id)
	return err
}

// DeviceCheckedIn refreshes last_seen on any command report.
func (db *DB) DeviceCheckedIn(ctx context.Context, id string) error {
	_, err := db.sql.ExecContext(ctx,
		`UPDATE devices SET last_seen = datetime('now') WHERE id = ?`, id)
	return err
}

// ListDevices returns the inventory ordered by most-recently-seen.
func (db *DB) ListDevices(ctx context.Context) ([]Device, error) {
	rows, err := db.sql.QueryContext(ctx,
		`SELECT id, udid, serial, name, model, product, os_version, build_version,
		        enrolled_at, last_seen, token_updated_at, checked_out_at
		 FROM devices
		 ORDER BY last_seen DESC`)
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

// GetDevice returns one device by ID, or sql.ErrNoRows if absent.
func (db *DB) GetDevice(ctx context.Context, id string) (Device, error) {
	var d Device
	err := db.sql.QueryRowContext(ctx,
		`SELECT id, udid, serial, name, model, product, os_version, build_version,
		        enrolled_at, last_seen, token_updated_at, checked_out_at
		 FROM devices WHERE id = ?`, id).
		Scan(&d.ID, &d.UDID, &d.Serial, &d.Name, &d.Model, &d.Product,
			&d.OSVersion, &d.BuildVersion, &d.EnrolledAt, &d.LastSeen, &d.TokenUpdatedAt, &d.CheckedOutAt)
	return d, err
}

// DeviceCounts returns total and active-within-24h counts for the dashboard.
func (db *DB) DeviceCounts(ctx context.Context) (total, active int, err error) {
	err = db.sql.QueryRowContext(ctx,
		`SELECT
		   count(*),
		   coalesce(sum(CASE WHEN checked_out_at IS NULL AND last_seen >= datetime('now','-1 day') THEN 1 ELSE 0 END), 0)
		 FROM devices`).Scan(&total, &active)
	return total, active, err
}
