package sqlite

import (
	"context"
	"database/sql"
	"strings"

	"github.com/dzsec/cairn-mdm/internal/mdmcore"
)

// Device is a row of the admin device inventory.
type Device struct {
	ID                string
	UDID              string
	Serial            string
	Name              string
	Model             string
	Product           string
	OSVersion         string
	BuildVersion      string
	AvailableCapacity string
	Battery           string
	EnrolledAt        sql.NullString
	LastSeen          sql.NullString
	TokenUpdatedAt    sql.NullString
	InventoryAt       sql.NullString
	CheckedOutAt      sql.NullString
}

// InventoryObserved is the timestamp of the last DeviceInformation response, or
// "" if the device has never returned one.
func (d Device) InventoryObserved() string {
	if d.InventoryAt.Valid {
		return d.InventoryAt.String
	}
	return ""
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

// DeviceInventory projects a DeviceInformation response's QueryResponses onto
// the row, stamping inventory_at. Each column is overwritten only when the
// incoming value is non-empty (same CASE-WHEN guard as DeviceEnrolled), so a
// partial query response never blanks a previously observed value.
func (db *DB) DeviceInventory(ctx context.Context, id string, inv mdmcore.DeviceInventory) error {
	_, err := db.sql.ExecContext(ctx,
		`UPDATE devices SET
		   name               = CASE WHEN ? <> '' THEN ? ELSE name END,
		   model              = CASE WHEN ? <> '' THEN ? ELSE model END,
		   product            = CASE WHEN ? <> '' THEN ? ELSE product END,
		   os_version         = CASE WHEN ? <> '' THEN ? ELSE os_version END,
		   build_version      = CASE WHEN ? <> '' THEN ? ELSE build_version END,
		   serial             = CASE WHEN ? <> '' THEN ? ELSE serial END,
		   available_capacity = CASE WHEN ? <> '' THEN ? ELSE available_capacity END,
		   battery            = CASE WHEN ? <> '' THEN ? ELSE battery END,
		   inventory_at       = datetime('now')
		 WHERE id = ?`,
		inv.Name, inv.Name,
		inv.Model, inv.Model,
		inv.Product, inv.Product,
		inv.OSVersion, inv.OSVersion,
		inv.BuildVersion, inv.BuildVersion,
		inv.Serial, inv.Serial,
		inv.AvailableCapacity, inv.AvailableCapacity,
		inv.Battery, inv.Battery,
		id)
	return err
}

// ListDevices returns the inventory ordered by most-recently-seen.
func (db *DB) ListDevices(ctx context.Context) ([]Device, error) {
	return db.ListDevicesFiltered(ctx, "", false)
}

// ListDevicesFiltered returns the inventory ordered by most-recently-seen,
// optionally narrowed by a case-insensitive substring match of query against
// name, serial, model, or udid, and by enrolledOnly (checked_out_at IS NULL).
// An empty query applies no text filter. The query is bound as a parameter, so
// it is injection-safe; any LIKE metacharacters in it match literally via an
// explicit ESCAPE clause.
func (db *DB) ListDevicesFiltered(ctx context.Context, query string, enrolledOnly bool) ([]Device, error) {
	sqlStr := `SELECT id, udid, serial, name, model, product, os_version, build_version,
	        available_capacity, battery,
	        enrolled_at, last_seen, token_updated_at, inventory_at, checked_out_at
	 FROM devices`
	var where []string
	var args []any
	if query != "" {
		// Escape LIKE metacharacters so a literal % or _ in the search box does
		// not turn into a wildcard. '\' is the escape character.
		pat := "%" + escapeLike(query) + "%"
		where = append(where,
			`(LOWER(name)   LIKE LOWER(?) ESCAPE '\'
			  OR LOWER(serial) LIKE LOWER(?) ESCAPE '\'
			  OR LOWER(model)  LIKE LOWER(?) ESCAPE '\'
			  OR LOWER(udid)   LIKE LOWER(?) ESCAPE '\')`)
		args = append(args, pat, pat, pat, pat)
	}
	if enrolledOnly {
		where = append(where, `checked_out_at IS NULL`)
	}
	if len(where) > 0 {
		sqlStr += " WHERE " + strings.Join(where, " AND ")
	}
	sqlStr += " ORDER BY last_seen DESC"

	rows, err := db.sql.QueryContext(ctx, sqlStr, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Device
	for rows.Next() {
		var d Device
		if err := rows.Scan(&d.ID, &d.UDID, &d.Serial, &d.Name, &d.Model, &d.Product,
			&d.OSVersion, &d.BuildVersion, &d.AvailableCapacity, &d.Battery,
			&d.EnrolledAt, &d.LastSeen, &d.TokenUpdatedAt, &d.InventoryAt, &d.CheckedOutAt); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// escapeLike escapes the LIKE wildcards (%, _) and the escape character itself
// so user input matches literally under an `ESCAPE '\'` clause.
func escapeLike(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return r.Replace(s)
}

// GetDevice returns one device by ID, or sql.ErrNoRows if absent.
func (db *DB) GetDevice(ctx context.Context, id string) (Device, error) {
	var d Device
	err := db.sql.QueryRowContext(ctx,
		`SELECT id, udid, serial, name, model, product, os_version, build_version,
		        available_capacity, battery,
		        enrolled_at, last_seen, token_updated_at, inventory_at, checked_out_at
		 FROM devices WHERE id = ?`, id).
		Scan(&d.ID, &d.UDID, &d.Serial, &d.Name, &d.Model, &d.Product,
			&d.OSVersion, &d.BuildVersion, &d.AvailableCapacity, &d.Battery,
			&d.EnrolledAt, &d.LastSeen, &d.TokenUpdatedAt, &d.InventoryAt, &d.CheckedOutAt)
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
