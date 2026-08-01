package sqlite

import (
	"context"
	"testing"
)

// TestCommandHistoryCompositeIdentity proves MDM-REL-001 is fixed: the same
// command_uuid issued to two different devices produces two independent history
// rows, a result resolves only the reporting device's row, and per-device
// listing returns the correct row. Before the composite (command_uuid,
// device_id) key, the ON CONFLICT (command_uuid) DO NOTHING dropped every row
// but the first and CommandResult updated whichever single row survived.
func TestCommandHistoryCompositeIdentity(t *testing.T) {
	ctx := context.Background()
	db, err := Open(ctx, t.TempDir()+"/cmd_composite.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	const uuid = "shared-cmd"

	// One command UUID fanned out to two devices: two rows, not one.
	if err := db.CommandSent(ctx, "DEV-A", uuid, "DeviceInformation"); err != nil {
		t.Fatal(err)
	}
	if err := db.CommandSent(ctx, "DEV-B", uuid, "DeviceInformation"); err != nil {
		t.Fatal(err)
	}

	var n int
	if err := db.SQL().QueryRowContext(ctx,
		`SELECT COUNT(*) FROM command_history WHERE command_uuid = ?`, uuid).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("shared command_uuid produced %d rows, want 2 (one per device)", n)
	}

	// A re-send for the same (uuid, device) is idempotent — still two rows.
	if err := db.CommandSent(ctx, "DEV-A", uuid, "DeviceInformation"); err != nil {
		t.Fatal(err)
	}
	if err := db.SQL().QueryRowContext(ctx,
		`SELECT COUNT(*) FROM command_history WHERE command_uuid = ?`, uuid).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("duplicate (uuid, device) send changed row count to %d, want 2", n)
	}

	// A result for (uuid, DEV-A) resolves only DEV-A's row; DEV-B stays pending.
	if err := db.CommandResult(ctx, "DEV-A", uuid, "Acknowledged", ""); err != nil {
		t.Fatal(err)
	}

	a := findEntry(t, db, "DEV-A", uuid)
	if a.Status != "Acknowledged" || !a.ResultAt.Valid || a.Pending() {
		t.Errorf("DEV-A row not resolved: %+v", a)
	}
	b := findEntry(t, db, "DEV-B", uuid)
	if b.Status != "Sent" || b.ResultAt.Valid || !b.Pending() {
		t.Errorf("DEV-B row should still be pending, got: %+v", b)
	}

	// Per-device listing returns each device's own row for the shared UUID.
	listA, err := db.ListCommands(ctx, "DEV-A", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(listA) != 1 || listA[0].DeviceID != "DEV-A" || listA[0].Status != "Acknowledged" {
		t.Errorf("DEV-A listing wrong: %+v", listA)
	}
	listB, err := db.ListCommands(ctx, "DEV-B", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(listB) != 1 || listB[0].DeviceID != "DEV-B" || listB[0].Status != "Sent" {
		t.Errorf("DEV-B listing wrong: %+v", listB)
	}

	// Now resolve DEV-B independently and confirm DEV-A is untouched.
	if err := db.CommandResult(ctx, "DEV-B", uuid, "Error", "boom"); err != nil {
		t.Fatal(err)
	}
	b = findEntry(t, db, "DEV-B", uuid)
	if b.Status != "Error" || b.Error != "boom" || b.Pending() {
		t.Errorf("DEV-B row not resolved: %+v", b)
	}
	a = findEntry(t, db, "DEV-A", uuid)
	if a.Status != "Acknowledged" || a.Error != "" {
		t.Errorf("resolving DEV-B disturbed DEV-A: %+v", a)
	}
}

func findEntry(t *testing.T, db *DB, deviceID, uuid string) CommandEntry {
	t.Helper()
	list, err := db.ListCommands(context.Background(), deviceID, 50)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range list {
		if c.CommandUUID == uuid {
			return c
		}
	}
	t.Fatalf("command %q for device %q not found in history", uuid, deviceID)
	return CommandEntry{}
}
