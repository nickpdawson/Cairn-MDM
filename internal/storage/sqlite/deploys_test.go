package sqlite

import (
	"context"
	"testing"

	"github.com/dzsec/cairn/internal/mdmcore"
)

func TestDeployQueries(t *testing.T) {
	ctx := context.Background()
	db, err := Open(ctx, t.TempDir()+"/deploys.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	// Seed a group with two member devices and one assigned profile.
	if err := db.DeviceEnrolled(ctx, mdmcore.DeviceRecord{
		ID: "UDID-A", UDID: "UDID-A", Serial: "C02A", Name: "Ridge",
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.DeviceEnrolled(ctx, mdmcore.DeviceRecord{
		ID: "UDID-B", UDID: "UDID-B", Serial: "C02B", Name: "Summit",
	}); err != nil {
		t.Fatal(err)
	}
	profID, err := db.SaveProfile(ctx, Profile{
		Identifier: "com.example.wifi", UUID: "u-1", Name: "Wi-Fi",
		PayloadTypes: "com.apple.wifi.managed", Source: "upload", Data: []byte("v1"),
	})
	if err != nil {
		t.Fatal(err)
	}
	gid, err := db.CreateGroup(ctx, "Field", "")
	if err != nil {
		t.Fatal(err)
	}
	for _, dev := range []string{"UDID-A", "UDID-B"} {
		if err := db.AddDeviceToGroup(ctx, gid, dev); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.AssignProfile(ctx, gid, profID); err != nil {
		t.Fatal(err)
	}

	// Two deploy rows: A installed, B failed. (C is not a member and has only a
	// sent row — it must not count toward the group rollup.)
	if _, err := db.SQL().ExecContext(ctx,
		`INSERT INTO profile_deploys (device_id, profile_id, command_uuid, profile_updated_at, status, updated_at)
		 VALUES ('UDID-A', ?, 'cmd-a', 'v1', 'installed', datetime('now')),
		        ('UDID-B', ?, 'cmd-b', 'v1', 'failed',    datetime('now')),
		        ('UDID-C', ?, 'cmd-c', 'v1', 'sent',      datetime('now'))`,
		profID, profID, profID); err != nil {
		t.Fatal(err)
	}

	// DeviceDeploys for A: one profile, installed.
	dd, err := db.DeviceDeploys(ctx, "UDID-A")
	if err != nil {
		t.Fatal(err)
	}
	if len(dd) != 1 {
		t.Fatalf("DeviceDeploys(A) = %d rows, want 1", len(dd))
	}
	if dd[0].ProfileID != profID || dd[0].ProfileName != "Wi-Fi" || dd[0].Status != "installed" {
		t.Errorf("DeviceDeploys(A)[0] = %+v", dd[0])
	}
	if dd[0].UpdatedAt == "" {
		t.Error("DeviceDeploys(A)[0] missing updated_at")
	}

	// ProfileDeploys: three devices, display name falls back to serial for A/B
	// and to the raw id for the non-enrolled C.
	pd, err := db.ProfileDeploys(ctx, profID)
	if err != nil {
		t.Fatal(err)
	}
	if len(pd) != 3 {
		t.Fatalf("ProfileDeploys = %d rows, want 3", len(pd))
	}
	byDev := map[string]ProfileDeploy{}
	for _, p := range pd {
		byDev[p.DeviceID] = p
	}
	if got := byDev["UDID-A"]; got.Status != "installed" || got.DeviceName != "Ridge" {
		t.Errorf("ProfileDeploys[A] = %+v", got)
	}
	if got := byDev["UDID-C"]; got.Status != "sent" || got.DeviceName != "UDID-C" {
		t.Errorf("ProfileDeploys[C] fallback name/status = %+v", got)
	}

	// GroupDeployStatus: only A (installed) and B (failed) are members; C is not.
	gs, err := db.GroupDeployStatus(ctx, gid)
	if err != nil {
		t.Fatal(err)
	}
	if len(gs) != 1 {
		t.Fatalf("GroupDeployStatus = %d rows, want 1", len(gs))
	}
	s := gs[0]
	if s.ProfileID != profID || s.Installed != 1 || s.Pending != 0 || s.Failed != 1 {
		t.Errorf("GroupDeployStatus[0] = %+v, want installed=1 pending=0 failed=1", s)
	}
}
