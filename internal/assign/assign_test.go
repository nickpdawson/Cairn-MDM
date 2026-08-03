package assign

import (
	"context"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/nickpdawson/cairn-mdm/internal/mdmcore"
	"github.com/nickpdawson/cairn-mdm/internal/storage/sqlite"
)

// fakeCommander records InstallProfile sends instead of enqueueing/pushing.
type fakeCommander struct {
	mu    sync.Mutex
	sends []send
	n     int
}

type send struct {
	device string
	data   string
	uuid   string
}

func (f *fakeCommander) SendInstallProfileUUID(_ context.Context, profile []byte, id string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.n++
	uuid := "cmd-" + string(rune('a'+f.n-1))
	f.sends = append(f.sends, send{device: id, data: string(profile), uuid: uuid})
	return uuid, nil
}

func (f *fakeCommander) all() []send {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]send(nil), f.sends...)
}

func TestReconcileLifecycle(t *testing.T) {
	ctx := context.Background()
	db, err := sqlite.Open(ctx, t.TempDir()+"/assign.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	// An enrolled, pushable device.
	if err := db.DeviceEnrolled(ctx, mdmcore.DeviceRecord{ID: "UDID-1", UDID: "UDID-1", Name: "Test Mac"}); err != nil {
		t.Fatal(err)
	}
	if err := db.DeviceTokenUpdated(ctx, "UDID-1"); err != nil {
		t.Fatal(err)
	}

	// A profile assigned to a group the device is in.
	pid, err := db.SaveProfile(ctx, sqlite.Profile{
		Identifier: "com.example.wifi", UUID: "u1", Name: "Wi-Fi", Data: []byte("v1"), Source: "upload",
	})
	if err != nil {
		t.Fatal(err)
	}
	gid, err := db.CreateGroup(ctx, "Laptops", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AddDeviceToGroup(ctx, gid, "UDID-1"); err != nil {
		t.Fatal(err)
	}
	if err := db.AssignProfile(ctx, gid, pid); err != nil {
		t.Fatal(err)
	}

	cmd := &fakeCommander{}
	rec := New(db, cmd, slog.New(slog.NewTextHandler(io.Discard, nil)))

	// First reconcile pushes the profile once.
	if err := rec.ReconcileDevice(ctx, "UDID-1"); err != nil {
		t.Fatal(err)
	}
	sends := cmd.all()
	if len(sends) != 1 || sends[0].device != "UDID-1" || sends[0].data != "v1" {
		t.Fatalf("first reconcile sends = %+v, want one v1 push", sends)
	}

	// Second reconcile is a no-op (deploy recorded).
	if err := rec.ReconcileDevice(ctx, "UDID-1"); err != nil {
		t.Fatal(err)
	}
	if len(cmd.all()) != 1 {
		t.Fatalf("reconcile is not idempotent: %d sends", len(cmd.all()))
	}

	// Device acknowledges → deploy resolves to installed.
	if err := db.CommandResult(ctx, "UDID-1", sends[0].uuid, "Acknowledged", ""); err != nil {
		t.Fatal(err)
	}
	var status string
	if err := db.SQL().QueryRow(
		`SELECT status FROM profile_deploys WHERE device_id = 'UDID-1' AND profile_id = ?`, pid).
		Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "installed" {
		t.Errorf("deploy status = %q, want installed", status)
	}

	// Re-uploading the profile (new version) re-arms the deploy.
	time.Sleep(5 * time.Millisecond) // ensure updated_at (ms resolution) changes
	if _, err := db.SaveProfile(ctx, sqlite.Profile{
		Identifier: "com.example.wifi", UUID: "u2", Name: "Wi-Fi", Data: []byte("v2"), Source: "upload",
	}); err != nil {
		t.Fatal(err)
	}
	if err := rec.ReconcileDevice(ctx, "UDID-1"); err != nil {
		t.Fatal(err)
	}
	sends = cmd.all()
	if len(sends) != 2 || sends[1].data != "v2" {
		t.Fatalf("re-upload did not re-push: %+v", sends)
	}

	// Group fan-out targets only pushable members.
	if err := db.DeviceEnrolled(ctx, mdmcore.DeviceRecord{ID: "UDID-2", UDID: "UDID-2"}); err != nil {
		t.Fatal(err)
	}
	// UDID-2 has no TokenUpdate yet — not pushable.
	if err := db.AddDeviceToGroup(ctx, gid, "UDID-2"); err != nil {
		t.Fatal(err)
	}
	ids, err := db.GroupDeviceIDs(ctx, gid)
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 1 || ids[0] != "UDID-1" {
		t.Fatalf("pushable group members = %v, want [UDID-1]", ids)
	}

	// Failed install marks the deploy failed and does NOT auto-retry.
	if err := db.CommandResult(ctx, "UDID-1", sends[1].uuid, "Error", "install refused"); err != nil {
		t.Fatal(err)
	}
	if err := rec.ReconcileDevice(ctx, "UDID-1"); err != nil {
		t.Fatal(err)
	}
	if len(cmd.all()) != 2 {
		t.Fatalf("failed deploy auto-retried: %d sends", len(cmd.all()))
	}
}
