package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"testing"
)

func TestProfileLibraryCRUD(t *testing.T) {
	ctx := context.Background()
	db, err := Open(ctx, t.TempDir()+"/profiles.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	id1, err := db.SaveProfile(ctx, Profile{
		Identifier: "com.example.wifi", UUID: "u-1", Name: "Wi-Fi",
		PayloadTypes: "com.apple.wifi.managed", Source: "upload", Data: []byte("v1"),
	})
	if err != nil {
		t.Fatalf("save: %v", err)
	}

	// Same identifier upserts in place (device replacement semantics).
	id2, err := db.SaveProfile(ctx, Profile{
		Identifier: "com.example.wifi", UUID: "u-2", Name: "Wi-Fi v2",
		PayloadTypes: "com.apple.wifi.managed", Source: "upload", Data: []byte("v2"),
	})
	if err != nil {
		t.Fatalf("re-save: %v", err)
	}
	if id1 != id2 {
		t.Errorf("upsert created a new row: %d != %d", id1, id2)
	}

	p, err := db.GetProfile(ctx, id1)
	if err != nil {
		t.Fatal(err)
	}
	if p.Name != "Wi-Fi v2" || string(p.Data) != "v2" || p.UUID != "u-2" {
		t.Errorf("upsert did not replace fields: %+v", p)
	}

	if _, err := db.SaveProfile(ctx, Profile{Identifier: "com.example.sso", UUID: "u-3", Name: "SSO", Data: []byte("x"), Source: "builder:kerberos-sso"}); err != nil {
		t.Fatal(err)
	}
	list, err := db.ListProfiles(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 {
		t.Fatalf("got %d profiles, want 2", len(list))
	}
	if list[0].Name != "SSO" { // NOCASE name order
		t.Errorf("order wrong: %s first", list[0].Name)
	}

	if err := db.DeleteProfile(ctx, id1); err != nil {
		t.Fatal(err)
	}
	if _, err := db.GetProfile(ctx, id1); !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("deleted profile still readable, err=%v", err)
	}
	if err := db.DeleteProfile(ctx, id1); !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("double delete err=%v, want ErrNoRows", err)
	}
}

func TestCommandHistory(t *testing.T) {
	ctx := context.Background()
	db, err := Open(ctx, t.TempDir()+"/cmd.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	if err := db.CommandSent(ctx, "UDID-1", "cmd-1", "DeviceInformation"); err != nil {
		t.Fatal(err)
	}
	if err := db.CommandSent(ctx, "UDID-1", "cmd-2", "InstallProfile"); err != nil {
		t.Fatal(err)
	}

	list, err := db.ListCommands(ctx, "UDID-1", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 {
		t.Fatalf("got %d entries, want 2", len(list))
	}
	for _, c := range list {
		if !c.Pending() || c.Status != "Sent" {
			t.Errorf("fresh command not pending: %+v", c)
		}
	}

	if err := db.CommandResult(ctx, "UDID-1", "cmd-2", "Error", "profile install failed"); err != nil {
		t.Fatal(err)
	}
	list, _ = db.ListCommands(ctx, "UDID-1", 10)
	var found bool
	for _, c := range list {
		if c.CommandUUID == "cmd-2" {
			found = true
			if c.Status != "Error" || c.Error != "profile install failed" || !c.ResultAt.Valid || c.Pending() {
				t.Errorf("result not recorded: %+v", c)
			}
		}
	}
	if !found {
		t.Fatal("cmd-2 missing from history")
	}

	// Results for commands Cairn didn't send are ignored, not errors.
	if err := db.CommandResult(ctx, "UDID-1", "unknown-uuid", "Acknowledged", ""); err != nil {
		t.Errorf("unknown-uuid result should be a no-op, got %v", err)
	}
}
