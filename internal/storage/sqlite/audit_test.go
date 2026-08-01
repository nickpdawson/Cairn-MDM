package sqlite

import (
	"context"
	"testing"
)

func TestAppendAndListAudit(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	entries := []AuditEntry{
		{Username: "nick", Provider: "local", Action: "POST", Target: "/login", Result: "302", Remote: "203.0.113.1"},
		{Username: "nick", Provider: "local", Action: "POST", Target: "/admin/groups", Result: "303", Remote: "203.0.113.1"},
		{Username: "nick", Provider: "local", Action: "POST", Target: "/admin/groups/1/delete", Result: "303", Remote: "203.0.113.1"},
	}
	for _, e := range entries {
		if err := db.AppendAudit(ctx, e); err != nil {
			t.Fatalf("AppendAudit(%q): %v", e.Target, err)
		}
	}

	got, err := db.ListAudit(ctx, 200)
	if err != nil {
		t.Fatalf("ListAudit: %v", err)
	}
	if len(got) != len(entries) {
		t.Fatalf("ListAudit returned %d rows, want %d", len(got), len(entries))
	}

	// Newest first: the last appended row leads the list.
	if got[0].Target != "/admin/groups/1/delete" {
		t.Errorf("newest row = %q, want /admin/groups/1/delete", got[0].Target)
	}
	if got[len(got)-1].Target != "/login" {
		t.Errorf("oldest row = %q, want /login", got[len(got)-1].Target)
	}

	// Fields round-trip and the table stamps a timestamp.
	first := got[0]
	if first.Username != "nick" || first.Provider != "local" || first.Action != "POST" || first.Result != "303" || first.Remote != "203.0.113.1" {
		t.Errorf("field round-trip mismatch: %+v", first)
	}
	if first.At == "" {
		t.Error("audit row missing auto-stamped at")
	}
	if first.ID == 0 {
		t.Error("audit row missing id")
	}
}

func TestListAuditDefaultLimit(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	// A non-positive limit must not error and must default (200).
	if _, err := db.ListAudit(ctx, 0); err != nil {
		t.Fatalf("ListAudit(0): %v", err)
	}
	if _, err := db.ListAudit(ctx, -5); err != nil {
		t.Fatalf("ListAudit(-5): %v", err)
	}
}
