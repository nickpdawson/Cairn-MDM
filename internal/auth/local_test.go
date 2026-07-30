package auth

import (
	"context"
	"errors"
	"testing"

	"github.com/dzsec/cairn/internal/storage/sqlite"
)

func testStore(t *testing.T) *LocalStore {
	t.Helper()
	db, err := sqlite.Open(context.Background(), t.TempDir()+"/auth.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return NewLocalStore(db.SQL())
}

func TestCreateAndAuthenticate(t *testing.T) {
	ctx := context.Background()
	s := testStore(t)

	if err := s.CreateUser(ctx, "nick", "correct horse battery", RoleAdmin, "Nick"); err != nil {
		t.Fatalf("create: %v", err)
	}

	id, err := s.Authenticate(ctx, "nick", "correct horse battery")
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if id.Role != RoleAdmin || id.Provider != "local" || id.DisplayName != "Nick" {
		t.Errorf("identity = %+v", id)
	}

	if _, err := s.Authenticate(ctx, "nick", "wrong"); !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("wrong password err = %v, want ErrInvalidCredentials", err)
	}
	if _, err := s.Authenticate(ctx, "ghost", "whatever"); !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("missing user err = %v, want ErrInvalidCredentials", err)
	}
}

func TestDuplicateUserRejected(t *testing.T) {
	ctx := context.Background()
	s := testStore(t)
	if err := s.CreateUser(ctx, "a", "pw12345678", RoleOperator, ""); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateUser(ctx, "a", "pw12345678", RoleOperator, ""); err == nil {
		t.Fatal("expected duplicate username to be rejected")
	}
}

func TestCountUsersAndFirstRun(t *testing.T) {
	ctx := context.Background()
	s := testStore(t)
	if n, _ := s.CountUsers(ctx); n != 0 {
		t.Fatalf("fresh store has %d users, want 0", n)
	}
	_ = s.CreateUser(ctx, "a", "pw12345678", RoleAdmin, "")
	if n, _ := s.CountUsers(ctx); n != 1 {
		t.Fatalf("after create: %d users, want 1", n)
	}
}

func TestRoleAtLeast(t *testing.T) {
	if !RoleAdmin.AtLeast(RoleOperator) {
		t.Error("admin should outrank operator")
	}
	if RoleUser.AtLeast(RoleAdmin) {
		t.Error("user should not satisfy admin")
	}
	if !RoleOperator.AtLeast(RoleOperator) {
		t.Error("operator should satisfy operator")
	}
}

func TestListAndDeleteUsers(t *testing.T) {
	ctx := context.Background()
	s := testStore(t)

	if err := s.CreateUser(ctx, "admin1", "hunter2hunter2", RoleAdmin, ""); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateUser(ctx, "op1", "hunter2hunter2", RoleOperator, "Op One"); err != nil {
		t.Fatal(err)
	}

	users, err := s.ListUsers(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(users) != 2 {
		t.Fatalf("got %d users, want 2", len(users))
	}

	// Deleting the last admin is refused.
	if err := s.DeleteUser(ctx, "admin1"); err == nil {
		t.Fatal("deleting the last admin should be refused")
	}

	// A second admin makes the first deletable.
	if err := s.CreateUser(ctx, "admin2", "hunter2hunter2", RoleAdmin, ""); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteUser(ctx, "admin1"); err != nil {
		t.Fatalf("delete admin1 with admin2 present: %v", err)
	}
	if _, err := s.Authenticate(ctx, "admin1", "hunter2hunter2"); err == nil {
		t.Error("deleted user can still authenticate")
	}
	if err := s.DeleteUser(ctx, "nosuch"); err == nil {
		t.Error("deleting unknown user should error")
	}
}
