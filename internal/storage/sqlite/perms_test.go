package sqlite

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// TestOpenRestrictsDBPerms verifies that Open tightens the database file to
// 0600 (MDM-SEC-002). The file holds the CA private key, APNs key, and session
// tokens, so it must not be world- or group-readable.
func TestOpenRestrictsDBPerms(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix file permissions not meaningful on Windows")
	}

	path := filepath.Join(t.TempDir(), "cairn.db")
	db, err := Open(context.Background(), path)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer db.Close()

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat db: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("db perms = %o, want 600", got)
	}

	// WAL/SHM siblings, when present, must be restricted too.
	for _, suffix := range []string{"-wal", "-shm"} {
		si, err := os.Stat(path + suffix)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			t.Fatalf("stat %s: %v", suffix, err)
		}
		if got := si.Mode().Perm(); got != 0o600 {
			t.Errorf("%s perms = %o, want 600", suffix, got)
		}
	}
}
