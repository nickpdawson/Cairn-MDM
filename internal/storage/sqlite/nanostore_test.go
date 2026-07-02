package sqlite

import (
	"context"
	"embed"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/micromdm/nanomdm/test/e2e"
)

// NanoMDM's e2e suite loads a few fixtures via paths relative to its own module
// (../../mdm/testdata/..., ../../test/e2e/testdata/...). We embed copies and lay
// them out in a temp tree, then run the suite from a working directory two
// levels deep so those relative paths resolve. push_cert.txt is NanoMDM's
// test push certificate (no private key), renamed to dodge the repo's *.pem
// ignore rule.
//
//go:embed testdata/Authenticate.2.plist testdata/TokenUpdate.2.plist testdata/push_cert.txt
var fixtures embed.FS

// TestNanoStorageE2E runs NanoMDM's own end-to-end storage suite against the
// SQLite backend. It stands up the real NanoMDM check-in/command HTTP stack,
// enrolls a simulated device, exercises certificate auth, the command queue,
// bootstrap tokens, push certificates, token-update tallies, and the storage
// migrator. If the SQLite kv backend has the protocol semantics wrong, this
// fails — it is the correctness gate for the whole storage layer.
func TestNanoStorageE2E(t *testing.T) {
	ctx := context.Background()

	// Absolute DB path so it is unaffected by the chdir below.
	db, err := Open(ctx, filepath.Join(t.TempDir(), "e2e.db"))
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer db.Close()

	store := db.NanoStorage(slog.New(slog.NewTextHandler(io.Discard, nil)))

	// Reconstruct the fixture layout the suite expects, relative to a working
	// directory two levels deep.
	root := t.TempDir()
	place := func(embedded, rel string) {
		b, err := fixtures.ReadFile(embedded)
		if err != nil {
			t.Fatal(err)
		}
		dst := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(dst, b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	place("testdata/Authenticate.2.plist", "mdm/testdata/Authenticate.2.plist")
	place("testdata/TokenUpdate.2.plist", "mdm/testdata/TokenUpdate.2.plist")
	place("testdata/push_cert.txt", "test/e2e/testdata/push.pem")

	workdir := filepath.Join(root, "a", "b")
	if err := os.MkdirAll(workdir, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Chdir(workdir)

	e2e.TestE2E(t, ctx, store)
}
