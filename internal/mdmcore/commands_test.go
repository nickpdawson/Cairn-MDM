package mdmcore

import (
	"testing"

	"github.com/micromdm/plist"
)

// decodeQueries pulls Command.Queries out of a built command's raw plist.
func decodeQueries(t *testing.T, raw []byte) (string, []any) {
	t.Helper()
	var doc struct {
		Command struct {
			RequestType string
			Queries     []any
		}
	}
	if err := plist.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("unmarshal command: %v", err)
	}
	return doc.Command.RequestType, doc.Command.Queries
}

// A DeviceInformation with no explicit queries must still carry a non-empty
// Queries array — Apple's current schema rejects a missing Queries with
// CommandFormatError (the migration-surfaced bug).
func TestDeviceInformationDefaultQueriesPresent(t *testing.T) {
	cmd, err := DeviceInformationCommand()
	if err != nil {
		t.Fatal(err)
	}
	rt, queries := decodeQueries(t, cmd.Raw)
	if rt != "DeviceInformation" {
		t.Fatalf("RequestType = %q", rt)
	}
	if len(queries) == 0 {
		t.Fatal("default DeviceInformation sent an empty/absent Queries array")
	}
	if len(queries) != len(defaultDeviceInfoQueries) {
		t.Fatalf("got %d queries, want %d", len(queries), len(defaultDeviceInfoQueries))
	}
}

func TestDeviceInformationExplicitQueries(t *testing.T) {
	cmd, err := DeviceInformationCommand("DeviceName", "OSVersion")
	if err != nil {
		t.Fatal(err)
	}
	_, queries := decodeQueries(t, cmd.Raw)
	if len(queries) != 2 || queries[0] != "DeviceName" || queries[1] != "OSVersion" {
		t.Fatalf("queries = %v, want [DeviceName OSVersion]", queries)
	}
}
