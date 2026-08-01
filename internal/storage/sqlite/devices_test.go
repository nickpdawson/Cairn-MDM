package sqlite

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/micromdm/nanomdm/mdm"

	"github.com/dzsec/cairn/internal/mdmcore"
)

// stubService is a no-op inner NanoMDM service so the EventService decorator can
// be exercised without a full protocol stack.
type stubService struct{}

func (stubService) Authenticate(*mdm.Request, *mdm.Authenticate) error { return nil }
func (stubService) TokenUpdate(*mdm.Request, *mdm.TokenUpdate) error   { return nil }
func (stubService) CheckOut(*mdm.Request, *mdm.CheckOut) error         { return nil }
func (stubService) SetBootstrapToken(*mdm.Request, *mdm.SetBootstrapToken) error {
	return nil
}
func (stubService) GetBootstrapToken(*mdm.Request, *mdm.GetBootstrapToken) (*mdm.BootstrapToken, error) {
	return nil, nil
}
func (stubService) UserAuthenticate(*mdm.Request, *mdm.UserAuthenticate) ([]byte, error) {
	return nil, nil
}
func (stubService) DeclarativeManagement(*mdm.Request, *mdm.DeclarativeManagement) ([]byte, error) {
	return nil, nil
}
func (stubService) GetToken(*mdm.Request, *mdm.GetToken) (*mdm.GetTokenResponse, error) {
	return nil, nil
}
func (stubService) CommandAndReportResults(*mdm.Request, *mdm.CommandResults) (*mdm.Command, error) {
	return nil, nil
}

func req(id string) *mdm.Request {
	return &mdm.Request{EnrollID: &mdm.EnrollID{Type: mdm.Device, ID: id}}
}

func TestDeviceProjectionLifecycle(t *testing.T) {
	ctx := context.Background()
	db, err := Open(ctx, t.TempDir()+"/dev.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	svc := mdmcore.NewEventService(stubService{}, db, db, slog.New(slog.NewTextHandler(io.Discard, nil)))

	// Authenticate — device appears in inventory with attributes parsed from Raw.
	rawAuth := []byte(`<?xml version="1.0"?><plist version="1.0"><dict>
	  <key>MessageType</key><string>Authenticate</string>
	  <key>UDID</key><string>UDID-1</string>
	  <key>DeviceName</key><string>Ridge MBP</string>
	  <key>Model</key><string>MacBookPro18,2</string>
	  <key>ProductName</key><string>Mac14,7</string>
	  <key>OSVersion</key><string>15.5</string>
	  <key>SerialNumber</key><string>C02XYZ</string>
	</dict></plist>`)
	if err := svc.Authenticate(req("UDID-1"), &mdm.Authenticate{
		Enrollment: mdm.Enrollment{UDID: "UDID-1"}, SerialNumber: "C02XYZ", Raw: rawAuth,
	}); err != nil {
		t.Fatalf("authenticate: %v", err)
	}

	devs, err := db.ListDevices(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(devs) != 1 {
		t.Fatalf("got %d devices, want 1", len(devs))
	}
	d := devs[0]
	if d.Name != "Ridge MBP" || d.Model != "MacBookPro18,2" || d.OSVersion != "15.5" || d.Serial != "C02XYZ" {
		t.Errorf("attributes not projected from Raw: %+v", d)
	}
	if !d.Enrolled() {
		t.Error("device should be enrolled after Authenticate")
	}

	// TokenUpdate — pushable timestamp set.
	if err := svc.TokenUpdate(req("UDID-1"), &mdm.TokenUpdate{Enrollment: mdm.Enrollment{UDID: "UDID-1"}}); err != nil {
		t.Fatal(err)
	}
	devs, _ = db.ListDevices(ctx)
	if !devs[0].TokenUpdatedAt.Valid {
		t.Error("token_updated_at should be set after TokenUpdate")
	}

	total, active, err := db.DeviceCounts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if total != 1 || active != 1 {
		t.Errorf("counts total=%d active=%d, want 1/1", total, active)
	}

	// DeviceInformation result — QueryResponses projected onto the inventory.
	rawInfo := []byte(`<?xml version="1.0"?><plist version="1.0"><dict>
	  <key>Status</key><string>Acknowledged</string>
	  <key>CommandUUID</key><string>CMD-INFO</string>
	  <key>QueryResponses</key><dict>
	    <key>DeviceName</key><string>Ridge Pro</string>
	    <key>Model</key><string>Mac14,7</string>
	    <key>ProductName</key><string>Mac14,7</string>
	    <key>OSVersion</key><string>15.6</string>
	    <key>BuildVersion</key><string>24G84</string>
	    <key>SerialNumber</key><string>C02XYZ</string>
	    <key>AvailableDeviceCapacity</key><real>123.45</real>
	    <key>BatteryLevel</key><real>0.87</real>
	  </dict>
	</dict></plist>`)
	if _, err := svc.CommandAndReportResults(req("UDID-1"), &mdm.CommandResults{
		Enrollment: mdm.Enrollment{UDID: "UDID-1"}, CommandUUID: "CMD-INFO", Status: "Acknowledged", Raw: rawInfo,
	}); err != nil {
		t.Fatalf("command results (info): %v", err)
	}
	d, err = db.GetDevice(ctx, "UDID-1")
	if err != nil {
		t.Fatal(err)
	}
	if d.Name != "Ridge Pro" || d.OSVersion != "15.6" || d.BuildVersion != "24G84" {
		t.Errorf("inventory not projected from QueryResponses: %+v", d)
	}
	if d.AvailableCapacity != "123.45" || d.Battery != "0.87" {
		t.Errorf("numeric query values not projected: capacity=%q battery=%q", d.AvailableCapacity, d.Battery)
	}
	if !d.InventoryAt.Valid {
		t.Error("inventory_at should be set after a DeviceInformation result")
	}

	// A result with no QueryResponses (an ordinary acknowledgement) must not
	// clobber the inventory columns.
	rawAck := []byte(`<?xml version="1.0"?><plist version="1.0"><dict>
	  <key>Status</key><string>Acknowledged</string>
	  <key>CommandUUID</key><string>CMD-ACK</string>
	</dict></plist>`)
	if _, err := svc.CommandAndReportResults(req("UDID-1"), &mdm.CommandResults{
		Enrollment: mdm.Enrollment{UDID: "UDID-1"}, CommandUUID: "CMD-ACK", Status: "Acknowledged", Raw: rawAck,
	}); err != nil {
		t.Fatalf("command results (ack): %v", err)
	}
	d, err = db.GetDevice(ctx, "UDID-1")
	if err != nil {
		t.Fatal(err)
	}
	if d.Name != "Ridge Pro" || d.OSVersion != "15.6" || d.AvailableCapacity != "123.45" || d.Battery != "0.87" {
		t.Errorf("non-DeviceInformation result clobbered inventory: %+v", d)
	}

	// CheckOut — no longer enrolled.
	if err := svc.CheckOut(req("UDID-1"), &mdm.CheckOut{Enrollment: mdm.Enrollment{UDID: "UDID-1"}}); err != nil {
		t.Fatal(err)
	}
	devs, _ = db.ListDevices(ctx)
	if devs[0].Enrolled() {
		t.Error("device should not be enrolled after CheckOut")
	}
}
