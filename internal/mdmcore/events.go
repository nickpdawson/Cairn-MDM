package mdmcore

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"

	"github.com/micromdm/nanomdm/mdm"
	"github.com/micromdm/nanomdm/service"
	"github.com/micromdm/plist"
)

// DeviceRecord is the projection of a device's identity captured at check-in
// time. It feeds the admin inventory so the UI never has to parse NanoMDM's
// stored plists or poll the device.
type DeviceRecord struct {
	ID           string // enrollment ID (UDID on the device channel)
	UDID         string
	Serial       string
	Name         string
	Model        string
	Product      string
	OSVersion    string
	BuildVersion string
	Topic        string
}

// DeviceInventory is the projection of a DeviceInformation command's
// QueryResponses. Unlike DeviceRecord (captured at Authenticate), this is the
// fresh inventory the console's "Refresh device info" button asks for. Empty
// fields mean the device did not return that query and must not overwrite a
// previously observed value.
type DeviceInventory struct {
	Name              string
	Model             string
	Product           string
	OSVersion         string
	BuildVersion      string
	Serial            string
	AvailableCapacity string // AvailableDeviceCapacity, formatted
	Battery           string // BatteryLevel, formatted
}

// DeviceProjector persists device-inventory changes derived from check-ins.
// The SQLite storage implements it. This replaces v1's 30-second polling loop:
// enrollment and token-update events update the inventory the moment they happen.
type DeviceProjector interface {
	DeviceEnrolled(ctx context.Context, d DeviceRecord) error
	DeviceTokenUpdated(ctx context.Context, id string) error
	DeviceCheckedOut(ctx context.Context, id string) error
	DeviceCheckedIn(ctx context.Context, id string) error
	// DeviceInventory projects a DeviceInformation response's QueryResponses,
	// overwriting only the columns whose incoming value is non-empty and
	// stamping inventory_at.
	DeviceInventory(ctx context.Context, id string, inv DeviceInventory) error
}

// EventService decorates a NanoMDM service: it delegates every call to the inner
// service (which persists protocol state) and, on success, updates the device
// projection. Embedding the interface means we inherit all methods and override
// only the ones we care about.
type EventService struct {
	service.CheckinAndCommandService
	proj DeviceProjector
	rec  CommandRecorder
	log  *slog.Logger

	// onPushable, if set, is called (in its own goroutine) whenever a device
	// completes a TokenUpdate — i.e. it just became pushable. The assignment
	// reconciler hooks here to auto-push assigned profiles on enrollment.
	onPushable func(id string)
}

// NewEventService wraps inner with projection + history side effects. proj and
// rec may be nil.
func NewEventService(inner service.CheckinAndCommandService, proj DeviceProjector, rec CommandRecorder, log *slog.Logger) *EventService {
	return &EventService{CheckinAndCommandService: inner, proj: proj, rec: rec, log: log}
}

// OnPushable registers the became-pushable hook (see field doc).
func (s *EventService) OnPushable(fn func(id string)) { s.onPushable = fn }

func (s *EventService) Authenticate(r *mdm.Request, m *mdm.Authenticate) error {
	if err := s.CheckinAndCommandService.Authenticate(r, m); err != nil {
		return err
	}
	rec := DeviceRecord{
		ID:     r.ID,
		UDID:   m.UDID,
		Serial: m.SerialNumber,
		Topic:  m.Topic,
	}
	enrichFromRaw(&rec, m.Raw)
	if s.proj != nil {
		if err := s.proj.DeviceEnrolled(r.Context(), rec); err != nil {
			s.log.Warn("device projection (enroll) failed", "id", r.ID, "err", err)
		}
	}
	return nil
}

func (s *EventService) TokenUpdate(r *mdm.Request, m *mdm.TokenUpdate) error {
	if err := s.CheckinAndCommandService.TokenUpdate(r, m); err != nil {
		return err
	}
	if s.proj != nil {
		if err := s.proj.DeviceTokenUpdated(r.Context(), r.ID); err != nil {
			s.log.Warn("device projection (token update) failed", "id", r.ID, "err", err)
		}
	}
	// The device can now receive pushes — run the hook off the request path so
	// reconciliation (enqueue + APNs) never delays the check-in response.
	if s.onPushable != nil {
		go s.onPushable(r.ID)
	}
	return nil
}

func (s *EventService) CheckOut(r *mdm.Request, m *mdm.CheckOut) error {
	if err := s.CheckinAndCommandService.CheckOut(r, m); err != nil {
		return err
	}
	if s.proj != nil {
		if err := s.proj.DeviceCheckedOut(r.Context(), r.ID); err != nil {
			s.log.Warn("device projection (checkout) failed", "id", r.ID, "err", err)
		}
	}
	return nil
}

func (s *EventService) CommandAndReportResults(r *mdm.Request, m *mdm.CommandResults) (*mdm.Command, error) {
	cmd, err := s.CheckinAndCommandService.CommandAndReportResults(r, m)
	if err == nil {
		if s.proj != nil {
			if perr := s.proj.DeviceCheckedIn(r.Context(), r.ID); perr != nil {
				s.log.Warn("device projection (checkin) failed", "id", r.ID, "err", perr)
			}
		}
		// "Idle" is the device asking for work, not a result; everything else
		// (Acknowledged/Error/NotNow/CommandFormatError) resolves a history row.
		if s.rec != nil && m.Status != "Idle" && m.CommandUUID != "" {
			if rerr := s.rec.CommandResult(r.Context(), r.ID, m.CommandUUID, m.Status, firstError(m.ErrorChain)); rerr != nil {
				s.log.Warn("command history (result) failed", "id", r.ID, "uuid", m.CommandUUID, "err", rerr)
			}
		}
		// If this result carried a DeviceInformation response, project its
		// QueryResponses onto the inventory (MDM-INV-001). inventoryFromRaw
		// returns ok=false for any result that isn't one, so ordinary
		// acknowledgements never touch the inventory columns.
		if s.proj != nil {
			if inv, ok := inventoryFromRaw(m.Raw); ok {
				if perr := s.proj.DeviceInventory(r.Context(), r.ID, inv); perr != nil {
					s.log.Warn("device projection (inventory) failed", "id", r.ID, "err", perr)
				}
			}
		}
	}
	return cmd, err
}

// inventoryFromRaw extracts a DeviceInventory from a command result plist. It
// reports ok=false unless the result carries a top-level QueryResponses dict
// (i.e. it is a DeviceInformation response), so unrelated acknowledgements never
// clobber inventory.
func inventoryFromRaw(raw []byte) (DeviceInventory, bool) {
	if len(raw) == 0 {
		return DeviceInventory{}, false
	}
	var top map[string]any
	if err := plist.Unmarshal(raw, &top); err != nil {
		return DeviceInventory{}, false
	}
	qr, ok := top["QueryResponses"].(map[string]any)
	if !ok {
		return DeviceInventory{}, false
	}
	str := func(k string) string {
		if v, ok := qr[k].(string); ok {
			return v
		}
		return ""
	}
	inv := DeviceInventory{
		Name:              str("DeviceName"),
		Model:             str("Model"),
		Product:           str("ProductName"),
		OSVersion:         str("OSVersion"),
		BuildVersion:      str("BuildVersion"),
		Serial:            str("SerialNumber"),
		AvailableCapacity: numStr(qr["AvailableDeviceCapacity"]),
		Battery:           numStr(qr["BatteryLevel"]),
	}
	return inv, true
}

// numStr formats a plist numeric (float64/int64) query value as a string,
// returning "" for absent or non-numeric values so it is treated as "no update".
func numStr(v any) string {
	switch n := v.(type) {
	case float64:
		return strconv.FormatFloat(n, 'g', -1, 64)
	case int64:
		return strconv.FormatInt(n, 10)
	case int:
		return strconv.Itoa(n)
	case string:
		return n
	default:
		return ""
	}
}

// firstError summarizes an ErrorChain for the history row.
func firstError(chain []mdm.ErrorChain) string {
	if len(chain) == 0 {
		return ""
	}
	e := chain[0]
	desc := e.LocalizedDescription
	if desc == "" {
		desc = e.USEnglishDescription
	}
	if desc == "" {
		return fmt.Sprintf("%s error %d", e.ErrorDomain, e.ErrorCode)
	}
	return desc
}

// RecordFromAuthenticate builds a DeviceRecord from an Authenticate message,
// including the attributes only present in the raw plist. Used by the live
// EventService and by the v1 importer (which replays stored Authenticate
// messages and must project the same inventory rows a live check-in would).
func RecordFromAuthenticate(id string, m *mdm.Authenticate) DeviceRecord {
	rec := DeviceRecord{
		ID:     id,
		UDID:   m.UDID,
		Serial: m.SerialNumber,
		Topic:  m.Topic,
	}
	enrichFromRaw(&rec, m.Raw)
	return rec
}

// enrichFromRaw pulls the nice-to-have device attributes (name, model, OS) out
// of the raw Authenticate plist, which NanoMDM's struct does not expose.
func enrichFromRaw(rec *DeviceRecord, raw []byte) {
	if len(raw) == 0 {
		return
	}
	var m map[string]any
	if err := plist.Unmarshal(raw, &m); err != nil {
		return
	}
	str := func(k string) string {
		if v, ok := m[k].(string); ok {
			return v
		}
		return ""
	}
	rec.Name = str("DeviceName")
	rec.Model = str("Model")
	rec.Product = str("ProductName")
	rec.OSVersion = str("OSVersion")
	rec.BuildVersion = str("BuildVersion")
	if rec.Serial == "" {
		rec.Serial = str("SerialNumber")
	}
}
