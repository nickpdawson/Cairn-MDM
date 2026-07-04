package mdmcore

import (
	"context"
	"log/slog"

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

// DeviceProjector persists device-inventory changes derived from check-ins.
// The SQLite storage implements it. This replaces v1's 30-second polling loop:
// enrollment and token-update events update the inventory the moment they happen.
type DeviceProjector interface {
	DeviceEnrolled(ctx context.Context, d DeviceRecord) error
	DeviceTokenUpdated(ctx context.Context, id string) error
	DeviceCheckedOut(ctx context.Context, id string) error
	DeviceCheckedIn(ctx context.Context, id string) error
}

// EventService decorates a NanoMDM service: it delegates every call to the inner
// service (which persists protocol state) and, on success, updates the device
// projection. Embedding the interface means we inherit all methods and override
// only the ones we care about.
type EventService struct {
	service.CheckinAndCommandService
	proj DeviceProjector
	log  *slog.Logger
}

// NewEventService wraps inner with projection side effects.
func NewEventService(inner service.CheckinAndCommandService, proj DeviceProjector, log *slog.Logger) *EventService {
	return &EventService{CheckinAndCommandService: inner, proj: proj, log: log}
}

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
	if err := s.proj.DeviceEnrolled(r.Context(), rec); err != nil {
		s.log.Warn("device projection (enroll) failed", "id", r.ID, "err", err)
	}
	return nil
}

func (s *EventService) TokenUpdate(r *mdm.Request, m *mdm.TokenUpdate) error {
	if err := s.CheckinAndCommandService.TokenUpdate(r, m); err != nil {
		return err
	}
	if err := s.proj.DeviceTokenUpdated(r.Context(), r.ID); err != nil {
		s.log.Warn("device projection (token update) failed", "id", r.ID, "err", err)
	}
	return nil
}

func (s *EventService) CheckOut(r *mdm.Request, m *mdm.CheckOut) error {
	if err := s.CheckinAndCommandService.CheckOut(r, m); err != nil {
		return err
	}
	if err := s.proj.DeviceCheckedOut(r.Context(), r.ID); err != nil {
		s.log.Warn("device projection (checkout) failed", "id", r.ID, "err", err)
	}
	return nil
}

func (s *EventService) CommandAndReportResults(r *mdm.Request, m *mdm.CommandResults) (*mdm.Command, error) {
	cmd, err := s.CheckinAndCommandService.CommandAndReportResults(r, m)
	if err == nil {
		if perr := s.proj.DeviceCheckedIn(r.Context(), r.ID); perr != nil {
			s.log.Warn("device projection (checkin) failed", "id", r.ID, "err", perr)
		}
	}
	return cmd, err
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
