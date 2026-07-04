package mdmcore

import (
	"context"
	"crypto/rand"
	"fmt"

	"github.com/micromdm/nanomdm/mdm"
	"github.com/micromdm/nanomdm/push"
	"github.com/micromdm/nanomdm/storage"
	"github.com/micromdm/plist"
)

// InstallProfileCommand builds an InstallProfile command carrying the given
// profile bytes (raw .mobileconfig, signed or unsigned).
func InstallProfileCommand(profile []byte) (*mdm.Command, error) {
	return command(map[string]any{
		"RequestType": "InstallProfile",
		"Payload":     profile,
	})
}

// DeviceInformationCommand builds a DeviceInformation query for the given
// queries (e.g. "DeviceName", "OSVersion", "SerialNumber", "Model"). With no
// queries Apple returns a default set.
func DeviceInformationCommand(queries ...string) (*mdm.Command, error) {
	inner := map[string]any{"RequestType": "DeviceInformation"}
	if len(queries) > 0 {
		q := make([]any, len(queries))
		for i, s := range queries {
			q[i] = s
		}
		inner["Queries"] = q
	}
	return command(inner)
}

// command marshals a command dict with a fresh CommandUUID and decodes it into
// an mdm.Command (which also validates it and retains the raw plist).
func command(inner map[string]any) (*mdm.Command, error) {
	raw, err := plist.Marshal(map[string]any{
		"CommandUUID": newCommandUUID(),
		"Command":     inner,
	})
	if err != nil {
		return nil, fmt.Errorf("mdmcore: marshal command: %w", err)
	}
	return mdm.DecodeCommand(raw)
}

// Enqueue queues cmd for the given enrollment IDs and sends an APNs push so the
// devices wake and check in. This is the in-process path the admin console and
// CLI use — no HTTP round-trip, no API key.
func Enqueue(ctx context.Context, store storage.CommandEnqueuer, pusher push.Pusher, ids []string, cmd *mdm.Command) error {
	if _, err := store.EnqueueCommand(ctx, ids, cmd); err != nil {
		return fmt.Errorf("mdmcore: enqueue: %w", err)
	}
	if pusher != nil {
		if _, err := pusher.Push(ctx, ids); err != nil {
			return fmt.Errorf("mdmcore: push: %w", err)
		}
	}
	return nil
}

// Commander bundles the store + pusher and exposes high-level command actions
// for the admin console and API.
type Commander struct {
	store  storage.CommandEnqueuer
	pusher push.Pusher
}

// NewCommander builds a Commander.
func NewCommander(store storage.CommandEnqueuer, pusher push.Pusher) *Commander {
	return &Commander{store: store, pusher: pusher}
}

// SendDeviceInformation queries fresh device information from the given devices.
func (c *Commander) SendDeviceInformation(ctx context.Context, ids ...string) error {
	cmd, err := DeviceInformationCommand()
	if err != nil {
		return err
	}
	return Enqueue(ctx, c.store, c.pusher, ids, cmd)
}

// SendInstallProfile installs a profile (raw .mobileconfig) on the given devices.
func (c *Commander) SendInstallProfile(ctx context.Context, profile []byte, ids ...string) error {
	cmd, err := InstallProfileCommand(profile)
	if err != nil {
		return err
	}
	return Enqueue(ctx, c.store, c.pusher, ids, cmd)
}

func newCommandUUID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
