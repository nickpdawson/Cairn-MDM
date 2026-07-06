package mdmcore

import (
	"context"
	"crypto/rand"
	"fmt"
	"log/slog"

	"github.com/micromdm/nanomdm/mdm"
	"github.com/micromdm/nanomdm/push"
	"github.com/micromdm/nanomdm/storage"
	"github.com/micromdm/plist"
)

// CommandRecorder persists command history for the console: a row when a
// command is enqueued, resolved when the device reports results. The SQLite
// storage implements it. Recording is best-effort — a history failure never
// blocks the protocol path.
type CommandRecorder interface {
	CommandSent(ctx context.Context, deviceID, commandUUID, requestType string) error
	CommandResult(ctx context.Context, deviceID, commandUUID, status, errDesc string) error
}

// InstallProfileCommand builds an InstallProfile command carrying the given
// profile bytes (raw .mobileconfig, signed or unsigned).
func InstallProfileCommand(profile []byte) (*mdm.Command, error) {
	return command(map[string]any{
		"RequestType": "InstallProfile",
		"Payload":     profile,
	})
}

// RemoveProfileCommand builds a RemoveProfile command for the profile with the
// given PayloadIdentifier.
func RemoveProfileCommand(identifier string) (*mdm.Command, error) {
	return command(map[string]any{
		"RequestType": "RemoveProfile",
		"Identifier":  identifier,
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
	store    storage.CommandEnqueuer
	pusher   push.Pusher
	recorder CommandRecorder // may be nil
	log      *slog.Logger    // may be nil
}

// NewCommander builds a Commander.
func NewCommander(store storage.CommandEnqueuer, pusher push.Pusher) *Commander {
	return &Commander{store: store, pusher: pusher}
}

// WithRecorder returns a Commander that also records history rows for every
// enqueued command.
func (c *Commander) WithRecorder(rec CommandRecorder, log *slog.Logger) *Commander {
	c.recorder = rec
	c.log = log
	return c
}

// enqueue queues + pushes and records history.
func (c *Commander) enqueue(ctx context.Context, ids []string, cmd *mdm.Command) error {
	if err := Enqueue(ctx, c.store, c.pusher, ids, cmd); err != nil {
		return err
	}
	if c.recorder != nil {
		for _, id := range ids {
			if err := c.recorder.CommandSent(ctx, id, cmd.CommandUUID, cmd.Command.RequestType); err != nil && c.log != nil {
				c.log.Warn("command history (sent) failed", "id", id, "uuid", cmd.CommandUUID, "err", err)
			}
		}
	}
	return nil
}

// SendDeviceInformation queries fresh device information from the given devices.
func (c *Commander) SendDeviceInformation(ctx context.Context, ids ...string) error {
	cmd, err := DeviceInformationCommand()
	if err != nil {
		return err
	}
	return c.enqueue(ctx, ids, cmd)
}

// SendInstallProfile installs a profile (raw .mobileconfig) on the given devices.
func (c *Commander) SendInstallProfile(ctx context.Context, profile []byte, ids ...string) error {
	cmd, err := InstallProfileCommand(profile)
	if err != nil {
		return err
	}
	return c.enqueue(ctx, ids, cmd)
}

// SendInstallProfileUUID is SendInstallProfile for one device, returning the
// CommandUUID so callers (the assignment reconciler) can correlate the result.
func (c *Commander) SendInstallProfileUUID(ctx context.Context, profile []byte, id string) (string, error) {
	cmd, err := InstallProfileCommand(profile)
	if err != nil {
		return "", err
	}
	if err := c.enqueue(ctx, []string{id}, cmd); err != nil {
		return "", err
	}
	return cmd.CommandUUID, nil
}

// SendRemoveProfile removes the profile with the given PayloadIdentifier.
func (c *Commander) SendRemoveProfile(ctx context.Context, identifier string, ids ...string) error {
	cmd, err := RemoveProfileCommand(identifier)
	if err != nil {
		return err
	}
	return c.enqueue(ctx, ids, cmd)
}

func newCommandUUID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
