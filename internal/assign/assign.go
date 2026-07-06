// Package assign is the event-driven assignment reconciler: it computes the
// profiles a device should have (the union of its groups' assignments) and
// pushes the missing ones. It runs when a device becomes pushable (enrollment
// TokenUpdate) and when an admin changes membership or assignments — never on
// a polling loop. This replaces v1's 30-second poller design.
package assign

import (
	"context"
	"log/slog"
	"time"

	"github.com/dzsec/cairn/internal/storage/sqlite"
)

// Store is what the reconciler needs from storage.
type Store interface {
	ProfilesToDeploy(ctx context.Context, deviceID string) ([]sqlite.Profile, error)
	MarkDeploySent(ctx context.Context, deviceID string, profileID int64, commandUUID, profileUpdatedAt string) error
	GroupDeviceIDs(ctx context.Context, groupID int64) ([]string, error)
}

// Commander sends the InstallProfile commands.
type Commander interface {
	SendInstallProfileUUID(ctx context.Context, profile []byte, id string) (string, error)
}

// Reconciler pushes assigned-but-missing profiles to devices.
type Reconciler struct {
	store Store
	cmd   Commander
	log   *slog.Logger
}

// New builds a Reconciler.
func New(store Store, cmd Commander, log *slog.Logger) *Reconciler {
	return &Reconciler{store: store, cmd: cmd, log: log}
}

// ReconcileDevice sends every assigned profile the device is missing. Each
// send is marked before the result arrives; the deploy row is resolved to
// installed/failed when the device reports (see sqlite.CommandResult).
func (r *Reconciler) ReconcileDevice(ctx context.Context, deviceID string) error {
	profiles, err := r.store.ProfilesToDeploy(ctx, deviceID)
	if err != nil {
		return err
	}
	for _, p := range profiles {
		uuid, err := r.cmd.SendInstallProfileUUID(ctx, p.Data, deviceID)
		if err != nil {
			// Push/enqueue failure: log and continue with the rest. The deploy
			// stays unmarked, so the next reconcile retries it.
			r.log.Warn("reconcile: install push failed", "device", deviceID, "profile", p.Identifier, "err", err)
			continue
		}
		if err := r.store.MarkDeploySent(ctx, deviceID, p.ID, uuid, p.UpdatedAt); err != nil {
			r.log.Warn("reconcile: mark deploy failed", "device", deviceID, "profile", p.Identifier, "err", err)
		}
		r.log.Info("reconcile: profile pushed", "device", deviceID, "profile", p.Identifier, "command", uuid)
	}
	return nil
}

// ReconcileGroup reconciles every pushable device in a group (called after an
// assignment or membership change).
func (r *Reconciler) ReconcileGroup(ctx context.Context, groupID int64) error {
	ids, err := r.store.GroupDeviceIDs(ctx, groupID)
	if err != nil {
		return err
	}
	for _, id := range ids {
		if err := r.ReconcileDevice(ctx, id); err != nil {
			r.log.Warn("reconcile group: device failed", "group", groupID, "device", id, "err", err)
		}
	}
	return nil
}

// DeviceNowPushable is the mdmcore.OnPushable hook. It runs with its own
// context because the originating check-in request has already returned.
func (r *Reconciler) DeviceNowPushable(deviceID string) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if err := r.ReconcileDevice(ctx, deviceID); err != nil {
		r.log.Warn("reconcile on enroll failed", "device", deviceID, "err", err)
	}
}
