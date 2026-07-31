// Package importer migrates an existing NanoMDM deployment (v1: MySQL) into
// Cairn's storage with zero device re-enrollment.
//
// Strategy: rather than copying tables, the importer replays the raw Apple
// check-in plists stored in the source (Authenticate, TokenUpdate,
// UserAuthenticate) through Cairn's own storage.AllStorage — the exact code
// path a live device takes. Imported state is therefore byte-identical to
// what a fresh check-in would produce, regardless of backend layout. The
// four migration invariants (APNs topic+cert, server URL, identity trust
// chain, SCEP URL) live outside this data and are preserved by configuration.
package importer

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/dzsec/cairn/internal/mdmcore"
	"github.com/micromdm/nanomdm/mdm"
	"github.com/micromdm/nanomdm/storage"
)

// Source is the read side of a migration (the v1 NanoMDM database).
type Source interface {
	// Devices returns device-channel rows including raw check-in plists.
	Devices(ctx context.Context) ([]DeviceRow, error)
	// Users returns user-channel rows.
	Users(ctx context.Context) ([]UserRow, error)
	// Enrollments returns the source-of-truth push routing rows (used for
	// verification against what the replay produced).
	Enrollments(ctx context.Context) ([]EnrollmentRow, error)
	// CertAuthAssociations returns enrollment↔certificate-hash bindings —
	// without these, existing devices cannot authenticate.
	CertAuthAssociations(ctx context.Context) ([]CertAuthRow, error)
	// PushCerts returns the APNs push certificate(s).
	PushCerts(ctx context.Context) ([]PushCertRow, error)
	// PendingCommands counts still-active queue entries. The cutover
	// procedure drains the queue first; a non-empty queue aborts the import
	// unless explicitly allowed.
	PendingCommands(ctx context.Context) (int, error)
}

// DeviceRow is a device-channel enrollment with its raw check-in plists.
type DeviceRow struct {
	ID                string
	Authenticate      string // raw plist (required)
	TokenUpdate       string // raw plist (empty if device never completed enrollment)
	BootstrapTokenB64 string
	SerialNumber      string
}

// UserRow is a user-channel enrollment.
type UserRow struct {
	ID               string
	DeviceID         string
	TokenUpdate      string // raw plist
	UserAuthenticate string // raw plist (optional)
	UserAuthDigest   string // raw plist (optional digest-response round)
}

// EnrollmentRow is the push-routing record used for verification.
type EnrollmentRow struct {
	ID        string
	DeviceID  string
	Type      string
	Topic     string
	PushMagic string
	TokenHex  string
	Enabled   bool
}

// CertAuthRow binds an enrollment ID to its identity-certificate SHA-256.
type CertAuthRow struct {
	ID     string
	SHA256 string
}

// PushCertRow is an APNs push certificate + key (PEM).
type PushCertRow struct {
	Topic   string
	CertPEM string
	KeyPEM  string
}

// Options controls an import run.
type Options struct {
	// AllowPending proceeds even if the source command queue is not empty
	// (queued commands are NOT migrated; the cutover plan drains them first).
	AllowPending bool
	// DryRun reads and validates everything but writes nothing.
	DryRun bool
}

// Report is the outcome. Mismatches must be empty for a trustworthy cutover.
type Report struct {
	Devices      int
	Users        int
	Enrollments  int
	Associations int
	PushCerts    int
	Disabled     int
	Skipped      []string // ids skipped, with reasons
	Mismatches   []string // verification failures — non-empty means DO NOT cut over
	DryRun       bool
}

// Ok reports whether the migration verified cleanly.
func (r *Report) Ok() bool { return len(r.Mismatches) == 0 }

// Importer migrates a Source into Cairn's storage.
type Importer struct {
	dst  storage.AllStorage
	proj mdmcore.DeviceProjector // optional: populates the admin inventory
	log  *slog.Logger
}

// New builds an Importer. proj may be nil.
func New(dst storage.AllStorage, proj mdmcore.DeviceProjector, log *slog.Logger) *Importer {
	if log == nil {
		log = slog.Default()
	}
	return &Importer{dst: dst, proj: proj, log: log}
}

func deviceReq(ctx context.Context, id string) *mdm.Request {
	r := mdm.NewRequestWithContext(ctx, nil)
	r.EnrollID = &mdm.EnrollID{Type: mdm.Device, ID: id}
	return r
}

func userReq(ctx context.Context, id, parent string) *mdm.Request {
	r := mdm.NewRequestWithContext(ctx, nil)
	r.EnrollID = &mdm.EnrollID{Type: mdm.User, ID: id, ParentID: parent}
	return r
}

// Run performs the migration and verification.
func (im *Importer) Run(ctx context.Context, src Source, opts Options) (*Report, error) {
	rep := &Report{DryRun: opts.DryRun}

	// Gate: the source queue should be drained (cutover step A3).
	pending, err := src.PendingCommands(ctx)
	if err != nil {
		return nil, fmt.Errorf("importer: count pending commands: %w", err)
	}
	if pending > 0 && !opts.AllowPending {
		return nil, fmt.Errorf("importer: source has %d pending queued commands — drain the queue before cutover, or pass -allow-pending to skip them (they will NOT be migrated)", pending)
	}

	// Push certificates first (device records reference topics).
	pushCerts, err := src.PushCerts(ctx)
	if err != nil {
		return nil, fmt.Errorf("importer: read push certs: %w", err)
	}
	for _, pc := range pushCerts {
		if !opts.DryRun {
			if err := im.dst.StorePushCert(ctx, []byte(pc.CertPEM), []byte(pc.KeyPEM)); err != nil {
				return nil, fmt.Errorf("importer: store push cert %s: %w", pc.Topic, err)
			}
		}
		rep.PushCerts++
	}

	// Devices: replay Authenticate then TokenUpdate, exactly like a live
	// enrollment (Authenticate resets state; TokenUpdate enables + stores the
	// push token and unlock token).
	devices, err := src.Devices(ctx)
	if err != nil {
		return nil, fmt.Errorf("importer: read devices: %w", err)
	}
	for _, d := range devices {
		authMsg, err := decodeAs[*mdm.Authenticate](d.Authenticate)
		if err != nil {
			rep.Skipped = append(rep.Skipped, fmt.Sprintf("device %s: bad Authenticate plist: %v", d.ID, err))
			continue
		}
		if opts.DryRun {
			// Validate the rest without writing.
			if d.TokenUpdate != "" {
				if _, err := decodeAs[*mdm.TokenUpdate](d.TokenUpdate); err != nil {
					rep.Skipped = append(rep.Skipped, fmt.Sprintf("device %s: bad TokenUpdate plist: %v", d.ID, err))
					continue
				}
			}
			rep.Devices++
			continue
		}

		req := deviceReq(ctx, d.ID)
		if err := im.dst.StoreAuthenticate(req, authMsg); err != nil {
			return nil, fmt.Errorf("importer: device %s: store authenticate: %w", d.ID, err)
		}
		if im.proj != nil {
			if err := im.proj.DeviceEnrolled(ctx, mdmcore.RecordFromAuthenticate(d.ID, authMsg)); err != nil {
				im.log.Warn("import: device projection failed", "id", d.ID, "err", err)
			}
		}
		if d.TokenUpdate != "" {
			tuMsg, err := decodeAs[*mdm.TokenUpdate](d.TokenUpdate)
			if err != nil {
				rep.Skipped = append(rep.Skipped, fmt.Sprintf("device %s: bad TokenUpdate plist: %v", d.ID, err))
				continue
			}
			if err := im.dst.StoreTokenUpdate(req, tuMsg); err != nil {
				return nil, fmt.Errorf("importer: device %s: store token update: %w", d.ID, err)
			}
			if im.proj != nil {
				if err := im.proj.DeviceTokenUpdated(ctx, d.ID); err != nil {
					im.log.Warn("import: token projection failed", "id", d.ID, "err", err)
				}
			}
		}
		if d.BootstrapTokenB64 != "" {
			bs := &mdm.SetBootstrapToken{}
			if err := bs.BootstrapToken.SetTokenString(d.BootstrapTokenB64); err != nil {
				rep.Skipped = append(rep.Skipped, fmt.Sprintf("device %s: bad bootstrap token: %v", d.ID, err))
			} else if err := im.dst.StoreBootstrapToken(req, bs); err != nil {
				return nil, fmt.Errorf("importer: device %s: store bootstrap token: %w", d.ID, err)
			}
		}
		rep.Devices++
	}

	// User-channel enrollments.
	users, err := src.Users(ctx)
	if err != nil {
		return nil, fmt.Errorf("importer: read users: %w", err)
	}
	for _, u := range users {
		req := userReq(ctx, u.ID, u.DeviceID)
		for _, raw := range []string{u.UserAuthenticate, u.UserAuthDigest} {
			if raw == "" {
				continue
			}
			uaMsg, err := decodeAs[*mdm.UserAuthenticate](raw)
			if err != nil {
				rep.Skipped = append(rep.Skipped, fmt.Sprintf("user %s: bad UserAuthenticate plist: %v", u.ID, err))
				continue
			}
			if !opts.DryRun {
				if err := im.dst.StoreUserAuthenticate(req, uaMsg); err != nil {
					return nil, fmt.Errorf("importer: user %s: store user authenticate: %w", u.ID, err)
				}
			}
		}
		if u.TokenUpdate != "" {
			tuMsg, err := decodeAs[*mdm.TokenUpdate](u.TokenUpdate)
			if err != nil {
				rep.Skipped = append(rep.Skipped, fmt.Sprintf("user %s: bad TokenUpdate plist: %v", u.ID, err))
				continue
			}
			if !opts.DryRun {
				if err := im.dst.StoreTokenUpdate(req, tuMsg); err != nil {
					return nil, fmt.Errorf("importer: user %s: store token update: %w", u.ID, err)
				}
			}
		}
		rep.Users++
	}

	// Certificate-hash associations: the crown jewel. Without these, the
	// migrated devices' existing SCEP certs cannot authenticate check-ins.
	assocs, err := src.CertAuthAssociations(ctx)
	if err != nil {
		return nil, fmt.Errorf("importer: read cert-auth associations: %w", err)
	}
	for _, a := range assocs {
		if !opts.DryRun {
			if err := im.dst.AssociateCertHash(deviceReq(ctx, a.ID), a.SHA256); err != nil {
				return nil, fmt.Errorf("importer: associate %s: %w", a.ID, err)
			}
		}
		rep.Associations++
	}

	// Enrollment rows: disable what the source had disabled, then verify.
	enrollments, err := src.Enrollments(ctx)
	if err != nil {
		return nil, fmt.Errorf("importer: read enrollments: %w", err)
	}
	rep.Enrollments = len(enrollments)
	if opts.DryRun {
		return rep, nil
	}
	for _, e := range enrollments {
		if !e.Enabled {
			if err := im.dst.Disable(deviceReq(ctx, e.ID)); err != nil {
				im.log.Warn("import: disable failed", "id", e.ID, "err", err)
			}
			rep.Disabled++
		}
	}

	im.verify(ctx, src, enrollments, assocs, rep)
	return rep, nil
}

// verify re-reads the destination through the same interfaces NanoMDM's
// runtime uses and compares against the source's push-routing rows. Any
// mismatch means an enrolled device would not be pushable or authenticable
// after cutover.
func (im *Importer) verify(ctx context.Context, src Source, enrollments []EnrollmentRow, assocs []CertAuthRow, rep *Report) {
	var enabledIDs []string
	byID := map[string]EnrollmentRow{}
	for _, e := range enrollments {
		byID[e.ID] = e
		if e.Enabled {
			enabledIDs = append(enabledIDs, e.ID)
		}
	}
	pushInfos, err := im.dst.RetrievePushInfo(ctx, enabledIDs)
	if err != nil {
		rep.Mismatches = append(rep.Mismatches, fmt.Sprintf("retrieve push info: %v", err))
		return
	}
	for _, id := range enabledIDs {
		e := byID[id]
		p, ok := pushInfos[id]
		if !ok || p == nil {
			rep.Mismatches = append(rep.Mismatches, fmt.Sprintf("enrollment %s: no push info after import", id))
			continue
		}
		if p.Topic != e.Topic {
			rep.Mismatches = append(rep.Mismatches, fmt.Sprintf("enrollment %s: topic %q != source %q", id, p.Topic, e.Topic))
		}
		if p.PushMagic != e.PushMagic {
			rep.Mismatches = append(rep.Mismatches, fmt.Sprintf("enrollment %s: push magic mismatch", id))
		}
		// []byte conversion matters: mdm's token type has a String() method,
		// which %x would hex-encode a second time.
		if fmt.Sprintf("%x", []byte(p.Token)) != e.TokenHex {
			rep.Mismatches = append(rep.Mismatches, fmt.Sprintf("enrollment %s: push token mismatch", id))
		}
	}
	for _, a := range assocs {
		ok, err := im.dst.IsCertHashAssociated(deviceReq(ctx, a.ID), a.SHA256)
		if err != nil || !ok {
			rep.Mismatches = append(rep.Mismatches, fmt.Sprintf("cert association %s: not present after import (err=%v)", a.ID, err))
		}
	}
}

// decodeAs decodes a raw check-in plist and asserts its concrete type.
func decodeAs[T any](raw string) (T, error) {
	var zero T
	msg, err := mdm.DecodeCheckin([]byte(raw))
	if err != nil {
		return zero, err
	}
	typed, ok := msg.(T)
	if !ok {
		return zero, fmt.Errorf("unexpected check-in type %T", msg)
	}
	return typed, nil
}
