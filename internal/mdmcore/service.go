// Package mdmcore embeds NanoMDM as a library: it assembles the check-in and
// command service chain and exposes it as an HTTP handler Cairn mounts on its
// own listener. Unlike v1 — which ran NanoMDM as a separate container and
// talked to it over HTTP + its MySQL schema — the service here is composed
// in-process against a storage.AllStorage we provide.
package mdmcore

import (
	"log/slog"
	"net/http"

	nlog "github.com/micromdm/nanolib/log"
	"github.com/micromdm/nanomdm/cryptoutil"
	httpmdm "github.com/micromdm/nanomdm/http/mdm"
	"github.com/micromdm/nanomdm/service"
	"github.com/micromdm/nanomdm/service/certauth"
	"github.com/micromdm/nanomdm/service/nanomdm"
	"github.com/micromdm/nanomdm/storage"
)

// Core holds the assembled MDM service and its HTTP handler.
type Core struct {
	store   storage.AllStorage
	handler http.Handler
	events  *EventService // nil when no projector/recorder configured
}

// New assembles the NanoMDM service chain:
//
//	CertExtractMdmSignatureMiddleware  (pulls the device identity cert out of
//	                                    the Mdm-Signature header — required for
//	                                    SignMessage=true enrollments)
//	  └─ certauth                      (binds each request's cert to its
//	                                    enrollment; rejects mismatches)
//	       └─ nanomdm                  (the check-in/command protocol core)
//
// It intentionally does not mount NanoMDM's HTTP command API — Cairn enqueues
// commands in-process through its own authenticated API, so the API-key surface
// v1 exposed does not exist here.
func New(store storage.AllStorage, logger nlog.Logger, proj DeviceProjector, rec CommandRecorder, slog *slog.Logger) *Core {
	var svc service.CheckinAndCommandService = nanomdm.New(store, nanomdm.WithLogger(logger.With("service", "nanomdm")))
	// Wrap the core with the projector, then certauth on the outside. certauth
	// gates first, so the projection only runs for cert-authenticated requests
	// and records state after the core service has persisted it.
	var events *EventService
	if proj != nil || rec != nil {
		events = NewEventService(svc, proj, rec, slog)
		svc = events
	}
	svc = certauth.New(svc, store, certauth.WithLogger(logger.With("service", "certauth")))

	h := httpmdm.CheckinAndCommandHandler(svc, logger.With("handler", "mdm"))
	h = httpmdm.CertExtractMdmSignatureMiddleware(
		h,
		httpmdm.MdmSignatureVerifierFunc(cryptoutil.VerifyMdmSignature),
	)

	return &Core{store: store, handler: h, events: events}
}

// OnPushable registers a hook called whenever a device completes a TokenUpdate
// (i.e. becomes pushable). No-op if the event service is not configured.
func (c *Core) OnPushable(fn func(id string)) {
	if c.events != nil {
		c.events.OnPushable(fn)
	}
}

// Handler returns the MDM check-in/command HTTP handler to mount at the
// configured MDM path.
func (c *Core) Handler() http.Handler { return c.handler }

// Store returns the underlying storage (used by the admin/enqueue paths).
func (c *Core) Store() storage.AllStorage { return c.store }
