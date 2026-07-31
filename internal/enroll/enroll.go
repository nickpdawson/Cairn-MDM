// Package enroll serves the device enrollment profile. Enrollment is gated by
// single-use, expiring grants: GET /e/{token} redeems a grant and returns the
// CA-trust + SCEP + MDM profile, with the device cert bound per-device
// (%SerialNumber%) and to the grant's owner (SubjectAltName). The bare GET
// /enroll is default-denied and only served when explicitly opened for a
// zero-friction homelab.
package enroll

import (
	"context"
	"log/slog"
	"net/http"
	"strings"

	"github.com/dzsec/cairn/internal/profile"
)

// TopicProvider yields the current APNs topic (needed in the MDM payload).
type TopicProvider interface {
	GetSetting(ctx context.Context, key string) (string, error)
}

// Redemption is the grant data used to build a device's profile.
type Redemption struct {
	Platform       string
	Owner          string // rfc822/UPN → device cert SAN
	ExpectedSerial string
}

// Redeemer atomically validates and consumes a one-time enrollment grant.
type Redeemer interface {
	RedeemGrant(ctx context.Context, rawToken string) (Redemption, error)
}

// Config holds everything the handler needs to render a profile.
type Config struct {
	Organization  string   // reverse-DNS identifier root + PayloadOrganization
	CAAnchorsDER  [][]byte // CA cert(s) (DER) to install as trust anchors
	SCEPURL       string   // e.g. https://mdm.example.com/scep
	Challenge     string   // static SCEP challenge (may be empty)
	MDMServerURL  string   // e.g. https://mdm.example.com/mdm
	SubjectPrefix string   // device cert CN suffix, e.g. "devices.example.com"

	// AllowOpen serves the bare /enroll route unauthenticated (homelab
	// opt-in). Default false → bare /enroll is 404; use grant links.
	AllowOpen bool

	Signer *profile.Signer // optional; if set, profiles are CMS-signed
}

// Handler serves enrollment profiles.
type Handler struct {
	cfg      Config
	topics   TopicProvider
	redeemer Redeemer // may be nil (grant route disabled)
	topicKey string
	log      *slog.Logger
}

// New builds an enrollment handler. topicKey is the settings key holding the
// APNs topic (push.SettingTopic). redeemer may be nil to disable /e/{token}.
func New(cfg Config, topics TopicProvider, redeemer Redeemer, topicKey string, log *slog.Logger) *Handler {
	return &Handler{cfg: cfg, topics: topics, redeemer: redeemer, topicKey: topicKey, log: log}
}

// ServeOpen handles the bare GET /enroll. Default-denied unless AllowOpen; when
// open it issues an unbound profile (generic per-device CN, no owner SAN).
func (h *Handler) ServeOpen(w http.ResponseWriter, r *http.Request) {
	if !h.cfg.AllowOpen {
		h.log.Info("bare /enroll denied (use a grant link)", "remote", r.RemoteAddr)
		http.NotFound(w, r)
		return
	}
	h.serveProfile(w, r, Redemption{})
}

// ServeGrant handles GET /e/{token}: redeem the grant, then serve a profile
// bound to its owner. Invalid/expired/revoked/exhausted → 410 Gone.
func (h *Handler) ServeGrant(w http.ResponseWriter, r *http.Request) {
	if h.redeemer == nil {
		http.NotFound(w, r)
		return
	}
	token := normalizeToken(r.PathValue("token"))
	red, err := h.redeemer.RedeemGrant(r.Context(), token)
	if err != nil {
		h.log.Info("enrollment grant rejected", "remote", r.RemoteAddr, "err", err)
		http.Error(w, "This enrollment link is invalid, expired, or already used.", http.StatusGone)
		return
	}
	h.log.Info("enrollment grant redeemed", "owner", red.Owner, "platform", red.Platform, "remote", r.RemoteAddr)
	h.serveProfile(w, r, red)
}

// serveProfile builds, signs, and writes the .mobileconfig for a redemption.
func (h *Handler) serveProfile(w http.ResponseWriter, r *http.Request, red Redemption) {
	topic, err := h.topics.GetSetting(r.Context(), h.topicKey)
	if err != nil || topic == "" {
		h.log.Warn("enrollment requested but no APNs push certificate is loaded")
		http.Error(w, "server not ready: no APNs push certificate loaded", http.StatusServiceUnavailable)
		return
	}

	// Per-device subject: Apple substitutes %SerialNumber% at install, so each
	// device gets a unique, individually-revocable identity.
	subjectCN := "%SerialNumber%"
	if h.cfg.SubjectPrefix != "" {
		subjectCN += "." + h.cfg.SubjectPrefix
	}

	prof, err := profile.BuildEnrollment(profile.EnrollmentParams{
		Organization:  h.cfg.Organization,
		CAAnchorsDER:  h.cfg.CAAnchorsDER,
		SCEPURL:       h.cfg.SCEPURL,
		SubjectCN:     subjectCN,
		OwnerRFC822:   red.Owner,
		Challenge:     h.cfg.Challenge,
		MDMServerURL:  h.cfg.MDMServerURL,
		MDMCheckInURL: h.cfg.MDMServerURL,
		Topic:         topic,
	})
	if err != nil {
		h.log.Error("build enrollment profile", "err", err)
		http.Error(w, "failed to build profile", http.StatusInternalServerError)
		return
	}

	xml, err := profile.Marshal(prof)
	if err != nil {
		h.log.Error("marshal enrollment profile", "err", err)
		http.Error(w, "failed to render profile", http.StatusInternalServerError)
		return
	}

	body := xml
	if h.cfg.Signer != nil {
		signed, serr := profile.Sign(xml, *h.cfg.Signer)
		if serr != nil {
			h.log.Error("sign enrollment profile", "err", serr)
			http.Error(w, "failed to sign profile", http.StatusInternalServerError)
			return
		}
		body = signed
	}

	w.Header().Set("Content-Type", "application/x-apple-aspen-config")
	w.Header().Set("Content-Disposition", `attachment; filename="cairn-enroll.mobileconfig"`)
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(body)
}

// ServeHTTP keeps the http.Handler contract pointing at the bare route.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) { h.ServeOpen(w, r) }

// normalizeToken trims incidental whitespace from a path token.
func normalizeToken(s string) string { return strings.TrimSpace(s) }
