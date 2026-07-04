// Package enroll serves the device enrollment profile. Phase 1 provides an
// unauthenticated GET that returns the CA-trust + SCEP + MDM profile built from
// server config, the embedded CA, and the stored APNs topic. Authenticated
// enrollment tokens, one-time SCEP challenges, and QR codes layer on in later
// phases.
package enroll

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/dzsec/cairn/internal/profile"
)

// TopicProvider yields the current APNs topic (needed in the MDM payload).
type TopicProvider interface {
	GetSetting(ctx context.Context, key string) (string, error)
}

// Config holds everything the handler needs to render a profile.
type Config struct {
	Organization  string   // reverse-DNS identifier root + PayloadOrganization
	CAAnchorsDER  [][]byte // CA cert(s) (DER) to install as trust anchors
	SCEPURL       string   // e.g. https://mdm.example.com/scep
	Challenge     string   // static SCEP challenge (may be empty)
	MDMServerURL  string   // e.g. https://mdm.example.com/mdm
	SubjectPrefix string   // device cert CN suffix, e.g. "devices.example.com"

	Signer *profile.Signer // optional; if set, profiles are CMS-signed
}

// Handler serves enrollment profiles.
type Handler struct {
	cfg      Config
	topics   TopicProvider
	topicKey string
	log      *slog.Logger
}

// New builds an enrollment handler. topicKey is the settings key holding the
// APNs topic (push.SettingTopic).
func New(cfg Config, topics TopicProvider, topicKey string, log *slog.Logger) *Handler {
	return &Handler{cfg: cfg, topics: topics, topicKey: topicKey, log: log}
}

// ServeHTTP renders and returns the enrollment .mobileconfig.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	topic, err := h.topics.GetSetting(r.Context(), h.topicKey)
	if err != nil || topic == "" {
		h.log.Warn("enrollment requested but no APNs push certificate is loaded")
		http.Error(w, "server not ready: no APNs push certificate loaded", http.StatusServiceUnavailable)
		return
	}

	// A per-device SubjectCN. Until enrollment tokens exist (Phase 2), derive a
	// generic name; the SCEP subject is refined once tokens carry hostnames.
	subjectCN := "device." + h.cfg.SubjectPrefix
	if subjectCN == "device." {
		subjectCN = "device"
	}

	prof, err := profile.BuildEnrollment(profile.EnrollmentParams{
		Organization:  h.cfg.Organization,
		CAAnchorsDER:  h.cfg.CAAnchorsDER,
		SCEPURL:       h.cfg.SCEPURL,
		SubjectCN:     subjectCN,
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
	_, _ = w.Write(body)
}
