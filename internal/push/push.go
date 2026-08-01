// Package push wraps NanoMDM's APNs push stack and the APNs push-certificate
// lifecycle. The push certificate (from mdmcert.download or Apple Business
// Manager) is stored in the same storage backend as everything else; its topic
// is what ties enrolled devices to this server.
package push

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"time"

	nanolog "github.com/micromdm/nanolib/log"
	"github.com/micromdm/nanomdm/cryptoutil"
	"github.com/micromdm/nanomdm/push"
	"github.com/micromdm/nanomdm/push/nanopush"
	pushsvc "github.com/micromdm/nanomdm/push/service"
	"github.com/micromdm/nanomdm/storage"
)

// SettingTopic is the settings key under which the active APNs topic is cached
// so enrollment-profile generation can read it without knowing it in advance.
const SettingTopic = "apns_topic"

// SettingNotAfter caches the push certificate expiry (RFC3339) for renewal UX.
const SettingNotAfter = "apns_not_after"

// NewPusher builds a NanoMDM push service over the given storage. The returned
// Pusher looks up each enrollment's topic + push token and the stored push
// certificate to deliver APNs notifications.
func NewPusher(store storage.AllStorage, logger nanolog.Logger) push.Pusher {
	return pushsvc.New(store, store, nanopush.NewFactory(), logger.With("service", "push"))
}

// SettingStore is the subset of storage the cert loader records topic metadata
// into (satisfied by the sqlite DB).
type SettingStore interface {
	SetSetting(ctx context.Context, key, value string) error
}

// LoadCert validates an APNs certificate/key pair, stores it, and records its
// topic and expiry. It returns the topic (com.apple.mgmt.External.<uuid>) and
// the certificate expiry.
//
// Validation happens BEFORE storage (MDM-APNS-001): the key must match the
// certificate, the certificate must carry a valid APNs topic, and the current
// time must fall inside its validity window. A wrong-topic, mismatched, expired,
// or not-yet-valid certificate is rejected and never stored — a single global
// topic used to hide a second fleet's expiry behind the later date.
//
// The topic must never change across renewals — a different topic orphans every
// enrolled device — so callers (and the UI) surface the returned topic for
// confirmation against the previous one.
func LoadCert(ctx context.Context, store storage.PushCertStorer, settings SettingStore, pemCert, pemKey []byte) (topic string, notAfter time.Time, err error) {
	// (a) The pair must load as a usable TLS certificate. X509KeyPair fails if
	// the private key does not match the certificate's public key.
	tlsCert, err := tls.X509KeyPair(pemCert, pemKey)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("push: certificate/key pair invalid: %w", err)
	}

	// (b) The certificate must carry a valid APNs topic (UID OID).
	topic, err = cryptoutil.TopicFromPEMCert(pemCert)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("push: extract topic: %w", err)
	}

	// (c) The certificate must be within its validity window. Parse the leaf
	// directly rather than trusting tlsCert.Leaf, which is not populated on
	// every Go version.
	if len(tlsCert.Certificate) == 0 {
		return "", time.Time{}, fmt.Errorf("push: certificate chain is empty")
	}
	leaf, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		return "", time.Time{}, fmt.Errorf("push: parse certificate: %w", err)
	}
	now := time.Now()
	if now.Before(leaf.NotBefore) {
		return "", time.Time{}, fmt.Errorf("push: certificate for topic %s is not valid until %s", topic, leaf.NotBefore.UTC().Format(time.RFC3339))
	}
	if now.After(leaf.NotAfter) {
		return "", time.Time{}, fmt.Errorf("push: certificate for topic %s expired %s", topic, leaf.NotAfter.UTC().Format(time.RFC3339))
	}
	notAfter = leaf.NotAfter

	// Only a validated certificate reaches storage.
	if err := store.StorePushCert(ctx, pemCert, pemKey); err != nil {
		return "", time.Time{}, fmt.Errorf("push: store cert: %w", err)
	}

	// Backward-compatible settings cache. Per-topic metadata now lives in the
	// apns_topics table (see cmd/cairn/pushcert.go and internal/storage/sqlite/
	// apns.go); this cache is retained for callers that read the single active
	// topic. It reflects the most recently imported certificate.
	if err := settings.SetSetting(ctx, SettingTopic, topic); err != nil {
		return "", time.Time{}, fmt.Errorf("push: record topic: %w", err)
	}
	_ = settings.SetSetting(ctx, SettingNotAfter, notAfter.UTC().Format(time.RFC3339))

	return topic, notAfter, nil
}

// RenewalTier maps a push certificate's expiry to a renewal alert tier. It
// returns the whole days remaining (negative once expired), a severity token
// used for UI styling (critical|high|warning|caution|notice|ok), and a short
// human label. Thresholds escalate at 90/60/30/14/7 days so a second fleet's
// nearer expiry can never hide behind a later one.
func RenewalTier(notAfter time.Time) (days int, severity, label string) {
	days = int(time.Until(notAfter).Hours() / 24)
	switch {
	case days < 0:
		return days, "critical", "expired"
	case days <= 7:
		return days, "critical", "renew now"
	case days <= 14:
		return days, "high", "renew now"
	case days <= 30:
		return days, "warning", "renew soon"
	case days <= 60:
		return days, "caution", "plan renewal"
	case days <= 90:
		return days, "notice", "upcoming"
	default:
		return days, "ok", "ok"
	}
}
