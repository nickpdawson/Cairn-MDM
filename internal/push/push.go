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
// The topic must never change across renewals — a different topic orphans every
// enrolled device — so callers (and the UI) surface the returned topic for
// confirmation against the previous one.
func LoadCert(ctx context.Context, store storage.PushCertStorer, settings SettingStore, pemCert, pemKey []byte) (topic string, notAfter time.Time, err error) {
	// Validate the pair loads as a usable TLS certificate.
	tlsCert, err := tls.X509KeyPair(pemCert, pemKey)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("push: certificate/key pair invalid: %w", err)
	}

	topic, err = cryptoutil.TopicFromPEMCert(pemCert)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("push: extract topic: %w", err)
	}

	if err := store.StorePushCert(ctx, pemCert, pemKey); err != nil {
		return "", time.Time{}, fmt.Errorf("push: store cert: %w", err)
	}

	if len(tlsCert.Certificate) > 0 {
		if leaf, perr := parseLeafNotAfter(tlsCert); perr == nil {
			notAfter = leaf
		}
	}

	if err := settings.SetSetting(ctx, SettingTopic, topic); err != nil {
		return "", time.Time{}, fmt.Errorf("push: record topic: %w", err)
	}
	if !notAfter.IsZero() {
		_ = settings.SetSetting(ctx, SettingNotAfter, notAfter.UTC().Format(time.RFC3339))
	}

	return topic, notAfter, nil
}

func parseLeafNotAfter(tlsCert tls.Certificate) (time.Time, error) {
	leaf := tlsCert.Leaf
	if leaf == nil {
		var err error
		leaf, err = x509.ParseCertificate(tlsCert.Certificate[0])
		if err != nil {
			return time.Time{}, err
		}
	}
	return leaf.NotAfter, nil
}
