package auth

import (
	"sync"
	"time"

	"github.com/dzsec/cairn-mdm/internal/config"
)

// LoginThrottle is an in-memory brute-force limiter keyed by an arbitrary string
// (callers use username+"|"+clientIP). It counts failures within a sliding
// window and, once a key reaches MaxAttempts, locks that key out for a fixed
// duration (MDM-AUTH-001).
//
// State is process-local: a restart clears all counters, and a multi-instance
// deployment would need a shared store. For a single-binary admin console this
// is the right trade — no external dependency, and the blast radius of a lost
// counter is one extra login attempt.
type LoginThrottle struct {
	mu      sync.Mutex
	entries map[string]*throttleEntry
	max     int
	window  time.Duration
	lockout time.Duration
}

type throttleEntry struct {
	failures     int
	windowStart  time.Time
	lockoutUntil time.Time
	lastSeen     time.Time
}

// NewLoginThrottle builds a throttle from policy. Zero-valued policy fields are
// replaced with their defaults, so a bare config.LoginPolicy{} yields a working
// limiter.
func NewLoginThrottle(policy config.LoginPolicy) *LoginThrottle {
	p := policy.WithDefaults()
	return &LoginThrottle{
		entries: make(map[string]*throttleEntry),
		max:     p.MaxAttempts,
		window:  time.Duration(p.WindowSeconds) * time.Second,
		lockout: time.Duration(p.LockoutSeconds) * time.Second,
	}
}

// Allowed reports whether a login attempt for key may proceed. When the key is
// locked out it returns false and the remaining lockout duration.
func (t *LoginThrottle) Allowed(key string) (ok bool, retryAfter time.Duration) {
	t.mu.Lock()
	defer t.mu.Unlock()
	e := t.entries[key]
	if e == nil {
		return true, 0
	}
	now := time.Now()
	if now.Before(e.lockoutUntil) {
		return false, e.lockoutUntil.Sub(now)
	}
	return true, 0
}

// RecordFailure notes a failed attempt for key. When the failure count within
// the current window reaches MaxAttempts, the key is locked out.
func (t *LoginThrottle) RecordFailure(key string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := time.Now()
	e := t.entries[key]
	if e == nil {
		e = &throttleEntry{windowStart: now}
		t.entries[key] = e
	}
	e.lastSeen = now
	// Already locked out: the counter is settled; leave it until the lockout
	// expires (a fresh window then starts on the next failure).
	if now.Before(e.lockoutUntil) {
		return
	}
	// The window has elapsed (which, given lockout >= window in practice, also
	// covers the post-lockout case): start counting fresh.
	if now.Sub(e.windowStart) > t.window {
		e.windowStart = now
		e.failures = 0
	}
	e.failures++
	if e.failures >= t.max {
		e.lockoutUntil = now.Add(t.lockout)
	}
}

// RecordSuccess clears any failure/lockout state for key.
func (t *LoginThrottle) RecordSuccess(key string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.entries, key)
}

// Cleanup drops entries that are neither locked out nor recently active. It is
// safe to call opportunistically or from a ticker.
func (t *LoginThrottle) Cleanup() {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := time.Now()
	for k, e := range t.entries {
		if now.After(e.lockoutUntil) && now.Sub(e.lastSeen) > t.window {
			delete(t.entries, k)
		}
	}
}
