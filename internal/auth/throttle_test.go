package auth

import (
	"testing"
	"time"

	"github.com/dzsec/cairn/internal/config"
)

func TestThrottleLocksAfterMaxAttempts(t *testing.T) {
	th := NewLoginThrottle(config.LoginPolicy{MaxAttempts: 3, WindowSeconds: 300, LockoutSeconds: 300})
	key := "nick|203.0.113.9"

	// Below the threshold: still allowed.
	th.RecordFailure(key)
	th.RecordFailure(key)
	if ok, _ := th.Allowed(key); !ok {
		t.Fatal("locked out before reaching MaxAttempts")
	}

	// Third failure trips the lockout.
	th.RecordFailure(key)
	ok, retryAfter := th.Allowed(key)
	if ok {
		t.Fatal("expected lockout after MaxAttempts failures")
	}
	if retryAfter <= 0 {
		t.Errorf("retryAfter = %v, want > 0", retryAfter)
	}
}

func TestThrottleSuccessResets(t *testing.T) {
	th := NewLoginThrottle(config.LoginPolicy{MaxAttempts: 3, WindowSeconds: 300, LockoutSeconds: 300})
	key := "nick|203.0.113.9"

	th.RecordFailure(key)
	th.RecordFailure(key)
	th.RecordFailure(key)
	if ok, _ := th.Allowed(key); ok {
		t.Fatal("expected lockout")
	}

	th.RecordSuccess(key)
	if ok, retryAfter := th.Allowed(key); !ok || retryAfter != 0 {
		t.Errorf("after success: ok=%v retryAfter=%v, want ok=true retryAfter=0", ok, retryAfter)
	}
}

func TestThrottleWindowExpiryResumesAttempts(t *testing.T) {
	th := NewLoginThrottle(config.LoginPolicy{MaxAttempts: 3, WindowSeconds: 300, LockoutSeconds: 300})
	// Shrink the window directly (same-package access) so the test is fast and
	// deterministic rather than sleeping for the configured seconds.
	th.window = 40 * time.Millisecond
	key := "nick|203.0.113.9"

	// Two failures, then let the window lapse.
	th.RecordFailure(key)
	th.RecordFailure(key)
	time.Sleep(60 * time.Millisecond)

	// A failure after window expiry starts a fresh count — not a lockout.
	th.RecordFailure(key)
	if ok, _ := th.Allowed(key); !ok {
		t.Fatal("window should have reset the failure count; got a lockout")
	}
}

func TestThrottleCleanupDropsStaleEntries(t *testing.T) {
	th := NewLoginThrottle(config.LoginPolicy{MaxAttempts: 3, WindowSeconds: 300, LockoutSeconds: 300})
	th.window = 20 * time.Millisecond
	key := "nick|203.0.113.9"
	th.RecordFailure(key)

	time.Sleep(40 * time.Millisecond)
	th.Cleanup()

	th.mu.Lock()
	_, present := th.entries[key]
	th.mu.Unlock()
	if present {
		t.Error("Cleanup did not drop the stale entry")
	}
}
