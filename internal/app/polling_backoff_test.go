package app

import (
	"testing"
	"time"

	"github.com/rhushabhbontapalle/guardmycopy/internal/config"
)

func TestAdaptivePollBackoffStartsAtNormalizedBase(t *testing.T) {
	backoff := newAdaptivePollBackoff(time.Millisecond)

	if backoff.Current() != config.MinPollInterval() {
		t.Fatalf("expected normalized base interval %s, got %s", config.MinPollInterval(), backoff.Current())
	}
}

func TestAdaptivePollBackoffBacksOffAfterSustainedUnchanged(t *testing.T) {
	base := 500 * time.Millisecond
	backoff := newAdaptivePollBackoff(base)

	for i := 0; i < idleBackoffUnchangedThreshold-1; i++ {
		if got := backoff.OnClipboardUnchanged(); got != base {
			t.Fatalf("expected base interval before threshold, got %s", got)
		}
	}

	if got := backoff.OnClipboardUnchanged(); got != time.Second {
		t.Fatalf("expected first backoff step to 1s, got %s", got)
	}

	for i := 0; i < idleBackoffUnchangedThreshold-1; i++ {
		if got := backoff.OnClipboardUnchanged(); got != time.Second {
			t.Fatalf("expected 1s before second threshold, got %s", got)
		}
	}

	if got := backoff.OnClipboardUnchanged(); got != idleBackoffMaxInterval {
		t.Fatalf("expected second backoff step to cap %s, got %s", idleBackoffMaxInterval, got)
	}

	for i := 0; i < idleBackoffUnchangedThreshold*2; i++ {
		if got := backoff.OnClipboardUnchanged(); got != idleBackoffMaxInterval {
			t.Fatalf("expected interval to stay capped at %s, got %s", idleBackoffMaxInterval, got)
		}
	}
}

func TestAdaptivePollBackoffResetsImmediatelyOnChange(t *testing.T) {
	base := 500 * time.Millisecond
	backoff := newAdaptivePollBackoff(base)

	for i := 0; i < idleBackoffUnchangedThreshold; i++ {
		backoff.OnClipboardUnchanged()
	}
	if backoff.Current() != time.Second {
		t.Fatalf("expected current interval 1s after first backoff, got %s", backoff.Current())
	}

	if got := backoff.OnClipboardChanged(); got != base {
		t.Fatalf("expected reset to base interval %s, got %s", base, got)
	}

	for i := 0; i < idleBackoffUnchangedThreshold-1; i++ {
		if got := backoff.OnClipboardUnchanged(); got != base {
			t.Fatalf("expected base interval after reset before threshold, got %s", got)
		}
	}
}

func TestAdaptivePollBackoffDoesNotDropBelowLargeBase(t *testing.T) {
	base := 3 * time.Second
	backoff := newAdaptivePollBackoff(base)

	for i := 0; i < idleBackoffUnchangedThreshold*3; i++ {
		if got := backoff.OnClipboardUnchanged(); got != base {
			t.Fatalf("expected large base interval %s to remain unchanged, got %s", base, got)
		}
	}
}
