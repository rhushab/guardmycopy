package app

import (
	"time"

	"github.com/rhushabhbontapalle/guardmycopy/internal/config"
)

const (
	idleBackoffUnchangedThreshold = 4
	idleBackoffMaxInterval        = 2 * time.Second
)

type adaptivePollBackoff struct {
	baseInterval    time.Duration
	current         time.Duration
	maxInterval     time.Duration
	unchangedStreak int
}

func newAdaptivePollBackoff(baseInterval time.Duration) adaptivePollBackoff {
	normalizedBase := config.NormalizePollInterval(baseInterval)
	maxInterval := idleBackoffMaxInterval
	if maxInterval < normalizedBase {
		maxInterval = normalizedBase
	}

	return adaptivePollBackoff{
		baseInterval: normalizedBase,
		current:      normalizedBase,
		maxInterval:  maxInterval,
	}
}

func (b *adaptivePollBackoff) Current() time.Duration {
	return b.current
}

func (b *adaptivePollBackoff) OnClipboardUnchanged() time.Duration {
	b.unchangedStreak++
	if b.unchangedStreak < idleBackoffUnchangedThreshold {
		return b.current
	}

	b.unchangedStreak = 0
	next := b.current * 2
	if next < b.current || next > b.maxInterval {
		next = b.maxInterval
	}
	b.current = next
	return b.current
}

func (b *adaptivePollBackoff) OnClipboardChanged() time.Duration {
	b.unchangedStreak = 0
	b.current = b.baseInterval
	return b.current
}
