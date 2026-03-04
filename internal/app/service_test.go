package app

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/rhushabhbontapalle/clipguard/internal/config"
	"github.com/rhushabhbontapalle/clipguard/internal/core"
)

type mockClipboard struct {
	value    string
	readErr  error
	writeErr error
	writes   int
}

func (m *mockClipboard) ReadText() (string, error) {
	if m.readErr != nil {
		return "", m.readErr
	}
	return m.value, nil
}

func (m *mockClipboard) WriteText(value string) error {
	if m.writeErr != nil {
		return m.writeErr
	}
	m.value = value
	m.writes++
	return nil
}

type mockNotifier struct {
	calls int
}

func (m *mockNotifier) Notify(_, _ string) error {
	m.calls++
	return nil
}

func TestSanitizeWritesWhenChanged(t *testing.T) {
	clip := &mockClipboard{value: "start\n-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----\nend"}
	svc := New(config.Defaults(), clip)

	changed, err := svc.Sanitize(false)
	if err != nil {
		t.Fatalf("Sanitize returned error: %v", err)
	}
	if !changed {
		t.Fatal("expected sanitize to report change")
	}
	if clip.writes != 1 {
		t.Fatalf("expected one write, got %d", clip.writes)
	}
	if clip.value != "start\n---******* ******* ********\n***\n******** ******* *****---\nend" {
		t.Fatalf("unexpected clipboard value: %q", clip.value)
	}
}

func TestSanitizeNoopWhenUnchanged(t *testing.T) {
	clip := &mockClipboard{value: "hello"}
	svc := New(config.Defaults(), clip)

	changed, err := svc.Sanitize(false)
	if err != nil {
		t.Fatalf("Sanitize returned error: %v", err)
	}
	if changed {
		t.Fatal("expected sanitize to be a no-op")
	}
	if clip.writes != 0 {
		t.Fatalf("expected no writes, got %d", clip.writes)
	}
}

func TestSanitizeSkipsDisabledDetector(t *testing.T) {
	cfg := config.Defaults()
	cfg.Global.DetectorToggles[core.FindingTypePEMPrivateKey] = false

	clip := &mockClipboard{value: "start\n-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----\nend"}
	svc := New(cfg, clip)

	changed, err := svc.Sanitize(false)
	if err != nil {
		t.Fatalf("Sanitize returned error: %v", err)
	}
	if changed {
		t.Fatal("expected sanitize to be skipped for disabled detector")
	}
	if clip.writes != 0 {
		t.Fatalf("expected no writes, got %d", clip.writes)
	}
}

func TestSanitizeWarnActionDoesNotWrite(t *testing.T) {
	cfg := config.Defaults()
	cfg.Global.Actions[core.RiskLevelHigh] = config.ActionWarn

	clip := &mockClipboard{value: "start\n-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----\nend"}
	notifier := &mockNotifier{}
	svc := NewWithDependencies(cfg, clip, nil, notifier)

	changed, err := svc.Sanitize(false)
	if err != nil {
		t.Fatalf("Sanitize returned error: %v", err)
	}
	if changed {
		t.Fatal("expected warn action to avoid clipboard mutation")
	}
	if clip.writes != 0 {
		t.Fatalf("expected no writes, got %d", clip.writes)
	}
	if notifier.calls != 1 {
		t.Fatalf("expected 1 notification, got %d", notifier.calls)
	}
}

func TestSanitizeBlockActionClearsClipboard(t *testing.T) {
	cfg := config.Defaults()
	cfg.Global.Actions[core.RiskLevelHigh] = config.ActionBlock

	clip := &mockClipboard{value: "start\n-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----\nend"}
	svc := New(cfg, clip)

	changed, err := svc.Sanitize(false)
	if err != nil {
		t.Fatalf("Sanitize returned error: %v", err)
	}
	if !changed {
		t.Fatal("expected block action to mutate clipboard")
	}
	if clip.writes != 1 {
		t.Fatalf("expected one write, got %d", clip.writes)
	}
	if clip.value != "" {
		t.Fatalf("expected clipboard to be cleared, got %q", clip.value)
	}
}

func TestRunStopsWhenContextCanceled(t *testing.T) {
	clip := &mockClipboard{value: "hello"}
	svc := New(config.Defaults(), clip)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := svc.Run(ctx, time.Millisecond)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context canceled, got %v", err)
	}
}
