package app

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/rhushabhbontapalle/clipguard/internal/config"
)

type mockClipboard struct {
	value    string
	readErr  error
	writeErr error
	writes   int
}

func (m *mockClipboard) Read() (string, error) {
	if m.readErr != nil {
		return "", m.readErr
	}
	return m.value, nil
}

func (m *mockClipboard) Write(value string) error {
	if m.writeErr != nil {
		return m.writeErr
	}
	m.value = value
	m.writes++
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
