package userstate

import (
	"path/filepath"
	"testing"
	"time"
)

func TestStoreLoadMissingReturnsEmptyState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	store, err := New(path)
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}

	state, err := store.Load()
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if !state.SnoozedUntil.IsZero() {
		t.Fatalf("expected zero snoozed_until, got %s", state.SnoozedUntil)
	}
	if state.AllowOnce {
		t.Fatal("expected allow_once false")
	}
}

func TestStoreSaveAndLoadRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	store, err := New(path)
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}

	want := State{
		SnoozedUntil: time.Unix(1_700_000_000, 0).UTC(),
		AllowOnce:    true,
	}
	if err := store.Save(want); err != nil {
		t.Fatalf("Save returned error: %v", err)
	}

	got, err := store.Load()
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}

	if !got.SnoozedUntil.Equal(want.SnoozedUntil) {
		t.Fatalf("unexpected snoozed_until: got %s want %s", got.SnoozedUntil, want.SnoozedUntil)
	}
	if got.AllowOnce != want.AllowOnce {
		t.Fatalf("unexpected allow_once: got %t want %t", got.AllowOnce, want.AllowOnce)
	}
}
