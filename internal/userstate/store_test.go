package userstate

import (
	"os"
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

func TestStoreSaveUsesPrivatePermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "state.json")
	store, err := New(path)
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}

	if err := store.Save(State{AllowOnce: true}); err != nil {
		t.Fatalf("Save returned error: %v", err)
	}

	dirInfo, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatalf("stat state directory: %v", err)
	}
	if got := dirInfo.Mode().Perm(); got&0o077 != 0 {
		t.Fatalf("expected private state directory permissions, got %o", got)
	}

	fileInfo, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat state file: %v", err)
	}
	if got := fileInfo.Mode().Perm(); got&0o077 != 0 {
		t.Fatalf("expected private state file permissions, got %o", got)
	}
}

func TestStoreSaveOverwritesExistingStateWithoutTempLeak(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	store, err := New(path)
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}

	if err := store.Save(State{AllowOnce: true}); err != nil {
		t.Fatalf("first Save returned error: %v", err)
	}

	want := State{
		SnoozedUntil: time.Unix(1_700_000_100, 0).UTC(),
	}
	if err := store.Save(want); err != nil {
		t.Fatalf("second Save returned error: %v", err)
	}

	got, err := store.Load()
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if !got.SnoozedUntil.Equal(want.SnoozedUntil) {
		t.Fatalf("unexpected snoozed_until: got %s want %s", got.SnoozedUntil, want.SnoozedUntil)
	}
	if got.AllowOnce {
		t.Fatal("expected allow_once to be overwritten")
	}

	matches, err := filepath.Glob(path + ".tmp-*")
	if err != nil {
		t.Fatalf("glob temp files: %v", err)
	}
	if len(matches) != 0 {
		t.Fatalf("expected no temporary state files, found %v", matches)
	}
}
