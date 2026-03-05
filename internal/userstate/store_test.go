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

func TestEnforcementDegraded(t *testing.T) {
	tests := []struct {
		name  string
		state State
		want  bool
	}{
		{
			name:  "empty state is not degraded",
			state: State{},
			want:  false,
		},
		{
			name: "error with count is degraded",
			state: State{
				LastEnforcementError:   "write clipboard: pasteboard unavailable",
				LastEnforcementErrorAt: time.Unix(1_700_000_000, 0).UTC(),
				ConsecutiveErrors:      1,
			},
			want: true,
		},
		{
			name: "error without count is not degraded",
			state: State{
				LastEnforcementError: "stale error",
			},
			want: false,
		},
		{
			name: "count without error is not degraded",
			state: State{
				ConsecutiveErrors: 1,
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.state.EnforcementDegraded()
			if got != tt.want {
				t.Fatalf("EnforcementDegraded() = %t, want %t", got, tt.want)
			}
		})
	}
}

func TestStoreSaveAndLoadHealthRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	store, err := New(path)
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}

	errorTime := time.Unix(1_700_000_000, 0).UTC()
	want := State{
		AllowOnce:              true,
		LastEnforcementError:   "write clipboard: pasteboard unavailable",
		LastEnforcementErrorAt: errorTime,
		ConsecutiveErrors:      3,
	}
	if err := store.Save(want); err != nil {
		t.Fatalf("Save returned error: %v", err)
	}

	got, err := store.Load()
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if got.LastEnforcementError != want.LastEnforcementError {
		t.Fatalf("unexpected last_enforcement_error: got %q want %q", got.LastEnforcementError, want.LastEnforcementError)
	}
	if !got.LastEnforcementErrorAt.Equal(want.LastEnforcementErrorAt) {
		t.Fatalf("unexpected last_enforcement_error_at: got %s want %s", got.LastEnforcementErrorAt, want.LastEnforcementErrorAt)
	}
	if got.ConsecutiveErrors != want.ConsecutiveErrors {
		t.Fatalf("unexpected consecutive_errors: got %d want %d", got.ConsecutiveErrors, want.ConsecutiveErrors)
	}
}
