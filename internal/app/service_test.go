package app

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rhushabhbontapalle/guardmycopy/internal/auditlog"
	"github.com/rhushabhbontapalle/guardmycopy/internal/config"
	"github.com/rhushabhbontapalle/guardmycopy/internal/core"
	"github.com/rhushabhbontapalle/guardmycopy/internal/userstate"
)

type mockClipboard struct {
	value    string
	readErr  error
	writeErr error
	writes   int
	readHook func()
}

func (m *mockClipboard) ReadText() (string, error) {
	if m.readHook != nil {
		m.readHook()
	}
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

type mockRuntimeStateStore struct {
	state     userstate.State
	loadErr   error
	saveErr   error
	saveCalls int
}

func (m *mockRuntimeStateStore) Load() (userstate.State, error) {
	if m.loadErr != nil {
		return userstate.State{}, m.loadErr
	}
	return m.state, nil
}

func (m *mockRuntimeStateStore) Save(state userstate.State) error {
	if m.saveErr != nil {
		return m.saveErr
	}
	m.state = state
	m.saveCalls++
	return nil
}

type mockAuditLogStore struct {
	logErr  error
	entries []auditlog.Entry
}

func (m *mockAuditLogStore) Log(entry auditlog.Entry) error {
	if m.logErr != nil {
		return m.logErr
	}
	m.entries = append(m.entries, entry)
	return nil
}

func TestSanitizeWritesWhenChanged(t *testing.T) {
	cfg := config.Defaults()
	cfg.Global.Actions[core.RiskLevelHigh] = config.ActionSanitize

	clip := &mockClipboard{value: "start\n-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----\nend"}
	svc := New(cfg, clip)

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
	notifier := &mockNotifier{}
	svc := NewWithDependencies(cfg, clip, nil, notifier)

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
	if clip.value != blockedClipboardValue {
		t.Fatalf("expected clipboard to be blocked marker, got %q", clip.value)
	}
	if notifier.calls != 1 {
		t.Fatalf("expected 1 notification, got %d", notifier.calls)
	}
}

func TestScanCurrentReportsDecision(t *testing.T) {
	clip := &mockClipboard{value: "start\n-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----\nend"}
	svc := New(config.Defaults(), clip)

	decision, err := svc.ScanCurrent()
	if err != nil {
		t.Fatalf("ScanCurrent returned error: %v", err)
	}
	if decision.Action != config.ActionBlock {
		t.Fatalf("expected block action, got %s", decision.Action)
	}
	if decision.RiskLevel != core.RiskLevelHigh {
		t.Fatalf("expected high risk level, got %s", decision.RiskLevel)
	}
	if decision.Score != 15 {
		t.Fatalf("expected score 15, got %d", decision.Score)
	}
	if decision.Findings != 1 {
		t.Fatalf("expected 1 finding, got %d", decision.Findings)
	}
}

func TestScanCurrentTreatsClipboardAllowlistAsAllow(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "guardmycopy.yaml")

	content := `global:
  allowlist_patterns:
    - 'PRIVATE KEY'
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}

	clip := &mockClipboard{value: "start\n-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----\nend"}
	svc := New(cfg, clip)

	decision, err := svc.ScanCurrent()
	if err != nil {
		t.Fatalf("ScanCurrent returned error: %v", err)
	}
	if decision.Action != config.ActionAllow {
		t.Fatalf("expected allow action, got %s", decision.Action)
	}
	if decision.Score != 0 {
		t.Fatalf("expected score 0, got %d", decision.Score)
	}
	if decision.Findings != 0 {
		t.Fatalf("expected 0 findings, got %d", decision.Findings)
	}
	if !decision.Allowlisted {
		t.Fatal("expected allowlisted=true")
	}
}

func TestApplyActionDebouncesNotificationsPerHash(t *testing.T) {
	cfg := config.Defaults()
	clip := &mockClipboard{}
	notifier := &mockNotifier{}
	svc := NewWithDependencies(cfg, clip, nil, notifier)

	now := time.Unix(100, 0)
	svc.timeNow = func() time.Time { return now }

	decision := PolicyDecision{
		ActiveAppName: "Terminal",
		Score:         15,
		RiskLevel:     core.RiskLevelHigh,
		Action:        config.ActionWarn,
	}
	contentHash := hashText("secret payload")

	if _, _, err := svc.applyAction(decision, "secret payload", "secret payload", contentHash); err != nil {
		t.Fatalf("first applyAction returned error: %v", err)
	}
	if notifier.calls != 1 {
		t.Fatalf("expected first notification, got %d calls", notifier.calls)
	}

	now = now.Add(500 * time.Millisecond)
	if _, _, err := svc.applyAction(decision, "secret payload", "secret payload", contentHash); err != nil {
		t.Fatalf("second applyAction returned error: %v", err)
	}
	if notifier.calls != 1 {
		t.Fatalf("expected debounce to suppress second notification, got %d calls", notifier.calls)
	}

	now = now.Add(600 * time.Millisecond)
	if _, _, err := svc.applyAction(decision, "secret payload", "secret payload", contentHash); err != nil {
		t.Fatalf("third applyAction returned error: %v", err)
	}
	if notifier.calls != 2 {
		t.Fatalf("expected notification after debounce window, got %d calls", notifier.calls)
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

func TestShouldBypassEnforcementSnoozed(t *testing.T) {
	clip := &mockClipboard{value: "secret"}
	svc := New(config.Defaults(), clip)

	now := time.Unix(1_700_000_000, 0).UTC()
	svc.timeNow = func() time.Time { return now }

	stateStore := &mockRuntimeStateStore{
		state: userstate.State{
			SnoozedUntil: now.Add(5 * time.Minute),
		},
	}
	svc.SetRuntimeStateStore(stateStore)

	bypass, reason, err := svc.shouldBypassEnforcement()
	if err != nil {
		t.Fatalf("shouldBypassEnforcement returned error: %v", err)
	}
	if !bypass {
		t.Fatal("expected bypass to be true")
	}
	if reason == "" {
		t.Fatal("expected bypass reason")
	}
	if stateStore.saveCalls != 0 {
		t.Fatalf("expected no save calls, got %d", stateStore.saveCalls)
	}
}

func TestShouldBypassEnforcementConsumesAllowOnce(t *testing.T) {
	clip := &mockClipboard{value: "secret"}
	svc := New(config.Defaults(), clip)

	now := time.Unix(1_700_000_000, 0).UTC()
	svc.timeNow = func() time.Time { return now }

	stateStore := &mockRuntimeStateStore{
		state: userstate.State{
			AllowOnce: true,
		},
	}
	svc.SetRuntimeStateStore(stateStore)

	bypass, reason, err := svc.shouldBypassEnforcement()
	if err != nil {
		t.Fatalf("shouldBypassEnforcement returned error: %v", err)
	}
	if !bypass {
		t.Fatal("expected bypass to be true")
	}
	if reason != "allow-once consumed" {
		t.Fatalf("unexpected reason: %q", reason)
	}
	if stateStore.state.AllowOnce {
		t.Fatal("expected allow_once to be consumed")
	}
	if stateStore.saveCalls != 1 {
		t.Fatalf("expected one save call, got %d", stateStore.saveCalls)
	}
}

func TestRunRespectsAllowOnceState(t *testing.T) {
	clip := &mockClipboard{value: "start\n-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----\nend"}
	svc := New(config.Defaults(), clip)

	stateStore := &mockRuntimeStateStore{
		state: userstate.State{
			AllowOnce: true,
		},
	}
	svc.SetRuntimeStateStore(stateStore)

	ctx, cancel := context.WithCancel(context.Background())
	clip.readHook = func() {
		cancel()
		clip.readHook = nil
	}

	err := svc.Run(ctx, time.Millisecond)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context canceled, got %v", err)
	}
	if clip.writes != 0 {
		t.Fatalf("expected run to skip enforcement due to allow-once, writes=%d", clip.writes)
	}
	if stateStore.state.AllowOnce {
		t.Fatal("expected allow_once to be consumed during run")
	}
}

func TestScanCurrentDetailedWritesAuditEntry(t *testing.T) {
	clip := &mockClipboard{value: "start\n-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----\nend"}
	svc := New(config.Defaults(), clip)

	fixedTime := time.Unix(1_700_000_000, 0).UTC()
	svc.timeNow = func() time.Time { return fixedTime }

	auditStore := &mockAuditLogStore{}
	svc.SetAuditLogStore(auditStore)

	decision, _, err := svc.ScanCurrentDetailed()
	if err != nil {
		t.Fatalf("ScanCurrentDetailed returned error: %v", err)
	}
	if len(auditStore.entries) != 1 {
		t.Fatalf("expected 1 audit entry, got %d", len(auditStore.entries))
	}

	entry := auditStore.entries[0]
	if !entry.Timestamp.Equal(fixedTime) {
		t.Fatalf("unexpected timestamp: got %s want %s", entry.Timestamp, fixedTime)
	}
	if entry.App != decision.ActiveAppName {
		t.Fatalf("unexpected app: got %q want %q", entry.App, decision.ActiveAppName)
	}
	if entry.Score != 15 {
		t.Fatalf("unexpected score: got %d want 15", entry.Score)
	}
	if entry.RiskLevel != string(core.RiskLevelHigh) {
		t.Fatalf("unexpected risk level: %q", entry.RiskLevel)
	}
	if entry.Action != string(config.ActionBlock) {
		t.Fatalf("unexpected action: %q", entry.Action)
	}
	if len(entry.FindingTypes) != 1 || entry.FindingTypes[0] != core.FindingTypePEMPrivateKey {
		t.Fatalf("unexpected finding types: %#v", entry.FindingTypes)
	}

	expectedHash := hashToHex(hashText(clip.value))
	if entry.ContentHash != expectedHash {
		t.Fatalf("unexpected content hash: got %q want %q", entry.ContentHash, expectedHash)
	}
}

func TestScanCurrentDetailedIgnoresAuditWriteErrors(t *testing.T) {
	clip := &mockClipboard{value: "hello"}
	svc := New(config.Defaults(), clip)
	svc.SetAuditLogStore(&mockAuditLogStore{logErr: errors.New("disk full")})

	if _, _, err := svc.ScanCurrentDetailed(); err != nil {
		t.Fatalf("ScanCurrentDetailed should ignore audit log errors, got %v", err)
	}
}
