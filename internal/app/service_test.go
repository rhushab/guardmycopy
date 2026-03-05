package app

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rhushab/guardmycopy/internal/auditlog"
	"github.com/rhushab/guardmycopy/internal/config"
	"github.com/rhushab/guardmycopy/internal/core"
	"github.com/rhushab/guardmycopy/internal/userstate"
)

type mockClipboard struct {
	value    string
	readErr  error
	writeErr error
	reads    int
	writes   int
	readHook func()
}

func (m *mockClipboard) ReadText() (string, error) {
	m.reads++
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

type mockClipboardWithChangeDetector struct {
	*mockClipboard
	changeCounts     []int64
	changeCountErr   error
	changeCountCalls int
	changeCountHook  func(call int)
}

func (m *mockClipboardWithChangeDetector) ChangeCount() (int64, error) {
	m.changeCountCalls++
	if m.changeCountHook != nil {
		m.changeCountHook(m.changeCountCalls)
	}
	if m.changeCountErr != nil {
		return 0, m.changeCountErr
	}
	if len(m.changeCounts) == 0 {
		return 0, nil
	}

	index := m.changeCountCalls - 1
	if index >= len(m.changeCounts) {
		index = len(m.changeCounts) - 1
	}
	return m.changeCounts[index], nil
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

func TestApplyActionBlockNoopWhenClipboardAlreadyBlocked(t *testing.T) {
	clip := &mockClipboard{value: blockedClipboardValue}
	notifier := &mockNotifier{}
	svc := NewWithDependencies(config.Defaults(), clip, nil, notifier)

	decision := PolicyDecision{
		ActiveAppName: "Slack",
		Score:         15,
		RiskLevel:     core.RiskLevelHigh,
		Action:        config.ActionBlock,
	}

	changed, nextValue, err := svc.applyAction(decision, blockedClipboardValue, blockedClipboardValue, hashText("secret payload"))
	if err != nil {
		t.Fatalf("applyAction returned error: %v", err)
	}
	if changed {
		t.Fatal("expected block action to no-op when clipboard is already blocked")
	}
	if nextValue != blockedClipboardValue {
		t.Fatalf("expected blocked marker to remain unchanged, got %q", nextValue)
	}
	if clip.writes != 0 {
		t.Fatalf("expected no clipboard writes, got %d", clip.writes)
	}
	if notifier.calls != 0 {
		t.Fatalf("expected no notification for redundant block, got %d", notifier.calls)
	}
}

func TestApplyActionSanitizeNoopWhenClipboardAlreadySanitized(t *testing.T) {
	current := "prefix\n---******* ******* ********\n***\n******** ******* *****---\nsuffix"
	clip := &mockClipboard{value: current}
	notifier := &mockNotifier{}
	svc := NewWithDependencies(config.Defaults(), clip, nil, notifier)

	decision := PolicyDecision{
		ActiveAppName: "Google Chrome",
		Score:         8,
		RiskLevel:     core.RiskLevelMed,
		Action:        config.ActionSanitize,
	}

	changed, nextValue, err := svc.applyAction(decision, current, current, hashText("secret payload"))
	if err != nil {
		t.Fatalf("applyAction returned error: %v", err)
	}
	if changed {
		t.Fatal("expected sanitize action to no-op when clipboard already matches sanitized value")
	}
	if nextValue != current {
		t.Fatalf("expected sanitized clipboard to remain unchanged, got %q", nextValue)
	}
	if clip.writes != 0 {
		t.Fatalf("expected no clipboard writes, got %d", clip.writes)
	}
	if notifier.calls != 0 {
		t.Fatalf("expected no notification for redundant sanitize, got %d", notifier.calls)
	}
}

func TestShouldNotifyEvictsExpiredHashes(t *testing.T) {
	clip := &mockClipboard{}
	svc := New(config.Defaults(), clip)

	now := time.Unix(100, 0)
	svc.timeNow = func() time.Time { return now }

	firstHash := hashText("first secret")
	secondHash := hashText("second secret")
	thirdHash := hashText("third secret")

	if !svc.shouldNotify(firstHash) {
		t.Fatal("expected first hash to notify")
	}

	now = now.Add(500 * time.Millisecond)
	if !svc.shouldNotify(secondHash) {
		t.Fatal("expected second hash to notify")
	}
	if len(svc.lastAlertByHash) != 2 {
		t.Fatalf("expected 2 cached hashes, got %d", len(svc.lastAlertByHash))
	}

	now = now.Add(600 * time.Millisecond)
	if !svc.shouldNotify(thirdHash) {
		t.Fatal("expected third hash to notify")
	}
	if len(svc.lastAlertByHash) != 2 {
		t.Fatalf("expected cache to evict expired entries, got %d", len(svc.lastAlertByHash))
	}
	if _, ok := svc.lastAlertByHash[firstHash]; ok {
		t.Fatal("expected first hash entry to be evicted")
	}
	if _, ok := svc.lastAlertByHash[secondHash]; !ok {
		t.Fatal("expected second hash entry to remain")
	}
	if _, ok := svc.lastAlertByHash[thirdHash]; !ok {
		t.Fatal("expected third hash entry to be present")
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

func TestRunContinuesAfterTransientClipboardChangeCountFailure(t *testing.T) {
	clip := &mockClipboardWithChangeDetector{
		mockClipboard: &mockClipboard{
			value: "start\n-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----\nend",
		},
		changeCountErr: errors.New("pasteboard temporarily unavailable"),
	}
	clip.changeCountHook = func(call int) {
		if call > 1 {
			clip.changeCountErr = nil
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	clip.readHook = func() {
		cancel()
		clip.readHook = nil
	}

	var warnings bytes.Buffer
	svc := New(config.Defaults(), clip)
	svc.SetWarningOutput(&warnings)

	err := svc.Run(ctx, time.Millisecond)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context canceled, got %v", err)
	}
	if clip.reads != 1 {
		t.Fatalf("expected one clipboard read after change count failure, got %d", clip.reads)
	}
	if clip.writes != 1 {
		t.Fatalf("expected enforcement to continue after change count failure, got %d writes", clip.writes)
	}
	if !strings.Contains(warnings.String(), "clipboard change count unavailable") {
		t.Fatalf("expected change count warning, got %q", warnings.String())
	}
}

func TestRunContinuesAfterTransientClipboardReadFailure(t *testing.T) {
	clip := &mockClipboard{
		value: "start\n-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----\nend",
	}
	clip.readHook = func() {
		switch clip.reads {
		case 1:
			clip.readErr = errors.New("pasteboard temporarily unavailable")
		default:
			clip.readErr = nil
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	initialHook := clip.readHook
	clip.readHook = func() {
		initialHook()
		if clip.reads == 2 {
			cancel()
			clip.readHook = nil
		}
	}

	var warnings bytes.Buffer
	svc := New(config.Defaults(), clip)
	svc.SetWarningOutput(&warnings)

	err := svc.Run(ctx, time.Millisecond)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context canceled, got %v", err)
	}
	if clip.reads != 2 {
		t.Fatalf("expected run to retry after read failure, got %d reads", clip.reads)
	}
	if clip.writes != 1 {
		t.Fatalf("expected enforcement after retry, got %d writes", clip.writes)
	}
	if !strings.Contains(warnings.String(), "clipboard read failed; retrying") {
		t.Fatalf("expected clipboard read warning, got %q", warnings.String())
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

func TestRunReenforcesWhenSnoozeExpiresWithoutClipboardOrAppChange(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	snoozedUntil := now.Add(time.Minute)

	clip := &mockClipboardWithChangeDetector{
		mockClipboard: &mockClipboard{
			value: "start\n-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----\nend",
		},
		changeCounts: []int64{7, 7, 8},
	}
	notifier := &mockNotifier{}
	foreground := &mockForegroundApp{name: "Slack", bundleID: "com.tinyspeck.slackmacgap"}
	stateStore := &mockRuntimeStateStore{
		state: userstate.State{
			SnoozedUntil: snoozedUntil,
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	clip.changeCountHook = func(call int) {
		switch call {
		case 2:
			now = snoozedUntil.Add(time.Millisecond)
		case 3:
			cancel()
			clip.changeCountHook = nil
		}
	}

	svc := NewWithDependencies(config.Defaults(), clip, foreground, notifier)
	svc.timeNow = func() time.Time { return now }
	svc.SetRuntimeStateStore(stateStore)

	err := svc.Run(ctx, time.Millisecond)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context canceled, got %v", err)
	}
	if clip.reads != 2 {
		t.Fatalf("expected two clipboard reads across snooze expiry, got %d", clip.reads)
	}
	if clip.writes != 1 {
		t.Fatalf("expected one clipboard write after snooze expiry, got %d", clip.writes)
	}
	if clip.value != blockedClipboardValue {
		t.Fatalf("expected clipboard to be blocked after snooze expiry, got %q", clip.value)
	}
	if notifier.calls != 1 {
		t.Fatalf("expected one notification after snooze expiry, got %d", notifier.calls)
	}
	if stateStore.saveCalls != 1 {
		t.Fatalf("expected expired snooze to be persisted once, got %d saves", stateStore.saveCalls)
	}
	if !stateStore.state.SnoozedUntil.IsZero() {
		t.Fatalf("expected snooze to be cleared after expiry, got %s", stateStore.state.SnoozedUntil)
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

func TestScanCurrentDetailedReportsForegroundAppFailureFallback(t *testing.T) {
	cfg := config.Defaults()
	slackPolicy := clonePolicy(cfg.Global)
	slackPolicy.Actions[core.RiskLevelHigh] = config.ActionAllow
	cfg.PerApp["Slack"] = slackPolicy

	clip := &mockClipboard{value: "start\n-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----\nend"}
	foreground := &mockForegroundApp{err: errors.New("osascript active app failed: accessibility denied")}
	svc := NewWithDependencies(cfg, clip, foreground, nil)

	decision, reasoning, err := svc.ScanCurrentDetailed()
	if err != nil {
		t.Fatalf("ScanCurrentDetailed returned error: %v", err)
	}
	if decision.Action != config.ActionBlock {
		t.Fatalf("expected global block fallback, got %s", decision.Action)
	}
	if decision.PolicySource != PolicySourceGlobalFallbackAppDetectionFailed {
		t.Fatalf("unexpected policy source: %q", decision.PolicySource)
	}
	if decision.AppContextStatus != AppContextStatusResolutionFailed {
		t.Fatalf("unexpected app context status: %q", decision.AppContextStatus)
	}

	joined := strings.Join(reasoning, "\n")
	if !strings.Contains(joined, "foreground app detection failed: osascript active app failed: accessibility denied") {
		t.Fatalf("expected failure reasoning, got %q", joined)
	}
	if !strings.Contains(joined, "global policy was used because app context could not be resolved; per-app overrides were skipped") {
		t.Fatalf("expected explicit global fallback reasoning, got %q", joined)
	}
}

func TestScanCurrentDetailedDebouncesForegroundAppWarnings(t *testing.T) {
	clip := &mockClipboard{value: "hello"}
	foreground := &mockForegroundApp{err: errors.New("osascript active app failed: accessibility denied")}
	svc := NewWithDependencies(config.Defaults(), clip, foreground, nil)

	var warnings bytes.Buffer
	svc.SetWarningOutput(&warnings)

	now := time.Unix(1_700_000_000, 0).UTC()
	svc.timeNow = func() time.Time { return now }

	if _, _, err := svc.ScanCurrentDetailed(); err != nil {
		t.Fatalf("first ScanCurrentDetailed returned error: %v", err)
	}
	if _, _, err := svc.ScanCurrentDetailed(); err != nil {
		t.Fatalf("second ScanCurrentDetailed returned error: %v", err)
	}
	if got := strings.Count(warnings.String(), "warning: foreground app detection failed"); got != 1 {
		t.Fatalf("expected 1 debounced warning, got %d (%q)", got, warnings.String())
	}

	now = now.Add(svc.warningDebounce + time.Millisecond)
	if _, _, err := svc.ScanCurrentDetailed(); err != nil {
		t.Fatalf("third ScanCurrentDetailed returned error: %v", err)
	}
	if got := strings.Count(warnings.String(), "warning: foreground app detection failed"); got != 2 {
		t.Fatalf("expected warning after debounce window, got %d (%q)", got, warnings.String())
	}
}

func TestScanCurrentDetailedWritesAuditAppContextMetadataOnFailure(t *testing.T) {
	clip := &mockClipboard{value: "start\n-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----\nend"}
	foreground := &mockForegroundApp{err: errors.New("osascript active app failed: accessibility denied")}
	svc := NewWithDependencies(config.Defaults(), clip, foreground, nil)

	auditStore := &mockAuditLogStore{}
	svc.SetAuditLogStore(auditStore)

	if _, _, err := svc.ScanCurrentDetailed(); err != nil {
		t.Fatalf("ScanCurrentDetailed returned error: %v", err)
	}
	if len(auditStore.entries) != 1 {
		t.Fatalf("expected 1 audit entry, got %d", len(auditStore.entries))
	}

	metadata := auditStore.entries[0].AppContext
	if metadata == nil {
		t.Fatal("expected app context metadata on failure")
	}
	if metadata.Status != string(AppContextStatusResolutionFailed) {
		t.Fatalf("unexpected app context status: %q", metadata.Status)
	}
	if metadata.PolicySource != string(PolicySourceGlobalFallbackAppDetectionFailed) {
		t.Fatalf("unexpected app context policy source: %q", metadata.PolicySource)
	}
	if !strings.Contains(metadata.Error, "osascript active app failed: accessibility denied") {
		t.Fatalf("unexpected app context error: %q", metadata.Error)
	}
}
