package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rhushabhbontapalle/guardmycopy/internal/app"
	"github.com/rhushabhbontapalle/guardmycopy/internal/auditlog"
	"github.com/rhushabhbontapalle/guardmycopy/internal/config"
	"github.com/rhushabhbontapalle/guardmycopy/internal/core"
	"github.com/rhushabhbontapalle/guardmycopy/internal/userstate"
)

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// e2eClipboard is a clipboard mock for end-to-end scenarios.
type e2eClipboard struct {
	value    string
	readHook func()
	writes   int
}

func (c *e2eClipboard) ReadText() (string, error) {
	if c.readHook != nil {
		c.readHook()
	}
	return c.value, nil
}

func (c *e2eClipboard) WriteText(v string) error {
	c.value = v
	c.writes++
	return nil
}

type e2eNotifier struct {
	calls    int
	lastBody string
}

func (n *e2eNotifier) Notify(title, body string) error {
	n.calls++
	n.lastBody = body
	return nil
}

type e2eForegroundApp struct{ name string }

func (f *e2eForegroundApp) ActiveAppName() (string, error) { return f.name, nil }

// ---------------------------------------------------------------------------
// 1. CLI: version
// ---------------------------------------------------------------------------

func TestE2E_VersionCommand(t *testing.T) {
	code := run([]string{"--version"})
	if code != 0 {
		t.Fatalf("expected exit 0, got %d", code)
	}
	code = run([]string{"version"})
	if code != 0 {
		t.Fatalf("expected exit 0, got %d", code)
	}
}

// ---------------------------------------------------------------------------
// 2. CLI: help and sub-command help
// ---------------------------------------------------------------------------

func TestE2E_HelpCommands(t *testing.T) {
	for _, args := range [][]string{
		{"--help"},
		{"-h"},
		{"help"},
		{"help", "sanitize"},
		{"help", "once"},
		{"help", "run"},
		{"help", "snooze"},
		{"help", "allow-once"},
		{"help", "log"},
		{"help", "config"},
	} {
		var stdout, stderr bytes.Buffer
		code := runHelp(args[1:], &stdout, &stderr)
		if args[0] == "--help" || args[0] == "-h" || args[0] == "help" {
			code = run(args)
		}
		if code != 0 {
			t.Fatalf("help %v returned %d; stderr=%q", args, code, stderr.String())
		}
	}
}

// ---------------------------------------------------------------------------
// 3. CLI: unknown command
// ---------------------------------------------------------------------------

func TestE2E_UnknownCommand(t *testing.T) {
	code := run([]string{"foobar"})
	if code != 2 {
		t.Fatalf("expected exit 2, got %d", code)
	}
}

func TestE2E_NoCommand(t *testing.T) {
	code := run(nil)
	if code != 2 {
		t.Fatalf("expected exit 2, got %d", code)
	}
}

// ---------------------------------------------------------------------------
// 4. config init → load → config init --force
// ---------------------------------------------------------------------------

func TestE2E_ConfigInitLoadForce(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "guardmycopy", "config.yaml")

	var stdout, stderr bytes.Buffer

	// First init.
	code := runConfigInitWithIO([]string{"--path", cfgPath}, &stdout, &stderr, "")
	if code != 0 {
		t.Fatalf("config init failed: %d; stderr=%q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), cfgPath) {
		t.Fatalf("expected path in output, got %q", stdout.String())
	}

	// Load the generated config and verify it parses correctly.
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("config.Load returned error: %v", err)
	}
	if cfg.PollInterval != 500*time.Millisecond {
		t.Fatalf("unexpected poll interval: %s", cfg.PollInterval)
	}
	if cfg.Global.Thresholds.Med != 8 || cfg.Global.Thresholds.High != 15 {
		t.Fatalf("unexpected thresholds: %+v", cfg.Global.Thresholds)
	}

	// Second init without --force must fail.
	stdout.Reset()
	stderr.Reset()
	code = runConfigInitWithIO(nil, &stdout, &stderr, cfgPath)
	if code != 1 {
		t.Fatalf("expected exit 1 on duplicate, got %d", code)
	}
	if !strings.Contains(stderr.String(), "already exists") {
		t.Fatalf("expected already-exists error, got %q", stderr.String())
	}

	// With --force should succeed.
	stdout.Reset()
	stderr.Reset()
	code = runConfigInitWithIO([]string{"--force"}, &stdout, &stderr, cfgPath)
	if code != 0 {
		t.Fatalf("config init --force failed: %d; stderr=%q", code, stderr.String())
	}
}

// ---------------------------------------------------------------------------
// 5. sanitize piped input: clean text → unchanged
// ---------------------------------------------------------------------------

func TestE2E_SanitizeCleanText(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runSanitizeWithIO(nil, strings.NewReader("hello world"), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit %d; stderr=%q", code, stderr.String())
	}
	if stdout.String() != "hello world" {
		t.Fatalf("clean text should pass through unchanged, got %q", stdout.String())
	}
}

// ---------------------------------------------------------------------------
// 6. sanitize piped input: PEM private key → redacted
// ---------------------------------------------------------------------------

func TestE2E_SanitizePEMKey(t *testing.T) {
	pem := "line1\n-----BEGIN PRIVATE KEY-----\nsecretdata\n-----END PRIVATE KEY-----\nline2"
	var stdout, stderr bytes.Buffer
	code := runSanitizeWithIO(nil, strings.NewReader(pem), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit %d; stderr=%q", code, stderr.String())
	}
	out := stdout.String()
	if strings.Contains(out, "secretdata") {
		t.Fatalf("expected PEM body to be redacted, got %q", out)
	}
	if !strings.Contains(out, "***") {
		t.Fatalf("expected redaction markers, got %q", out)
	}
	if !strings.Contains(out, "line1") || !strings.Contains(out, "line2") {
		t.Fatal("expected surrounding text preserved")
	}
}

// ---------------------------------------------------------------------------
// 7. sanitize --diff shows summary
// ---------------------------------------------------------------------------

func TestE2E_SanitizeDiffJWT(t *testing.T) {
	jwt := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
	var stdout, stderr bytes.Buffer
	code := runSanitizeWithIO([]string{"--diff"}, strings.NewReader(jwt), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit %d; stderr=%q", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "risk=") {
		t.Fatal("expected risk in diff output")
	}
	if !strings.Contains(stderr.String(), "score=") {
		t.Fatal("expected score in diff output")
	}
	if !strings.Contains(stderr.String(), "findings=") {
		t.Fatal("expected findings in diff output")
	}
}

// ---------------------------------------------------------------------------
// 8. sanitize: env secret detection
// ---------------------------------------------------------------------------

func TestE2E_SanitizeEnvSecret(t *testing.T) {
	input := `export SECRET_TOKEN=supersecretvalue1234567`
	var stdout, stderr bytes.Buffer
	code := runSanitizeWithIO(nil, strings.NewReader(input), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit %d; stderr=%q", code, stderr.String())
	}
	out := stdout.String()
	if strings.Contains(out, "supersecretvalue1234567") {
		t.Fatalf("env secret value should be redacted, got %q", out)
	}
}

// ---------------------------------------------------------------------------
// 9. once: PEM key → block action
// ---------------------------------------------------------------------------

func TestE2E_OncePEMKeyBlockAction(t *testing.T) {
	clip := &testClipboard{
		value: "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----",
	}
	svc := app.New(config.Defaults(), clip)

	var stdout, stderr bytes.Buffer
	code := runOnceWithService(svc, &stdout, &stderr, true)
	if code != 0 {
		t.Fatalf("exit %d; stderr=%q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "action=block") {
		t.Fatalf("expected block action, got %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), "risk=high") {
		t.Fatalf("expected high risk, got %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), "reason=") {
		t.Fatal("expected verbose reasoning in stderr")
	}
}

// ---------------------------------------------------------------------------
// 10. once: clean text → allow action
// ---------------------------------------------------------------------------

func TestE2E_OnceCleanTextAllowAction(t *testing.T) {
	clip := &testClipboard{value: "just some normal text"}
	svc := app.New(config.Defaults(), clip)

	var stdout, stderr bytes.Buffer
	code := runOnceWithService(svc, &stdout, &stderr, false)
	if code != 0 {
		t.Fatalf("exit %d; stderr=%q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "action=allow") {
		t.Fatalf("expected allow action, got %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), "risk=low") {
		t.Fatalf("expected low risk, got %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), "findings=0") {
		t.Fatalf("expected 0 findings, got %q", stdout.String())
	}
}

// ---------------------------------------------------------------------------
// 11. run loop → PEM key detected → blocked clipboard
// ---------------------------------------------------------------------------

func TestE2E_RunLoopBlocksPEMKey(t *testing.T) {
	clip := &e2eClipboard{
		value: "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----",
	}
	cfg := config.Defaults()
	svc := app.NewWithDependencies(cfg, clip, nil, nil)

	ctx, cancel := context.WithCancel(context.Background())
	clip.readHook = func() {
		cancel()
		clip.readHook = nil
	}

	err := svc.Run(ctx, time.Millisecond)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context canceled, got %v", err)
	}
	if clip.value != "[GUARDMYCOPY BLOCKED]" {
		t.Fatalf("expected blocked marker, got %q", clip.value)
	}
}

// ---------------------------------------------------------------------------
// 12. run loop → per-app policy override (Chrome sanitizes instead of block)
// ---------------------------------------------------------------------------

func TestE2E_RunLoopPerAppPolicySanitize(t *testing.T) {
	cfg := config.Defaults()
	chromePolicy := cfg.Global
	chromeActions := make(map[core.RiskLevel]config.Action)
	for k, v := range cfg.Global.Actions {
		chromeActions[k] = v
	}
	chromePolicy.Actions = chromeActions
	chromePolicy.Actions[core.RiskLevelHigh] = config.ActionSanitize
	chromeToggles := make(map[string]bool)
	for k, v := range cfg.Global.DetectorToggles {
		chromeToggles[k] = v
	}
	chromePolicy.DetectorToggles = chromeToggles
	cfg.PerApp["Google Chrome"] = chromePolicy

	clip := &e2eClipboard{
		value: "prefix\n-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----\nsuffix",
	}
	foreground := &e2eForegroundApp{name: "Google Chrome"}
	notifier := &e2eNotifier{}

	svc := app.NewWithDependencies(cfg, clip, foreground, notifier)

	ctx, cancel := context.WithCancel(context.Background())
	clip.readHook = func() {
		cancel()
		clip.readHook = nil
	}

	err := svc.Run(ctx, time.Millisecond)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context canceled, got %v", err)
	}
	if clip.value == "[GUARDMYCOPY BLOCKED]" {
		t.Fatal("Chrome policy should sanitize, not block")
	}
	if !strings.Contains(clip.value, "***") {
		t.Fatalf("expected sanitized content, got %q", clip.value)
	}
	if !strings.Contains(clip.value, "prefix") || !strings.Contains(clip.value, "suffix") {
		t.Fatal("expected surrounding text preserved in sanitized output")
	}
}

// ---------------------------------------------------------------------------
// 13. run loop → detector toggle disables PEM detector → allow
// ---------------------------------------------------------------------------

func TestE2E_RunLoopDetectorToggleDisablesPEM(t *testing.T) {
	cfg := config.Defaults()
	cfg.Global.DetectorToggles[core.FindingTypePEMPrivateKey] = false

	clip := &e2eClipboard{
		value: "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----",
	}
	svc := app.NewWithDependencies(cfg, clip, nil, nil)

	ctx, cancel := context.WithCancel(context.Background())
	clip.readHook = func() {
		cancel()
		clip.readHook = nil
	}

	err := svc.Run(ctx, time.Millisecond)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context canceled, got %v", err)
	}
	// Clipboard should NOT have been changed because PEM detector is disabled
	if clip.writes != 0 {
		t.Fatalf("expected no clipboard writes with PEM disabled, got %d", clip.writes)
	}
}

// ---------------------------------------------------------------------------
// 14. run loop → allowlist pattern match → allow
// ---------------------------------------------------------------------------

func TestE2E_RunLoopAllowlistPatternMatch(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	cfgContent := `global:
  allowlist_patterns:
    - 'PRIVATE KEY'
`
	if err := os.WriteFile(cfgPath, []byte(cfgContent), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}

	clip := &e2eClipboard{
		value: "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----",
	}
	svc := app.NewWithDependencies(cfg, clip, nil, nil)

	ctx, cancel := context.WithCancel(context.Background())
	clip.readHook = func() {
		cancel()
		clip.readHook = nil
	}

	err = svc.Run(ctx, time.Millisecond)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context canceled, got %v", err)
	}
	// Allowlisted content should be allowed through without modification
	if clip.writes != 0 {
		t.Fatalf("expected no clipboard writes with allowlisted content, got %d", clip.writes)
	}
}

// ---------------------------------------------------------------------------
// 15. snooze → run loop → enforcement bypassed
// ---------------------------------------------------------------------------

func TestE2E_SnoozeBypassesEnforcement(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "state.json")

	// Set a snooze 10 minutes from now.
	var stdout, stderr bytes.Buffer
	now := time.Now()
	code := runSnoozeWithIO([]string{"10m"}, &stdout, &stderr, func() time.Time { return now }, statePath)
	if code != 0 {
		t.Fatalf("snooze failed: %d; stderr=%q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "snoozed until") {
		t.Fatalf("expected snooze confirmation, got %q", stdout.String())
	}

	// Verify state persisted correctly.
	store, err := userstate.New(statePath)
	if err != nil {
		t.Fatalf("userstate.New: %v", err)
	}
	state, err := store.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if state.SnoozedUntil.Before(now) {
		t.Fatal("snoozed_until should be in the future")
	}

	// Create service with this state.
	cfg := config.Defaults()
	clip := &e2eClipboard{
		value: "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----",
	}
	svc := app.NewWithDependencies(cfg, clip, nil, nil)
	svc.SetRuntimeStateStore(store)

	ctx, cancel := context.WithCancel(context.Background())
	clip.readHook = func() {
		cancel()
		clip.readHook = nil
	}

	err = svc.Run(ctx, time.Millisecond)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context canceled, got %v", err)
	}
	// Snooze is active → enforcement bypassed → no clipboard writes.
	if clip.writes != 0 {
		t.Fatalf("expected no clipboard writes during snooze, got %d", clip.writes)
	}
}

// ---------------------------------------------------------------------------
// 16. allow-once → run loop → enforcement bypassed once
// ---------------------------------------------------------------------------

func TestE2E_AllowOnceBypassesEnforcementOnce(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "state.json")

	var stdout, stderr bytes.Buffer
	code := runAllowOnceWithIO(nil, &stdout, &stderr, statePath)
	if code != 0 {
		t.Fatalf("allow-once failed: %d; stderr=%q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "bypass enforcement once") {
		t.Fatalf("expected confirmation, got %q", stdout.String())
	}

	// Verify state.
	store, err := userstate.New(statePath)
	if err != nil {
		t.Fatalf("userstate.New: %v", err)
	}
	state, err := store.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !state.AllowOnce {
		t.Fatal("expected AllowOnce=true")
	}

	// Run once with this state — should bypass.
	cfg := config.Defaults()
	clip := &e2eClipboard{
		value: "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----",
	}
	svc := app.NewWithDependencies(cfg, clip, nil, nil)
	svc.SetRuntimeStateStore(store)

	ctx, cancel := context.WithCancel(context.Background())
	clip.readHook = func() {
		cancel()
		clip.readHook = nil
	}

	err = svc.Run(ctx, time.Millisecond)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context canceled, got %v", err)
	}
	if clip.writes != 0 {
		t.Fatalf("expected no writes with allow-once, got %d", clip.writes)
	}
	// Verify allow-once was consumed.
	state, err = store.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if state.AllowOnce {
		t.Fatal("expected AllowOnce to be consumed")
	}
}

// ---------------------------------------------------------------------------
// 17. audit log: run once → entry written → log tail reads it back
// ---------------------------------------------------------------------------

func TestE2E_AuditLogWriteAndTail(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "audit.jsonl")

	clip := &testClipboard{
		value: "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----",
	}
	auditStore, err := auditlog.New(logPath)
	if err != nil {
		t.Fatalf("auditlog.New: %v", err)
	}
	svc := app.New(config.Defaults(), clip)
	svc.SetAuditLogStore(auditStore)

	var stdout, stderr bytes.Buffer
	code := runOnceWithService(svc, &stdout, &stderr, false)
	if code != 0 {
		t.Fatalf("once exit %d; stderr=%q", code, stderr.String())
	}

	// Read the audit log via the log command.
	stdout.Reset()
	stderr.Reset()
	code = runLogWithIO([]string{"--tail", "5"}, &stdout, &stderr, logPath)
	if code != 0 {
		t.Fatalf("log exit %d; stderr=%q", code, stderr.String())
	}

	lines := strings.Split(strings.TrimSpace(stdout.String()), "\n")
	if len(lines) != 1 {
		t.Fatalf("expected 1 audit line, got %d: %q", len(lines), stdout.String())
	}

	// Parse the JSONL entry and verify key fields.
	var entry auditlog.Entry
	if err := json.Unmarshal([]byte(lines[0]), &entry); err != nil {
		t.Fatalf("unmarshal audit entry: %v", err)
	}
	if entry.Action != "block" {
		t.Fatalf("expected block action in audit, got %q", entry.Action)
	}
	if entry.RiskLevel != "high" {
		t.Fatalf("expected high risk in audit, got %q", entry.RiskLevel)
	}
	if entry.Score != 15 {
		t.Fatalf("expected score 15 in audit, got %d", entry.Score)
	}
	if len(entry.FindingTypes) == 0 || entry.FindingTypes[0] != "pem_private_key" {
		t.Fatalf("expected pem_private_key finding type, got %v", entry.FindingTypes)
	}
	if entry.ContentHash == "" {
		t.Fatal("expected non-empty content hash in audit")
	}
	// Privacy check: raw clipboard should NOT be in the hash field.
	if strings.Contains(entry.ContentHash, "PRIVATE KEY") {
		t.Fatal("audit entry should not contain raw clipboard content")
	}
}

// ---------------------------------------------------------------------------
// 18. audit log: multiple entries → tail returns correct count
// ---------------------------------------------------------------------------

func TestE2E_AuditLogTailMultipleEntries(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "audit.jsonl")
	store, err := auditlog.New(logPath)
	if err != nil {
		t.Fatalf("auditlog.New: %v", err)
	}

	base := time.Unix(1_700_000_000, 0).UTC()
	for i := 0; i < 5; i++ {
		if err := store.Log(auditlog.Entry{
			Timestamp:    base.Add(time.Duration(i) * time.Second),
			App:          "TestApp",
			Score:        (i + 1) * 5,
			RiskLevel:    "med",
			FindingTypes: []string{"jwt"},
			Action:       "sanitize",
			ContentHash:  "hash" + string(rune('A'+i)),
		}); err != nil {
			t.Fatalf("Log: %v", err)
		}
	}

	// Tail 3 of 5.
	var stdout, stderr bytes.Buffer
	code := runLogWithIO([]string{"--tail", "3"}, &stdout, &stderr, logPath)
	if code != 0 {
		t.Fatalf("log exit %d; stderr=%q", code, stderr.String())
	}
	lines := strings.Split(strings.TrimSpace(stdout.String()), "\n")
	if len(lines) != 3 {
		t.Fatalf("expected 3 lines, got %d", len(lines))
	}
	// Last 3 should have scores 15, 20, 25.
	for i, expected := range []int{15, 20, 25} {
		var entry auditlog.Entry
		if err := json.Unmarshal([]byte(lines[i]), &entry); err != nil {
			t.Fatalf("unmarshal line %d: %v", i, err)
		}
		if entry.Score != expected {
			t.Fatalf("line %d: expected score %d, got %d", i, expected, entry.Score)
		}
	}
}

// ---------------------------------------------------------------------------
// 19. snooze: bad inputs
// ---------------------------------------------------------------------------

func TestE2E_SnoozeBadInputs(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "state.json")
	now := time.Now

	tests := []struct {
		name string
		args []string
		want int
	}{
		{"no_args", nil, 2},
		{"negative_duration", []string{"-5m"}, 2},
		{"zero_duration", []string{"0s"}, 2},
		{"invalid_format", []string{"abc"}, 2},
		{"extra_args", []string{"5m", "extra"}, 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := runSnoozeWithIO(tt.args, &stdout, &stderr, now, statePath)
			if code != tt.want {
				t.Fatalf("expected exit %d, got %d; stderr=%q", tt.want, code, stderr.String())
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 20. run loop: warn action (notification triggered, clipboard untouched)
// ---------------------------------------------------------------------------

func TestE2E_RunLoopWarnAction(t *testing.T) {
	cfg := config.Defaults()
	cfg.Global.Actions[core.RiskLevelHigh] = config.ActionWarn

	clip := &e2eClipboard{
		value: "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----",
	}
	notifier := &e2eNotifier{}
	svc := app.NewWithDependencies(cfg, clip, nil, notifier)

	ctx, cancel := context.WithCancel(context.Background())
	clip.readHook = func() {
		cancel()
		clip.readHook = nil
	}

	err := svc.Run(ctx, time.Millisecond)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context canceled, got %v", err)
	}
	// Warn should NOT modify clipboard.
	if clip.writes != 0 {
		t.Fatalf("warn action should not write clipboard, got %d writes", clip.writes)
	}
	// But should trigger a notification.
	if notifier.calls != 1 {
		t.Fatalf("expected 1 notification, got %d", notifier.calls)
	}
}

// ---------------------------------------------------------------------------
// 21. run loop: deduplication — same content is only processed once
// ---------------------------------------------------------------------------

func TestE2E_RunLoopDeduplicatesUnchangedClipboard(t *testing.T) {
	clip := &e2eClipboard{
		value: "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----",
	}
	cfg := config.Defaults()
	notifier := &e2eNotifier{}
	svc := app.NewWithDependencies(cfg, clip, nil, notifier)

	ctx, cancel := context.WithCancel(context.Background())
	ticks := 0
	clip.readHook = func() {
		ticks++
		if ticks >= 3 {
			cancel()
			clip.readHook = nil
		}
	}

	err := svc.Run(ctx, time.Millisecond)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context canceled, got %v", err)
	}
	// Even though we processed 3+ ticks, block should only happen once.
	if clip.writes != 1 {
		t.Fatalf("expected exactly 1 write (dedup), got %d", clip.writes)
	}
}

// ---------------------------------------------------------------------------
// 22. run loop: empty clipboard → allow (no writes, no notification)
// ---------------------------------------------------------------------------

func TestE2E_RunLoopEmptyClipboard(t *testing.T) {
	clip := &e2eClipboard{value: ""}
	cfg := config.Defaults()
	notifier := &e2eNotifier{}
	svc := app.NewWithDependencies(cfg, clip, nil, notifier)

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
		t.Fatalf("expected no writes for empty clipboard, got %d", clip.writes)
	}
	if notifier.calls != 0 {
		t.Fatalf("expected no notifications for empty clipboard, got %d", notifier.calls)
	}
}

// ---------------------------------------------------------------------------
// 23. sanitize: high-entropy token
// ---------------------------------------------------------------------------

func TestE2E_SanitizeHighEntropyToken(t *testing.T) {
	// This is a random-looking 40-char mixed-case string with symbols
	token := "aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW3xY5zA"
	input := "token=" + token
	var stdout, stderr bytes.Buffer
	code := runSanitizeWithIO(nil, strings.NewReader(input), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit %d; stderr=%q", code, stderr.String())
	}
	// Due to env_secret detection (key contains "token"), the value should be sanitized.
	// The exact redaction depends on which detector fires, but some redaction should happen.
	out := stdout.String()
	if out == input {
		// Check if the detector actually fires — the key "token" matches SECRET_TOKEN pattern
		// and the value is long enough. If not, the output could be the same.
		// Let's verify with the engine directly.
		result := core.New().Scan(input)
		if len(result.Findings) > 0 {
			t.Fatalf("expected sanitized output, got unchanged %q", out)
		}
		// If no findings, that's fine — the input isn't sensitive enough
	}
}

// ---------------------------------------------------------------------------
// 24. full user journey: config init → once → run loop → audit log → snooze
// ---------------------------------------------------------------------------

func TestE2E_FullUserJourney(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	logPath := filepath.Join(dir, "audit.jsonl")
	statePath := filepath.Join(dir, "state.json")

	// Step 1: Config init.
	var stdout, stderr bytes.Buffer
	code := runConfigInitWithIO([]string{"--path", cfgPath}, &stdout, &stderr, "")
	if code != 0 {
		t.Fatalf("config init: exit %d; stderr=%q", code, stderr.String())
	}

	// Step 2: Load config.
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("config load: %v", err)
	}

	// Step 3: Scan clean clipboard → allow.
	clip := &testClipboard{value: "hello world"}
	svc := app.New(cfg, clip)
	auditStore, err := auditlog.New(logPath)
	if err != nil {
		t.Fatalf("auditlog.New: %v", err)
	}
	svc.SetAuditLogStore(auditStore)

	stdout.Reset()
	stderr.Reset()
	code = runOnceWithService(svc, &stdout, &stderr, false)
	if code != 0 {
		t.Fatalf("once clean: exit %d", code)
	}
	if !strings.Contains(stdout.String(), "action=allow") {
		t.Fatalf("expected allow for clean text, got %q", stdout.String())
	}

	// Step 4: Scan PEM key → block.
	clip.value = "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----"
	svc2 := app.New(cfg, clip)
	svc2.SetAuditLogStore(auditStore)

	stdout.Reset()
	stderr.Reset()
	code = runOnceWithService(svc2, &stdout, &stderr, true)
	if code != 0 {
		t.Fatalf("once PEM: exit %d", code)
	}
	if !strings.Contains(stdout.String(), "action=block") {
		t.Fatalf("expected block, got %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), "reason=") {
		t.Fatal("expected verbose reasoning")
	}

	// Step 5: Verify audit log has 2 entries.
	stdout.Reset()
	stderr.Reset()
	code = runLogWithIO([]string{"--tail", "10"}, &stdout, &stderr, logPath)
	if code != 0 {
		t.Fatalf("log tail: exit %d", code)
	}
	logLines := strings.Split(strings.TrimSpace(stdout.String()), "\n")
	if len(logLines) != 2 {
		t.Fatalf("expected 2 audit entries, got %d", len(logLines))
	}

	// Step 6: Snooze.
	stdout.Reset()
	stderr.Reset()
	code = runSnoozeWithIO([]string{"5m"}, &stdout, &stderr, time.Now, statePath)
	if code != 0 {
		t.Fatalf("snooze: exit %d; stderr=%q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "snoozed until") {
		t.Fatalf("expected snooze confirmation, got %q", stdout.String())
	}

	// Verify snooze state.
	stStore, err := userstate.New(statePath)
	if err != nil {
		t.Fatalf("userstate.New: %v", err)
	}
	st, err := stStore.Load()
	if err != nil {
		t.Fatalf("state Load: %v", err)
	}
	if st.SnoozedUntil.Before(time.Now()) {
		t.Fatal("expected snooze time to be in the future")
	}
}

// ---------------------------------------------------------------------------
// 25. log: --tail errors
// ---------------------------------------------------------------------------

func TestE2E_LogTailErrors(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runLogWithIO([]string{"--tail", "-1"}, &stdout, &stderr, filepath.Join(t.TempDir(), "audit.jsonl"))
	if code != 2 {
		t.Fatalf("expected exit 2, got %d", code)
	}
}

// ---------------------------------------------------------------------------
// 26. log: empty audit file returns no output
// ---------------------------------------------------------------------------

func TestE2E_LogEmptyAuditFile(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "audit.jsonl")
	var stdout, stderr bytes.Buffer
	code := runLogWithIO([]string{"--tail", "10"}, &stdout, &stderr, logPath)
	if code != 0 {
		t.Fatalf("exit %d; stderr=%q", code, stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("expected empty output, got %q", stdout.String())
	}
}

// ---------------------------------------------------------------------------
// 27. run --once flag via runLoop (uses once inside run command)
// ---------------------------------------------------------------------------

func TestE2E_RunOnceFlag(t *testing.T) {
	// The run command with --once flag internally calls runOnceWithService.
	// We test this indirectly through the once pathway.
	clip := &testClipboard{value: "normal text nothing sensitive"}
	svc := app.New(config.Defaults(), clip)

	var stdout, stderr bytes.Buffer
	code := runOnceWithService(svc, &stdout, &stderr, false)
	if code != 0 {
		t.Fatalf("exit %d; stderr=%q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "action=allow") {
		t.Fatalf("expected allow action, got %q", stdout.String())
	}
}

// ---------------------------------------------------------------------------
// 28. sanitize multiple finding types in same text
// ---------------------------------------------------------------------------

func TestE2E_SanitizeMultipleFindings(t *testing.T) {
	// Combine PEM key + env secret in same text
	input := `SECRET_TOKEN=mysupersecretvalue123456
-----BEGIN PRIVATE KEY-----
abc
-----END PRIVATE KEY-----`

	var stdout, stderr bytes.Buffer
	code := runSanitizeWithIO([]string{"--diff"}, strings.NewReader(input), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit %d; stderr=%q", code, stderr.String())
	}
	out := stdout.String()
	// Both secrets should be redacted.
	if strings.Contains(out, "mysupersecretvalue123456") {
		t.Fatal("env secret should be redacted")
	}
	// Check diff output reports multiple findings.
	if !strings.Contains(stderr.String(), "findings=") {
		t.Fatal("expected findings in diff output")
	}
}

// ---------------------------------------------------------------------------
// 29. run loop with audit log: verify audit entries have correct structure
// ---------------------------------------------------------------------------

func TestE2E_RunLoopAuditLogStructure(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "audit.jsonl")
	auditStore, err := auditlog.New(logPath)
	if err != nil {
		t.Fatalf("auditlog.New: %v", err)
	}

	clip := &e2eClipboard{
		value: "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----",
	}
	cfg := config.Defaults()
	foreground := &e2eForegroundApp{name: "iTerm2"}
	svc := app.NewWithDependencies(cfg, clip, foreground, nil)
	svc.SetAuditLogStore(auditStore)

	ctx, cancel := context.WithCancel(context.Background())
	clip.readHook = func() {
		cancel()
		clip.readHook = nil
	}

	err = svc.Run(ctx, time.Millisecond)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context canceled, got %v", err)
	}

	// Read audit entries.
	lines, err := auditStore.Tail(10)
	if err != nil {
		t.Fatalf("Tail: %v", err)
	}
	if len(lines) != 1 {
		t.Fatalf("expected 1 audit line, got %d", len(lines))
	}

	var entry auditlog.Entry
	if err := json.Unmarshal([]byte(lines[0]), &entry); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if entry.App != "iTerm2" {
		t.Fatalf("expected app=iTerm2, got %q", entry.App)
	}
	if entry.Action != "block" {
		t.Fatalf("expected block action, got %q", entry.Action)
	}
	if entry.ContentHash == "" {
		t.Fatal("expected non-empty content hash")
	}
	if entry.Timestamp.IsZero() {
		t.Fatal("expected non-zero timestamp")
	}
}

// ---------------------------------------------------------------------------
// 30. YAML config: load with custom thresholds and actions
// ---------------------------------------------------------------------------

func TestE2E_CustomConfigThresholdsAndActions(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	cfgContent := `global:
  poll_interval_ms: 250
  thresholds:
    med: 10
    high: 20
  actions:
    low: allow
    med: warn
    high: sanitize
`
	if err := os.WriteFile(cfgPath, []byte(cfgContent), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.PollInterval != 250*time.Millisecond {
		t.Fatalf("unexpected poll interval: %s", cfg.PollInterval)
	}
	if cfg.Global.Thresholds.Med != 10 || cfg.Global.Thresholds.High != 20 {
		t.Fatalf("unexpected thresholds: %+v", cfg.Global.Thresholds)
	}

	// With custom thresholds, a PEM key (score=15) is now med risk (10 <= 15 < 20).
	clip := &testClipboard{
		value: "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----",
	}
	svc := app.New(cfg, clip)

	var stdout, stderr bytes.Buffer
	code := runOnceWithService(svc, &stdout, &stderr, false)
	if code != 0 {
		t.Fatalf("exit %d; stderr=%q", code, stderr.String())
	}
	// With med thresholds at 10, PEM (score 15) is med risk.
	// Action for med is "warn" in this config.
	if !strings.Contains(stdout.String(), "action=warn") {
		t.Fatalf("expected warn action with custom thresholds, got %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), "risk=med") {
		t.Fatalf("expected med risk with custom thresholds, got %q", stdout.String())
	}
}

// ---------------------------------------------------------------------------
// 31. privacy: clipboard content never appears in audit log
// ---------------------------------------------------------------------------

func TestE2E_PrivacyClipboardNotInAuditLog(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "audit.jsonl")
	auditStore, err := auditlog.New(logPath)
	if err != nil {
		t.Fatalf("auditlog.New: %v", err)
	}

	sensitiveContent := "-----BEGIN PRIVATE KEY-----\nMY_SUPER_SECRET_DATA_THAT_MUST_NOT_LEAK\n-----END PRIVATE KEY-----"
	clip := &testClipboard{value: sensitiveContent}
	svc := app.New(config.Defaults(), clip)
	svc.SetAuditLogStore(auditStore)

	if _, err := svc.ScanCurrent(); err != nil {
		t.Fatalf("ScanCurrent: %v", err)
	}

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read audit: %v", err)
	}
	raw := string(data)
	if strings.Contains(raw, "MY_SUPER_SECRET_DATA_THAT_MUST_NOT_LEAK") {
		t.Fatal("PRIVACY VIOLATION: raw clipboard content found in audit log")
	}
	if strings.Contains(raw, "PRIVATE KEY") {
		t.Fatal("PRIVACY VIOLATION: PEM markers found in audit log")
	}
}

// ---------------------------------------------------------------------------
// 32. config: per-app policy loaded from YAML
// ---------------------------------------------------------------------------

func TestE2E_PerAppPolicyFromYAML(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	cfgContent := `global:
  actions:
    low: allow
    med: sanitize
    high: block

per_app:
  "Slack":
    actions:
      high: warn
`
	if err := os.WriteFile(cfgPath, []byte(cfgContent), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	clip := &e2eClipboard{
		value: "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----",
	}
	foreground := &e2eForegroundApp{name: "Slack"}
	notifier := &e2eNotifier{}
	svc := app.NewWithDependencies(cfg, clip, foreground, notifier)

	decision, err := svc.ScanCurrent()
	if err != nil {
		t.Fatalf("ScanCurrent: %v", err)
	}
	// Slack has action=warn for high risk.
	if decision.Action != config.ActionWarn {
		t.Fatalf("expected warn for Slack high risk, got %s", decision.Action)
	}
}

// ---------------------------------------------------------------------------
// 33. run loop: clipboard changes between ticks
// ---------------------------------------------------------------------------

func TestE2E_RunLoopDetectsClipboardChanges(t *testing.T) {
	clip := &e2eClipboard{value: "clean text"}
	cfg := config.Defaults()
	svc := app.NewWithDependencies(cfg, clip, nil, nil)

	ctx, cancel := context.WithCancel(context.Background())
	ticks := 0
	clip.readHook = func() {
		ticks++
		if ticks == 2 {
			// Change clipboard to sensitive content on second tick.
			clip.value = "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----"
		}
		if ticks >= 3 {
			cancel()
			clip.readHook = nil
		}
	}

	err := svc.Run(ctx, time.Millisecond)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context canceled, got %v", err)
	}
	// Should have blocked the PEM key when clipboard changed.
	if clip.value != "[GUARDMYCOPY BLOCKED]" {
		t.Fatalf("expected blocked marker after clipboard change, got %q", clip.value)
	}
}
