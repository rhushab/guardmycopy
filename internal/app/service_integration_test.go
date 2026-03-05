package app

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/rhushab/guardmycopy/internal/config"
	"github.com/rhushab/guardmycopy/internal/core"
)

type mockForegroundApp struct {
	name     string
	bundleID string
	err      error
}

func (m *mockForegroundApp) ActiveApp() (string, string, error) {
	if m.err != nil {
		return "", "", m.err
	}
	return m.name, m.bundleID, nil
}

func TestRunClipboardChangeScanDecisionActionFlow(t *testing.T) {
	cfg := config.Defaults()
	chromePolicy := copyPolicy(cfg.Global)
	chromePolicy.Actions[core.RiskLevelHigh] = config.ActionSanitize
	cfg.PerApp["Google Chrome"] = chromePolicy

	clip := &mockClipboard{
		value: "prefix\n-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----\nsuffix",
	}
	notifier := &mockNotifier{}
	foreground := &mockForegroundApp{name: "Google Chrome"}
	auditStore := &mockAuditLogStore{}

	svc := NewWithDependencies(cfg, clip, foreground, notifier)
	svc.SetAuditLogStore(auditStore)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	readCount := 0
	clip.readHook = func() {
		readCount++
		if readCount == 1 {
			cancel()
			clip.readHook = nil
		}
	}

	err := svc.Run(ctx, time.Millisecond)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context canceled, got %v", err)
	}
	if clip.writes != 1 {
		t.Fatalf("expected exactly one clipboard write, got %d", clip.writes)
	}
	if clip.value == blockedClipboardValue {
		t.Fatalf("expected sanitize action from per-app override, got blocked marker %q", clip.value)
	}
	if !strings.Contains(clip.value, "***") {
		t.Fatalf("expected sanitized clipboard text, got %q", clip.value)
	}
	if notifier.calls != 1 {
		t.Fatalf("expected one notification, got %d", notifier.calls)
	}
	if len(auditStore.entries) != 1 {
		t.Fatalf("expected one audit entry, got %d", len(auditStore.entries))
	}

	entry := auditStore.entries[0]
	if entry.App != "Google Chrome" {
		t.Fatalf("expected app name from foreground adapter, got %q", entry.App)
	}
	if entry.Action != string(config.ActionSanitize) {
		t.Fatalf("expected sanitized action in audit entry, got %q", entry.Action)
	}
	if entry.ContentHash == "" {
		t.Fatal("expected content hash in audit entry")
	}
	if strings.Contains(entry.ContentHash, "PRIVATE KEY") {
		t.Fatalf("audit entry should not contain raw clipboard content, got %q", entry.ContentHash)
	}
}

func TestRunUsesBundleIDOverrideBeforePerApp(t *testing.T) {
	cfg := config.Defaults()

	chromePolicy := copyPolicy(cfg.Global)
	chromePolicy.Actions[core.RiskLevelHigh] = config.ActionSanitize
	cfg.PerApp["Google Chrome"] = chromePolicy

	chromeBundlePolicy := copyPolicy(cfg.Global)
	chromeBundlePolicy.Actions[core.RiskLevelHigh] = config.ActionWarn
	cfg.PerAppBundleID["com.google.Chrome"] = chromeBundlePolicy

	clip := &mockClipboard{
		value: "prefix\n-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----\nsuffix",
	}
	notifier := &mockNotifier{}
	foreground := &mockForegroundApp{name: "Google Chrome", bundleID: "com.google.Chrome"}
	auditStore := &mockAuditLogStore{}

	svc := NewWithDependencies(cfg, clip, foreground, notifier)
	svc.SetAuditLogStore(auditStore)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	readCount := 0
	clip.readHook = func() {
		readCount++
		if readCount == 1 {
			cancel()
			clip.readHook = nil
		}
	}

	err := svc.Run(ctx, time.Millisecond)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context canceled, got %v", err)
	}
	if clip.writes != 0 {
		t.Fatalf("expected warn action from bundle-id override to avoid write, got %d writes", clip.writes)
	}
	if notifier.calls != 1 {
		t.Fatalf("expected one notification, got %d", notifier.calls)
	}
	if len(auditStore.entries) != 1 {
		t.Fatalf("expected one audit entry, got %d", len(auditStore.entries))
	}

	entry := auditStore.entries[0]
	if entry.Action != string(config.ActionWarn) {
		t.Fatalf("expected warn action in audit entry, got %q", entry.Action)
	}
	if entry.App != "Google Chrome" {
		t.Fatalf("expected app name in audit entry, got %q", entry.App)
	}
}

func copyPolicy(policy config.Policy) config.Policy {
	copied := policy
	copied.DetectorToggles = make(map[string]bool, len(policy.DetectorToggles))
	for detector, enabled := range policy.DetectorToggles {
		copied.DetectorToggles[detector] = enabled
	}

	copied.Actions = make(map[core.RiskLevel]config.Action, len(policy.Actions))
	for level, action := range policy.Actions {
		copied.Actions[level] = action
	}

	copied.AllowlistPatterns = append([]string(nil), policy.AllowlistPatterns...)
	return copied
}
