package app

import (
	"testing"

	"github.com/rhushabhbontapalle/guardmycopy/internal/config"
	"github.com/rhushabhbontapalle/guardmycopy/internal/core"
)

func TestPolicyResolverUsesThresholdsFromScore(t *testing.T) {
	cfg := config.Defaults()
	resolver := NewPolicyResolver(cfg)

	decision := resolver.Resolve("", "", 15, core.RiskLevelLow)
	if decision.RiskLevel != core.RiskLevelHigh {
		t.Fatalf("unexpected risk level: got %q want %q", decision.RiskLevel, core.RiskLevelHigh)
	}
	if decision.Action != config.ActionBlock {
		t.Fatalf("unexpected action: got %q want %q", decision.Action, config.ActionBlock)
	}
}

func TestPolicyResolverUsesPerAppOverrides(t *testing.T) {
	cfg := config.Defaults()
	policy := clonePolicy(cfg.Global)
	policy.Thresholds.Med = 3
	policy.Actions[core.RiskLevelMed] = config.ActionWarn
	cfg.PerApp["Google Chrome"] = policy

	resolver := NewPolicyResolver(cfg)
	decision := resolver.Resolve("Google Chrome", "", 4, core.RiskLevelLow)
	if decision.RiskLevel != core.RiskLevelMed {
		t.Fatalf("unexpected risk level: got %q want %q", decision.RiskLevel, core.RiskLevelMed)
	}
	if decision.Action != config.ActionWarn {
		t.Fatalf("unexpected action: got %q want %q", decision.Action, config.ActionWarn)
	}
}

func TestPolicyResolverPrefersBundleIDOverrideBeforeAppName(t *testing.T) {
	cfg := config.Defaults()

	appPolicy := clonePolicy(cfg.Global)
	appPolicy.Thresholds.Med = 3
	appPolicy.Actions[core.RiskLevelMed] = config.ActionWarn
	cfg.PerApp["Google Chrome"] = appPolicy

	bundlePolicy := clonePolicy(cfg.Global)
	bundlePolicy.Thresholds.Med = 3
	bundlePolicy.Actions[core.RiskLevelMed] = config.ActionBlock
	cfg.PerAppBundleID["com.google.Chrome"] = bundlePolicy

	resolver := NewPolicyResolver(cfg)
	decision := resolver.Resolve("Google Chrome", "com.google.Chrome", 4, core.RiskLevelLow)

	if decision.Action != config.ActionBlock {
		t.Fatalf("unexpected action: got %q want %q", decision.Action, config.ActionBlock)
	}
	if decision.ActiveAppBundleID != "com.google.Chrome" {
		t.Fatalf("unexpected active app bundle id: %q", decision.ActiveAppBundleID)
	}
}

func clonePolicy(policy config.Policy) config.Policy {
	cloned := policy
	cloned.DetectorToggles = make(map[string]bool, len(policy.DetectorToggles))
	for detector, enabled := range policy.DetectorToggles {
		cloned.DetectorToggles[detector] = enabled
	}

	cloned.Actions = make(map[core.RiskLevel]config.Action, len(policy.Actions))
	for level, action := range policy.Actions {
		cloned.Actions[level] = action
	}

	cloned.AllowlistPatterns = append([]string(nil), policy.AllowlistPatterns...)
	return cloned
}
