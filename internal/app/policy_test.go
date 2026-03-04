package app

import (
	"testing"

	"github.com/rhushabhbontapalle/clipguard/internal/config"
	"github.com/rhushabhbontapalle/clipguard/internal/core"
)

func TestPolicyResolverUsesThresholdsFromScore(t *testing.T) {
	cfg := config.Defaults()
	resolver := NewPolicyResolver(cfg)

	decision := resolver.Resolve("", 15, core.RiskLevelLow)
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
	decision := resolver.Resolve("Google Chrome", 4, core.RiskLevelLow)
	if decision.RiskLevel != core.RiskLevelMed {
		t.Fatalf("unexpected risk level: got %q want %q", decision.RiskLevel, core.RiskLevelMed)
	}
	if decision.Action != config.ActionWarn {
		t.Fatalf("unexpected action: got %q want %q", decision.Action, config.ActionWarn)
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
