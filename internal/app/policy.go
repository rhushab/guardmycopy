package app

import (
	"github.com/rhushabhbontapalle/guardmycopy/internal/config"
	"github.com/rhushabhbontapalle/guardmycopy/internal/core"
)

type PolicyDecision struct {
	ActiveAppName     string
	ActiveAppBundleID string
	Score             int
	RiskLevel         core.RiskLevel
	Action            config.Action
}

type PolicyResolver struct {
	cfg config.Config
}

func NewPolicyResolver(cfg config.Config) *PolicyResolver {
	return &PolicyResolver{cfg: cfg}
}

func (r *PolicyResolver) Resolve(
	activeAppName string,
	activeAppBundleID string,
	score int,
	riskLevel core.RiskLevel,
) PolicyDecision {
	policy := r.cfg.PolicyForAppAndBundleID(activeAppName, activeAppBundleID)
	effectiveRisk := riskFromScore(score, policy.Thresholds, riskLevel)

	return PolicyDecision{
		ActiveAppName:     activeAppName,
		ActiveAppBundleID: activeAppBundleID,
		Score:             score,
		RiskLevel:         effectiveRisk,
		Action:            policy.ActionForRisk(effectiveRisk),
	}
}

func riskFromScore(score int, thresholds config.Thresholds, fallback core.RiskLevel) core.RiskLevel {
	if score < 0 {
		score = 0
	}

	if thresholds.High > 0 && score >= thresholds.High {
		return core.RiskLevelHigh
	}
	if thresholds.Med > 0 && score >= thresholds.Med {
		return core.RiskLevelMed
	}
	if thresholds.Med > 0 || thresholds.High > 0 {
		return core.RiskLevelLow
	}

	if fallback == "" {
		return core.RiskLevelLow
	}
	return fallback
}
