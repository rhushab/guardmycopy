package app

import (
	"github.com/rhushab/guardmycopy/internal/config"
	"github.com/rhushab/guardmycopy/internal/core"
)

type PolicySource string

const (
	PolicySourceGlobal                           PolicySource = "global"
	PolicySourcePerApp                           PolicySource = "per_app"
	PolicySourcePerAppBundleID                   PolicySource = "per_app_bundle_id"
	PolicySourceGlobalFallbackAppDetectionFailed PolicySource = "global_fallback_app_detection_failed"
)

type PolicyDecision struct {
	ActiveAppName     string
	ActiveAppBundleID string
	Score             int
	RiskLevel         core.RiskLevel
	Action            config.Action
	PolicySource      PolicySource
	AppContextStatus  AppContextStatus
	AppContextError   string
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
	policy, source := r.policyForAppAndBundleID(activeAppName, activeAppBundleID)
	effectiveRisk := riskFromScore(score, policy.Thresholds, riskLevel)

	return PolicyDecision{
		ActiveAppName:     activeAppName,
		ActiveAppBundleID: activeAppBundleID,
		Score:             score,
		RiskLevel:         effectiveRisk,
		Action:            policy.ActionForRisk(effectiveRisk),
		PolicySource:      source,
	}
}

func (r *PolicyResolver) policyForAppAndBundleID(activeAppName, activeAppBundleID string) (config.Policy, PolicySource) {
	if activeAppBundleID != "" {
		if policy, ok := r.cfg.PerAppBundleID[activeAppBundleID]; ok {
			return policy, PolicySourcePerAppBundleID
		}
	}
	if activeAppName != "" {
		if policy, ok := r.cfg.PerApp[activeAppName]; ok {
			return policy, PolicySourcePerApp
		}
	}
	return r.cfg.Global, PolicySourceGlobal
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
