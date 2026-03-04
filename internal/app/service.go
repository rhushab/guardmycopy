package app

import (
	"context"
	"crypto/sha256"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/rhushabhbontapalle/clipguard/internal/config"
	"github.com/rhushabhbontapalle/clipguard/internal/core"
	"github.com/rhushabhbontapalle/clipguard/internal/platform"
)

const (
	blockedClipboardValue = "[CLIPGUARD BLOCKED]"
	alertDebounceWindow   = time.Second
)

type ScanDecision struct {
	ActiveAppName string
	Score         int
	RiskLevel     core.RiskLevel
	Action        config.Action
	Findings      int
}

type Service struct {
	cfg             config.Config
	clipboard       platform.Clipboard
	engine          *core.Engine
	redactor        core.Redactor
	policyResolver  *PolicyResolver
	foregroundApp   platform.ForegroundApp
	notifier        platform.Notifier
	alertDebounce   time.Duration
	lastAlertByHash map[[32]byte]time.Time
	timeNow         func() time.Time
}

func New(cfg config.Config, clipboard platform.Clipboard) *Service {
	return NewWithDependencies(cfg, clipboard, nil, nil)
}

func NewWithDependencies(
	cfg config.Config,
	clipboard platform.Clipboard,
	foregroundApp platform.ForegroundApp,
	notifier platform.Notifier,
) *Service {
	defaults := config.Defaults()
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = defaults.PollInterval
	}
	if cfg.PerApp == nil {
		cfg.PerApp = map[string]config.Policy{}
	}
	if cfg.Global.Thresholds.Med <= 0 {
		cfg.Global.Thresholds.Med = defaults.Global.Thresholds.Med
	}
	if cfg.Global.Thresholds.High < cfg.Global.Thresholds.Med {
		cfg.Global.Thresholds.High = defaults.Global.Thresholds.High
	}
	if cfg.Global.DetectorToggles == nil {
		cfg.Global.DetectorToggles = cloneDetectorToggles(defaults.Global.DetectorToggles)
	}
	if cfg.Global.Actions == nil {
		cfg.Global.Actions = cloneActions(defaults.Global.Actions)
	}

	return &Service{
		cfg:             cfg,
		clipboard:       clipboard,
		engine:          core.New(),
		redactor:        core.NewFormatPreservingRedactor(),
		policyResolver:  NewPolicyResolver(cfg),
		foregroundApp:   foregroundApp,
		notifier:        notifier,
		alertDebounce:   alertDebounceWindow,
		lastAlertByHash: make(map[[32]byte]time.Time),
		timeNow:         time.Now,
	}
}

func (s *Service) ScanCurrent() (ScanDecision, error) {
	current, err := s.clipboard.ReadText()
	if err != nil {
		return ScanDecision{}, fmt.Errorf("read clipboard: %w", err)
	}

	decision, result := s.decide(current)
	return ScanDecision{
		ActiveAppName: decision.ActiveAppName,
		Score:         decision.Score,
		RiskLevel:     decision.RiskLevel,
		Action:        decision.Action,
		Findings:      len(result.Findings),
	}, nil
}

func (s *Service) Sanitize(showDiff bool) (bool, error) {
	current, err := s.clipboard.ReadText()
	if err != nil {
		return false, fmt.Errorf("read clipboard: %w", err)
	}

	decision, result := s.decide(current)

	if showDiff {
		fmt.Printf(
			"app=%q action=%s risk=%s score=%d findings=%d\n",
			decision.ActiveAppName,
			decision.Action,
			decision.RiskLevel,
			result.Score,
			len(result.Findings),
		)
		fmt.Printf("detectors: %s\n", strings.Join(detectorsTriggered(result.Findings), ", "))
		fmt.Printf("before: %q\n", current)
		fmt.Printf("after:  %q\n", s.resultingClipboard(decision.Action, current, result.SanitizedText))
	}

	changed, _, err := s.applyAction(decision, current, result.SanitizedText, hashText(current))
	if err != nil {
		return false, err
	}

	return changed, nil
}

func detectorsTriggered(findings []core.Finding) []string {
	if len(findings) == 0 {
		return []string{"none"}
	}

	unique := make(map[string]struct{}, len(findings))
	for _, finding := range findings {
		unique[finding.Type] = struct{}{}
	}

	out := make([]string, 0, len(unique))
	for findingType := range unique {
		out = append(out, findingType)
	}
	sort.Strings(out)
	return out
}

func (s *Service) Run(ctx context.Context, interval time.Duration) error {
	if interval <= 0 {
		interval = s.cfg.PollInterval
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	var lastSeenHash [32]byte
	seen := false
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			current, err := s.clipboard.ReadText()
			if err != nil {
				return fmt.Errorf("read clipboard: %w", err)
			}
			currentHash := hashText(current)
			if seen && currentHash == lastSeenHash {
				continue
			}
			seen = true
			lastSeenHash = currentHash

			decision, result := s.decide(current)

			changed, nextValue, err := s.applyAction(decision, current, result.SanitizedText, currentHash)
			if err != nil {
				return err
			}
			if changed {
				lastSeenHash = hashText(nextValue)
			}
		}
	}
}

func (s *Service) decide(text string) (PolicyDecision, policyResult) {
	activeAppName := s.resolveActiveAppName()
	result := s.analyze(text, activeAppName)
	decision := s.policyResolver.Resolve(activeAppName, result.Score, result.RiskLevel)
	return decision, result
}

type policyResult struct {
	Findings      []core.Finding
	Score         int
	RiskLevel     core.RiskLevel
	SanitizedText string
}

func (s *Service) analyze(text string, activeAppName string) policyResult {
	scan := s.engine.Scan(text)
	policy := s.cfg.PolicyForApp(activeAppName)
	findings := filterFindings(text, scan.Findings, policy)
	score := scoreFindings(findings)
	riskLevel := riskFromScore(score, policy.Thresholds, scan.RiskLevel)

	sanitized := text
	if len(findings) > 0 {
		sanitized = s.redactor.Redact(text, findings)
	}

	return policyResult{
		Findings:      findings,
		Score:         score,
		RiskLevel:     riskLevel,
		SanitizedText: sanitized,
	}
}

func filterFindings(text string, findings []core.Finding, policy config.Policy) []core.Finding {
	filtered := make([]core.Finding, 0, len(findings))
	for _, finding := range findings {
		if !policy.DetectorEnabled(finding.Type) {
			continue
		}
		if finding.Start < 0 || finding.End > len(text) || finding.End <= finding.Start {
			continue
		}
		if policy.IsAllowlisted(text[finding.Start:finding.End]) {
			continue
		}
		filtered = append(filtered, finding)
	}
	return filtered
}

func scoreFindings(findings []core.Finding) int {
	weights := core.DefaultScoreWeights()

	score := 0
	for _, finding := range findings {
		switch finding.Severity {
		case core.SeverityHigh:
			score += weights.High
		case core.SeverityMedium:
			score += weights.Medium
		default:
			score += weights.Low
		}
	}
	return score
}

func (s *Service) resolveActiveAppName() string {
	if s.foregroundApp == nil {
		return ""
	}
	activeAppName, err := s.foregroundApp.ActiveAppName()
	if err != nil {
		return ""
	}
	return activeAppName
}

func (s *Service) applyAction(
	decision PolicyDecision,
	current string,
	sanitized string,
	clipboardHash [32]byte,
) (changed bool, nextValue string, err error) {
	switch decision.Action {
	case config.ActionAllow:
		return false, current, nil
	case config.ActionWarn:
		s.notifyAction(decision, clipboardHash)
		return false, current, nil
	case config.ActionBlock:
		if err := s.clipboard.WriteText(blockedClipboardValue); err != nil {
			return false, current, fmt.Errorf("write clipboard: %w", err)
		}
		s.notifyAction(decision, clipboardHash)
		return blockedClipboardValue != current, blockedClipboardValue, nil
	case config.ActionSanitize:
		fallthrough
	default:
		if err := s.clipboard.WriteText(sanitized); err != nil {
			return false, current, fmt.Errorf("write clipboard: %w", err)
		}
		s.notifyAction(decision, clipboardHash)
		return sanitized != current, sanitized, nil
	}
}

func (s *Service) resultingClipboard(action config.Action, current, sanitized string) string {
	switch action {
	case config.ActionBlock:
		return blockedClipboardValue
	case config.ActionSanitize:
		return sanitized
	default:
		return current
	}
}

func (s *Service) notifyAction(decision PolicyDecision, clipboardHash [32]byte) {
	if s.notifier == nil {
		return
	}
	if !s.shouldNotify(clipboardHash) {
		return
	}

	appLabel := decision.ActiveAppName
	if appLabel == "" {
		appLabel = "Unknown App"
	}

	title, message := notificationForAction(decision, appLabel)
	_ = s.notifier.Notify(title, message)
}

func (s *Service) shouldNotify(clipboardHash [32]byte) bool {
	if s.alertDebounce <= 0 {
		return true
	}

	now := s.timeNow()
	last, ok := s.lastAlertByHash[clipboardHash]
	if ok && now.Sub(last) < s.alertDebounce {
		return false
	}
	s.lastAlertByHash[clipboardHash] = now
	return true
}

func notificationForAction(decision PolicyDecision, appLabel string) (title, message string) {
	switch decision.Action {
	case config.ActionWarn:
		return "Clipguard warning", fmt.Sprintf(
			"Sensitive clipboard content detected in %s (risk=%s score=%d)",
			appLabel,
			decision.RiskLevel,
			decision.Score,
		)
	case config.ActionBlock:
		return "Clipguard blocked", fmt.Sprintf(
			"Clipboard content blocked in %s (risk=%s score=%d)",
			appLabel,
			decision.RiskLevel,
			decision.Score,
		)
	default:
		return "Clipguard sanitized", fmt.Sprintf(
			"Clipboard content sanitized in %s (risk=%s score=%d)",
			appLabel,
			decision.RiskLevel,
			decision.Score,
		)
	}
}

func hashText(value string) [32]byte {
	return sha256.Sum256([]byte(value))
}

func cloneDetectorToggles(input map[string]bool) map[string]bool {
	out := make(map[string]bool, len(input))
	for detectorType, enabled := range input {
		out[detectorType] = enabled
	}
	return out
}

func cloneActions(input map[core.RiskLevel]config.Action) map[core.RiskLevel]config.Action {
	out := make(map[core.RiskLevel]config.Action, len(input))
	for riskLevel, action := range input {
		out[riskLevel] = action
	}
	return out
}
