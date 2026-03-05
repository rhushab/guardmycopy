package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/rhushabhbontapalle/guardmycopy/internal/auditlog"
	"github.com/rhushabhbontapalle/guardmycopy/internal/config"
	"github.com/rhushabhbontapalle/guardmycopy/internal/core"
	"github.com/rhushabhbontapalle/guardmycopy/internal/platform"
	"github.com/rhushabhbontapalle/guardmycopy/internal/userstate"
)

const (
	blockedClipboardValue = "[GUARDMYCOPY BLOCKED]"
	alertDebounceWindow   = time.Second
)

type ScanDecision struct {
	ActiveAppName     string
	ActiveAppBundleID string
	Score             int
	RiskLevel         core.RiskLevel
	Action            config.Action
	Findings          int
	FindingTypes      []string
	ContentHash       string
	Allowlisted       bool
}

type RuntimeStateStore interface {
	Load() (userstate.State, error)
	Save(userstate.State) error
}

type AuditLogStore interface {
	Log(auditlog.Entry) error
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
	stateStore      RuntimeStateStore
	auditLogStore   AuditLogStore
	verboseOutput   io.Writer
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
	cfg.PollInterval = config.NormalizePollInterval(cfg.PollInterval)
	if cfg.PerApp == nil {
		cfg.PerApp = map[string]config.Policy{}
	}
	if cfg.PerAppBundleID == nil {
		cfg.PerAppBundleID = map[string]config.Policy{}
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
	decision, _, err := s.ScanCurrentDetailed()
	return decision, err
}

func (s *Service) ScanCurrentDetailed() (ScanDecision, []string, error) {
	current, err := s.clipboard.ReadText()
	if err != nil {
		return ScanDecision{}, nil, fmt.Errorf("read clipboard: %w", err)
	}
	currentHash := hashText(current)

	decision, result := s.decide(current)
	scanDecision := ScanDecision{
		ActiveAppName:     decision.ActiveAppName,
		ActiveAppBundleID: decision.ActiveAppBundleID,
		Score:             decision.Score,
		RiskLevel:         decision.RiskLevel,
		Action:            decision.Action,
		Findings:          len(result.Findings),
		FindingTypes:      findingTypes(result.Findings),
		ContentHash:       hashToHex(currentHash),
		Allowlisted:       result.Allowlisted,
	}
	s.writeAuditLog(scanDecision)
	return scanDecision, s.decisionReasoning(decision, result), nil
}

func (s *Service) SetRuntimeStateStore(store RuntimeStateStore) {
	s.stateStore = store
}

func (s *Service) SetAuditLogStore(store AuditLogStore) {
	s.auditLogStore = store
}

func (s *Service) SetVerboseOutput(output io.Writer) {
	s.verboseOutput = output
}

func (s *Service) Sanitize(showDiff bool) (bool, error) {
	current, err := s.clipboard.ReadText()
	if err != nil {
		return false, fmt.Errorf("read clipboard: %w", err)
	}

	decision, result := s.decide(current)

	if showDiff {
		safeBefore := s.redactForDisplay(current, result.Findings)
		safeAfter := s.redactForDisplay(
			s.resultingClipboard(decision.Action, current, result.SanitizedText),
			result.Findings,
		)
		fmt.Printf(
			"app=%q bundle_id=%q action=%s risk=%s score=%d findings=%d\n",
			decision.ActiveAppName,
			decision.ActiveAppBundleID,
			decision.Action,
			decision.RiskLevel,
			result.Score,
			len(result.Findings),
		)
		fmt.Printf("detectors: %s\n", strings.Join(detectorsTriggered(result.Findings), ", "))
		fmt.Printf("before(redacted): %q\n", safeBefore)
		fmt.Printf("after(redacted):  %q\n", safeAfter)
	}

	changed, _, err := s.applyAction(decision, current, result.SanitizedText, hashText(current))
	if err != nil {
		return false, err
	}

	return changed, nil
}

func detectorsTriggered(findings []core.Finding) []string {
	out := findingTypes(findings)
	if len(out) == 0 {
		return []string{"none"}
	}
	return out
}

func findingTypes(findings []core.Finding) []string {
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
	polling := newAdaptivePollBackoff(interval)
	timer := time.NewTimer(polling.Current())
	defer timer.Stop()

	var lastSeenHash [32]byte
	seen := false
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			current, err := s.clipboard.ReadText()
			if err != nil {
				return fmt.Errorf("read clipboard: %w", err)
			}
			currentHash := hashText(current)
			if seen && currentHash == lastSeenHash {
				timer.Reset(polling.OnClipboardUnchanged())
				continue
			}
			seen = true
			lastSeenHash = currentHash
			nextInterval := polling.OnClipboardChanged()

			bypass, bypassReason, err := s.shouldBypassEnforcement()
			if err != nil {
				return err
			}
			if bypass {
				s.logVerbose("action=allow reason=%s", bypassReason)
				timer.Reset(nextInterval)
				continue
			}

			decision, result := s.decide(current)
			s.logVerbose(
				"app=%q bundle_id=%q action=%s risk=%s score=%d findings=%d",
				decision.ActiveAppName,
				decision.ActiveAppBundleID,
				decision.Action,
				decision.RiskLevel,
				decision.Score,
				len(result.Findings),
			)
			for _, reason := range s.decisionReasoning(decision, result) {
				s.logVerbose("reason=%s", reason)
			}

			changed, nextValue, err := s.applyAction(decision, current, result.SanitizedText, currentHash)
			if err != nil {
				return err
			}
			s.writeAuditLog(ScanDecision{
				ActiveAppName:     decision.ActiveAppName,
				ActiveAppBundleID: decision.ActiveAppBundleID,
				Score:             decision.Score,
				RiskLevel:         decision.RiskLevel,
				Action:            decision.Action,
				Findings:          len(result.Findings),
				FindingTypes:      findingTypes(result.Findings),
				ContentHash:       hashToHex(currentHash),
				Allowlisted:       result.Allowlisted,
			})
			if changed {
				lastSeenHash = hashText(nextValue)
			}
			timer.Reset(nextInterval)
		}
	}
}

func (s *Service) decide(text string) (PolicyDecision, policyResult) {
	activeAppName, activeAppBundleID := s.resolveActiveApp()
	result := s.analyze(text, activeAppName, activeAppBundleID)
	if result.Allowlisted {
		return PolicyDecision{
			ActiveAppName:     activeAppName,
			ActiveAppBundleID: activeAppBundleID,
			Score:             0,
			RiskLevel:         core.RiskLevelLow,
			Action:            config.ActionAllow,
		}, result
	}
	decision := s.policyResolver.Resolve(activeAppName, activeAppBundleID, result.Score, result.RiskLevel)
	return decision, result
}

type policyResult struct {
	Findings      []core.Finding
	Score         int
	RiskLevel     core.RiskLevel
	SanitizedText string
	Allowlisted   bool
}

func (s *Service) analyze(text string, activeAppName string, activeAppBundleID string) policyResult {
	policy := s.cfg.PolicyForAppAndBundleID(activeAppName, activeAppBundleID)
	if policy.IsAllowlisted(text) {
		return policyResult{
			Findings:      nil,
			Score:         0,
			RiskLevel:     core.RiskLevelLow,
			SanitizedText: text,
			Allowlisted:   true,
		}
	}

	scan := s.engine.Scan(text)
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
		Allowlisted:   false,
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

func (s *Service) resolveActiveApp() (appName string, bundleID string) {
	if s.foregroundApp == nil {
		return "", ""
	}
	activeAppName, activeAppBundleID, err := s.foregroundApp.ActiveApp()
	if err != nil {
		return "", ""
	}
	return activeAppName, activeAppBundleID
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

	appLabel := formatAppLabel(decision.ActiveAppName, decision.ActiveAppBundleID)
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
		return "guardmycopy warning", fmt.Sprintf(
			"Sensitive clipboard content detected in %s (risk=%s score=%d)",
			appLabel,
			decision.RiskLevel,
			decision.Score,
		)
	case config.ActionBlock:
		return "guardmycopy blocked", fmt.Sprintf(
			"Clipboard content blocked in %s (risk=%s score=%d)",
			appLabel,
			decision.RiskLevel,
			decision.Score,
		)
	default:
		return "guardmycopy sanitized", fmt.Sprintf(
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

func hashToHex(value [32]byte) string {
	return hex.EncodeToString(value[:])
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

func (s *Service) shouldBypassEnforcement() (bool, string, error) {
	if s.stateStore == nil {
		return false, "", nil
	}

	state, err := s.stateStore.Load()
	if err != nil {
		return false, "", fmt.Errorf("load runtime state: %w", err)
	}

	now := s.timeNow()
	if !state.SnoozedUntil.IsZero() && state.SnoozedUntil.After(now) {
		return true, fmt.Sprintf("snoozed until %s", state.SnoozedUntil.Local().Format(time.RFC3339)), nil
	}

	dirty := false
	if !state.SnoozedUntil.IsZero() && !state.SnoozedUntil.After(now) {
		state.SnoozedUntil = time.Time{}
		dirty = true
	}

	if state.AllowOnce {
		state.AllowOnce = false
		dirty = true
		if err := s.stateStore.Save(state); err != nil {
			return false, "", fmt.Errorf("save runtime state: %w", err)
		}
		return true, "allow-once consumed", nil
	}

	if dirty {
		if err := s.stateStore.Save(state); err != nil {
			return false, "", fmt.Errorf("save runtime state: %w", err)
		}
	}

	return false, "", nil
}

func (s *Service) logVerbose(format string, args ...any) {
	if s.verboseOutput == nil {
		return
	}
	_, _ = fmt.Fprintf(s.verboseOutput, format+"\n", args...)
}

func (s *Service) writeAuditLog(decision ScanDecision) {
	if s.auditLogStore == nil {
		return
	}

	appName := decision.ActiveAppName
	if appName == "" {
		appName = decision.ActiveAppBundleID
	}

	entry := auditlog.Entry{
		Timestamp:    s.timeNow().UTC(),
		App:          appName,
		Score:        decision.Score,
		RiskLevel:    string(decision.RiskLevel),
		FindingTypes: append([]string(nil), decision.FindingTypes...),
		Action:       string(decision.Action),
		ContentHash:  decision.ContentHash,
	}
	if err := s.auditLogStore.Log(entry); err != nil {
		s.logVerbose("audit log write failed: %v", err)
	}
}

func (s *Service) decisionReasoning(decision PolicyDecision, result policyResult) []string {
	reasons := make([]string, 0, 3)
	if appContext := formatAppContext(decision.ActiveAppName, decision.ActiveAppBundleID); appContext != "" {
		reasons = append(reasons, appContext)
	}

	if result.Allowlisted {
		reasons = append(reasons, "clipboard matched allowlist regex; treated as allow")
		return reasons
	}
	if len(result.Findings) == 0 {
		reasons = append(
			reasons,
			"no active findings after detector toggles and allowlist filtering",
			fmt.Sprintf("policy resolved action=%s for risk=%s", decision.Action, decision.RiskLevel),
		)
		return reasons
	}

	reasons = append(
		reasons,
		fmt.Sprintf("detectors=%s", strings.Join(detectorsTriggered(result.Findings), ",")),
		fmt.Sprintf("policy resolved action=%s for risk=%s", decision.Action, decision.RiskLevel),
	)
	return reasons
}

func (s *Service) redactForDisplay(value string, findings []core.Finding) string {
	if len(findings) == 0 {
		return value
	}
	return s.redactor.Redact(value, findings)
}

func formatAppContext(appName, bundleID string) string {
	switch {
	case appName != "" && bundleID != "":
		return fmt.Sprintf("app=%q bundle_id=%q", appName, bundleID)
	case appName != "":
		return fmt.Sprintf("app=%q", appName)
	case bundleID != "":
		return fmt.Sprintf("bundle_id=%q", bundleID)
	default:
		return ""
	}
}

func formatAppLabel(appName, bundleID string) string {
	switch {
	case appName != "" && bundleID != "":
		return fmt.Sprintf("%s (%s)", appName, bundleID)
	case appName != "":
		return appName
	case bundleID != "":
		return bundleID
	default:
		return ""
	}
}
