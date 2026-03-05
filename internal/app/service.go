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

	"github.com/rhushab/guardmycopy/internal/auditlog"
	"github.com/rhushab/guardmycopy/internal/config"
	"github.com/rhushab/guardmycopy/internal/core"
	"github.com/rhushab/guardmycopy/internal/platform"
	"github.com/rhushab/guardmycopy/internal/userstate"
)

const (
	blockedClipboardValue        = "[GUARDMYCOPY BLOCKED]"
	alertDebounceWindow          = time.Second
	runtimeWarningDebounceWindow = 30 * time.Second
)

type AppContextStatus string

const (
	AppContextStatusResolved         AppContextStatus = "resolved"
	AppContextStatusUnavailable      AppContextStatus = "unavailable"
	AppContextStatusResolutionFailed AppContextStatus = "resolution_failed"
)

type ScanDecision struct {
	ActiveAppName     string
	ActiveAppBundleID string
	Score             int
	RiskLevel         core.RiskLevel
	Action            config.Action
	PolicySource      PolicySource
	Findings          int
	FindingTypes      []string
	ContentHash       string
	Allowlisted       bool
	AppContextStatus  AppContextStatus
	AppContextError   string
}

type activeAppContext struct {
	name     string
	bundleID string
}

type activeAppResolution struct {
	context activeAppContext
	status  AppContextStatus
	err     error
}

type RuntimeStateStore interface {
	Load() (userstate.State, error)
	Save(userstate.State) error
}

type AuditLogStore interface {
	Log(auditlog.Entry) error
}

type Service struct {
	cfg                      config.Config
	clipboard                platform.Clipboard
	clipboardChange          platform.ClipboardChangeDetector
	engine                   *core.Engine
	redactor                 core.Redactor
	policyResolver           *PolicyResolver
	foregroundApp            platform.ForegroundApp
	notifier                 platform.Notifier
	alertDebounce            time.Duration
	lastAlertByHash          map[[32]byte]time.Time
	timeNow                  func() time.Time
	stateStore               RuntimeStateStore
	auditLogStore            AuditLogStore
	verboseOutput            io.Writer
	warningOutput            io.Writer
	warningDebounce          time.Duration
	lastWarningByKey         map[string]time.Time
	pendingAllowOnceConsumed bool
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

	service := &Service{
		cfg:              cfg,
		clipboard:        clipboard,
		engine:           core.New(),
		redactor:         core.NewFormatPreservingRedactor(),
		policyResolver:   NewPolicyResolver(cfg),
		foregroundApp:    foregroundApp,
		notifier:         notifier,
		alertDebounce:    alertDebounceWindow,
		lastAlertByHash:  make(map[[32]byte]time.Time),
		warningDebounce:  runtimeWarningDebounceWindow,
		lastWarningByKey: make(map[string]time.Time),
		timeNow:          time.Now,
	}
	if detector, ok := clipboard.(platform.ClipboardChangeDetector); ok {
		service.clipboardChange = detector
	}
	return service
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
	appResolution := s.resolveActiveApp()

	decision, result := s.decideWithActiveAppResolution(current, appResolution)
	scanDecision := s.newScanDecision(decision, result, currentHash)
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

func (s *Service) SetWarningOutput(output io.Writer) {
	s.warningOutput = output
}

func (s *Service) Sanitize(showDiff bool) (bool, error) {
	current, err := s.clipboard.ReadText()
	if err != nil {
		return false, fmt.Errorf("read clipboard: %w", err)
	}
	appResolution := s.resolveActiveApp()

	decision, result := s.decideWithActiveAppResolution(current, appResolution)

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
	var lastSeenAppContext activeAppContext
	var lastSeenChangeCount int64
	var lastSeenSnoozeActive bool
	seen := false
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			currentChangeCount, hasChangeCount, err := s.currentClipboardChangeCount()
			if err != nil {
				s.warnRuntime("clipboard-change-count", "clipboard change count unavailable; falling back to full clipboard reads: %v", err)
				currentChangeCount = 0
				hasChangeCount = false
			}
			state := s.loadRuntimeStateForRun()
			snoozeActive := state.SnoozeActive(s.timeNow())

			appResolution := activeAppResolution{
				status: AppContextStatusUnavailable,
			}
			appResolutionLoaded := false
			if seen && hasChangeCount && currentChangeCount == lastSeenChangeCount {
				appResolution = s.resolveActiveApp()
				appResolutionLoaded = true
				if appResolution.context == lastSeenAppContext && snoozeActive == lastSeenSnoozeActive {
					timer.Reset(polling.OnClipboardUnchanged())
					continue
				}
			}

			current, err := s.clipboard.ReadText()
			if err != nil {
				s.warnRuntime("clipboard-read", "clipboard read failed; retrying: %v", err)
				timer.Reset(polling.OnClipboardChanged())
				continue
			}
			currentHash := hashText(current)
			if !appResolutionLoaded {
				appResolution = s.resolveActiveApp()
			}
			clipboardOrAppChanged := !seen ||
				currentHash != lastSeenHash ||
				appResolution.context != lastSeenAppContext
			if !clipboardOrAppChanged && snoozeActive == lastSeenSnoozeActive {
				if hasChangeCount {
					lastSeenChangeCount = currentChangeCount
				}
				timer.Reset(polling.OnClipboardUnchanged())
				continue
			}
			previousSeen := seen
			previousLastSeenHash := lastSeenHash
			previousLastSeenAppContext := lastSeenAppContext
			previousLastSeenChangeCount := lastSeenChangeCount
			previousLastSeenSnoozeActive := lastSeenSnoozeActive
			seen = true
			lastSeenHash = currentHash
			lastSeenAppContext = appResolution.context
			lastSeenSnoozeActive = snoozeActive
			if hasChangeCount {
				lastSeenChangeCount = currentChangeCount
			}
			nextInterval := polling.OnClipboardChanged()

			bypass, bypassReason := s.shouldBypassEnforcementForRun(state, clipboardOrAppChanged)
			if bypass {
				s.logVerbose("action=allow reason=%s", bypassReason)
				timer.Reset(nextInterval)
				continue
			}

			decision, result := s.decideWithActiveAppResolution(current, appResolution)
			s.logVerbose(
				"app=%q bundle_id=%q action=%s risk=%s score=%d findings=%d policy_source=%s app_context_status=%s",
				decision.ActiveAppName,
				decision.ActiveAppBundleID,
				decision.Action,
				decision.RiskLevel,
				decision.Score,
				len(result.Findings),
				decision.PolicySource,
				decision.AppContextStatus,
			)
			for _, reason := range s.decisionReasoning(decision, result) {
				s.logVerbose("reason=%s", reason)
			}

			changed, nextValue, err := s.applyAction(decision, current, result.SanitizedText, currentHash)
			if err != nil {
				seen = previousSeen
				lastSeenHash = previousLastSeenHash
				lastSeenAppContext = previousLastSeenAppContext
				lastSeenChangeCount = previousLastSeenChangeCount
				lastSeenSnoozeActive = previousLastSeenSnoozeActive
				s.warnRuntime("clipboard-write", "clipboard write failed; keeping enforcement active and retrying: %v", err)
				timer.Reset(polling.OnClipboardChanged())
				continue
			}
			s.writeAuditLog(s.newScanDecision(decision, result, currentHash))
			if changed {
				lastSeenHash = hashText(nextValue)
				currentChangeCount, hasChangeCount, err = s.currentClipboardChangeCount()
				if err != nil {
					s.warnRuntime("clipboard-change-count", "clipboard change count unavailable after clipboard update; continuing without fast-path optimization: %v", err)
					hasChangeCount = false
				}
				if hasChangeCount {
					lastSeenChangeCount = currentChangeCount
				}
			}
			timer.Reset(nextInterval)
		}
	}
}

func (s *Service) decideWithActiveAppResolution(
	text string,
	appResolution activeAppResolution,
) (PolicyDecision, policyResult) {
	policy, policySource := s.policyResolver.policyForAppAndBundleID(
		appResolution.context.name,
		appResolution.context.bundleID,
	)
	if appResolution.status == AppContextStatusResolutionFailed && policySource == PolicySourceGlobal {
		policySource = PolicySourceGlobalFallbackAppDetectionFailed
	}

	result := s.analyze(text, policy)
	decision := PolicyDecision{
		ActiveAppName:     appResolution.context.name,
		ActiveAppBundleID: appResolution.context.bundleID,
		PolicySource:      policySource,
		AppContextStatus:  appResolution.status,
	}
	if appResolution.err != nil {
		decision.AppContextError = appResolution.err.Error()
	}
	if result.Allowlisted {
		decision.Score = 0
		decision.RiskLevel = core.RiskLevelLow
		decision.Action = config.ActionAllow
		return decision, result
	}
	decision.Score = result.Score
	decision.RiskLevel = riskFromScore(result.Score, policy.Thresholds, result.RiskLevel)
	decision.Action = policy.ActionForRisk(decision.RiskLevel)
	return decision, result
}

type policyResult struct {
	Findings      []core.Finding
	Score         int
	RiskLevel     core.RiskLevel
	SanitizedText string
	Allowlisted   bool
}

func (s *Service) analyze(text string, policy config.Policy) policyResult {
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

func (s *Service) resolveActiveApp() activeAppResolution {
	if s.foregroundApp == nil {
		return activeAppResolution{status: AppContextStatusUnavailable}
	}
	activeAppName, activeAppBundleID, err := s.foregroundApp.ActiveApp()
	if err != nil {
		s.warnRuntime(
			"foreground-app:"+err.Error(),
			"foreground app detection failed; using global policy until app context is available: %v",
			err,
		)
		return activeAppResolution{
			status: AppContextStatusResolutionFailed,
			err:    err,
		}
	}
	activeAppName = strings.TrimSpace(activeAppName)
	activeAppBundleID = strings.TrimSpace(activeAppBundleID)
	if activeAppName == "" && activeAppBundleID == "" {
		return activeAppResolution{status: AppContextStatusUnavailable}
	}
	return activeAppResolution{
		context: activeAppContext{name: activeAppName, bundleID: activeAppBundleID},
		status:  AppContextStatusResolved,
	}
}

func (s *Service) currentClipboardChangeCount() (count int64, ok bool, err error) {
	if s.clipboardChange == nil {
		return 0, false, nil
	}

	count, err = s.clipboardChange.ChangeCount()
	if err != nil {
		return 0, true, fmt.Errorf("read clipboard change count: %w", err)
	}
	return count, true, nil
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
		if current == blockedClipboardValue {
			return false, current, nil
		}
		if err := s.clipboard.WriteText(blockedClipboardValue); err != nil {
			return false, current, fmt.Errorf("write clipboard: %w", err)
		}
		s.notifyAction(decision, clipboardHash)
		return true, blockedClipboardValue, nil
	case config.ActionSanitize:
		fallthrough
	default:
		if current == sanitized {
			return false, current, nil
		}
		if err := s.clipboard.WriteText(sanitized); err != nil {
			return false, current, fmt.Errorf("write clipboard: %w", err)
		}
		s.notifyAction(decision, clipboardHash)
		return true, sanitized, nil
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
	s.evictExpiredAlerts(now)
	last, ok := s.lastAlertByHash[clipboardHash]
	if ok && now.Sub(last) < s.alertDebounce {
		return false
	}
	s.lastAlertByHash[clipboardHash] = now
	return true
}

func (s *Service) evictExpiredAlerts(now time.Time) {
	for hash, last := range s.lastAlertByHash {
		if now.Sub(last) >= s.alertDebounce {
			delete(s.lastAlertByHash, hash)
		}
	}
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

func (s *Service) loadRuntimeState() (userstate.State, error) {
	if s.stateStore == nil {
		return userstate.State{}, nil
	}

	state, err := s.stateStore.Load()
	if err != nil {
		return userstate.State{}, fmt.Errorf("load runtime state: %w", err)
	}
	return state, nil
}

func (s *Service) loadRuntimeStateForRun() userstate.State {
	state, err := s.loadRuntimeState()
	loaded := err == nil
	if err != nil {
		s.warnRuntime(
			"runtime-state-load",
			"runtime state unavailable; continuing without persisted snooze or allow-once state: %v",
			err,
		)
		state = userstate.State{}
	}

	if !s.pendingAllowOnceConsumed {
		return state
	}
	if !loaded {
		return state
	}
	if !state.AllowOnce {
		s.pendingAllowOnceConsumed = false
		return state
	}

	state.AllowOnce = false
	if err := s.saveRuntimeState(state); err != nil {
		s.warnRuntime("runtime-state-save", "runtime state save failed; continuing with enforcement: %v", err)
		return state
	}

	s.pendingAllowOnceConsumed = false
	return state
}

func (s *Service) shouldBypassEnforcement() (bool, string, error) {
	state, err := s.loadRuntimeState()
	if err != nil {
		return false, "", err
	}
	return s.shouldBypassEnforcementWithState(state, true)
}

func (s *Service) shouldBypassEnforcementForRun(
	state userstate.State,
	allowOnceEligible bool,
) (bool, string) {
	bypass, reason, err := s.shouldBypassEnforcementWithState(state, allowOnceEligible)
	if err == nil {
		return bypass, reason
	}

	s.warnRuntime("runtime-state-save", "runtime state save failed; continuing with enforcement: %v", err)
	return false, ""
}

func (s *Service) shouldBypassEnforcementWithState(
	state userstate.State,
	allowOnceEligible bool,
) (bool, string, error) {
	if s.stateStore == nil {
		return false, "", nil
	}

	now := s.timeNow()
	if snoozedUntil, ok := state.ActiveSnoozedUntil(now); ok {
		return true, fmt.Sprintf("snoozed until %s", snoozedUntil.Local().Format(time.RFC3339)), nil
	}

	dirty := false
	if !state.SnoozedUntil.IsZero() {
		state.SnoozedUntil = time.Time{}
		dirty = true
	}

	if state.AllowOnce && allowOnceEligible {
		state.AllowOnce = false
		dirty = true
		if err := s.saveRuntimeState(state); err != nil {
			s.pendingAllowOnceConsumed = true
			return false, "", fmt.Errorf("save runtime state: %w", err)
		}
		s.pendingAllowOnceConsumed = false
		return true, "allow-once consumed", nil
	}

	if dirty {
		if err := s.saveRuntimeState(state); err != nil {
			return false, "", fmt.Errorf("save runtime state: %w", err)
		}
	}

	return false, "", nil
}

func (s *Service) saveRuntimeState(state userstate.State) error {
	if s.stateStore == nil {
		return nil
	}
	return s.stateStore.Save(state)
}

func (s *Service) logVerbose(format string, args ...any) {
	if s.verboseOutput == nil {
		return
	}
	_, _ = fmt.Fprintf(s.verboseOutput, format+"\n", args...)
}

func (s *Service) warnRuntime(key string, format string, args ...any) {
	if s.warningOutput == nil {
		return
	}
	if !s.shouldWarn(key) {
		return
	}
	_, _ = fmt.Fprintf(s.warningOutput, "warning: "+format+"\n", args...)
}

func (s *Service) shouldWarn(key string) bool {
	if s.warningDebounce <= 0 {
		return true
	}

	now := s.timeNow()
	s.evictExpiredWarnings(now)
	last, ok := s.lastWarningByKey[key]
	if ok && now.Sub(last) < s.warningDebounce {
		return false
	}
	s.lastWarningByKey[key] = now
	return true
}

func (s *Service) evictExpiredWarnings(now time.Time) {
	for key, last := range s.lastWarningByKey {
		if now.Sub(last) >= s.warningDebounce {
			delete(s.lastWarningByKey, key)
		}
	}
}

func (s *Service) newScanDecision(
	decision PolicyDecision,
	result policyResult,
	currentHash [32]byte,
) ScanDecision {
	return ScanDecision{
		ActiveAppName:     decision.ActiveAppName,
		ActiveAppBundleID: decision.ActiveAppBundleID,
		Score:             decision.Score,
		RiskLevel:         decision.RiskLevel,
		Action:            decision.Action,
		PolicySource:      decision.PolicySource,
		Findings:          len(result.Findings),
		FindingTypes:      findingTypes(result.Findings),
		ContentHash:       hashToHex(currentHash),
		Allowlisted:       result.Allowlisted,
		AppContextStatus:  decision.AppContextStatus,
		AppContextError:   decision.AppContextError,
	}
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
	if metadata := auditlogMetadataForDecision(decision); metadata != nil {
		entry.AppContext = metadata
	}
	if err := s.auditLogStore.Log(entry); err != nil {
		s.logVerbose("audit log write failed: %v", err)
	}
}

func (s *Service) decisionReasoning(decision PolicyDecision, result policyResult) []string {
	reasons := make([]string, 0, 6)
	if appContext := formatAppContext(decision.ActiveAppName, decision.ActiveAppBundleID); appContext != "" {
		reasons = append(reasons, appContext)
	}
	switch decision.AppContextStatus {
	case AppContextStatusResolutionFailed:
		reasons = append(
			reasons,
			fmt.Sprintf("foreground app detection failed: %s", decision.AppContextError),
			"global policy was used because app context could not be resolved; per-app overrides were skipped",
		)
	case AppContextStatusUnavailable:
		reasons = append(reasons, "foreground app context unavailable; using global policy")
	}
	reasons = append(reasons, fmt.Sprintf("policy_source=%s", decision.PolicySource))

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

func auditlogMetadataForDecision(decision ScanDecision) *auditlog.AppContextMetadata {
	if decision.AppContextStatus == AppContextStatusResolved {
		return nil
	}

	metadata := &auditlog.AppContextMetadata{
		Status:       string(decision.AppContextStatus),
		PolicySource: string(decision.PolicySource),
	}
	if decision.AppContextError != "" {
		metadata.Error = decision.AppContextError
	}
	return metadata
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
