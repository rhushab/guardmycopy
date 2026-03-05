package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/rhushabhbontapalle/guardmycopy/internal/core"
	"gopkg.in/yaml.v3"
)

const defaultPollInterval = 500 * time.Millisecond
const minPollInterval = 100 * time.Millisecond

const (
	defaultConfigDirName       = "guardmycopy"
	defaultConfigFileName      = "config.yaml"
	legacyDefaultConfigDirName = ".config/guardmycopy"
	defaultConfigDirMode       = 0o700
	defaultConfigFileMode      = 0o600
	defaultConfigTemplate      = `global:
  poll_interval_ms: 500
  thresholds:
    med: 8
    high: 15
  detector_toggles:
    pem_private_key: true
    jwt: true
    env_secret: true
    high_entropy_token: true
    aws_access_key_id: true
    github_pat_classic: true
    github_pat_fine_grained: true
    slack_token: true
    slack_webhook: true
    stripe_secret_key: true
  actions:
    low: allow
    med: sanitize
    high: block
  allowlist_patterns:
    - '(?i)^public_[A-Z0-9_]+$'

per_app:
  "Google Chrome":
    actions:
      med: warn
      high: block
    allowlist_patterns:
      - '^chrome-extension://'
per_app_bundle_id:
  "com.google.Chrome":
    actions:
      high: block
`
)

type Action string

const (
	ActionAllow    Action = "allow"
	ActionWarn     Action = "warn"
	ActionSanitize Action = "sanitize"
	ActionBlock    Action = "block"
)

type Thresholds struct {
	Med  int
	High int
}

type Policy struct {
	Thresholds        Thresholds
	DetectorToggles   map[string]bool
	Actions           map[core.RiskLevel]Action
	AllowlistPatterns []string

	allowlistRegex []*regexp.Regexp
}

type Config struct {
	PollInterval   time.Duration
	Global         Policy
	PerApp         map[string]Policy
	PerAppBundleID map[string]Policy
}

type fileConfig struct {
	Global         globalConfig          `yaml:"global"`
	PerApp         map[string]policyFile `yaml:"per_app"`
	PerAppBundleID map[string]policyFile `yaml:"per_app_bundle_id"`
}

type globalConfig struct {
	PollIntervalMS   *int              `yaml:"poll_interval_ms"`
	Thresholds       thresholdsFile    `yaml:"thresholds"`
	DetectorToggles  map[string]bool   `yaml:"detector_toggles"`
	Actions          map[string]string `yaml:"actions"`
	AllowlistPattern []string          `yaml:"allowlist_patterns"`
}

type policyFile struct {
	Thresholds       thresholdsFile    `yaml:"thresholds"`
	DetectorToggles  map[string]bool   `yaml:"detector_toggles"`
	Actions          map[string]string `yaml:"actions"`
	AllowlistPattern []string          `yaml:"allowlist_patterns"`
}

type thresholdsFile struct {
	Med    *int `yaml:"med"`
	Medium *int `yaml:"medium"`
	High   *int `yaml:"high"`
}

func Defaults() Config {
	weights := core.DefaultScoreWeights()

	return Config{
		PollInterval: NormalizePollInterval(defaultPollInterval),
		Global: Policy{
			Thresholds: Thresholds{
				Med:  weights.Medium,
				High: weights.High,
			},
			DetectorToggles: map[string]bool{
				core.FindingTypePEMPrivateKey:    true,
				core.FindingTypeJWT:              true,
				core.FindingTypeEnvSecret:        true,
				core.FindingTypeHighEntropyToken: true,
				core.FindingTypeAWSAccessKeyID:   true,
				core.FindingTypeGitHubPATClassic: true,
				core.FindingTypeGitHubPATFine:    true,
				core.FindingTypeSlackToken:       true,
				core.FindingTypeSlackWebhook:     true,
				core.FindingTypeStripeSecretKey:  true,
			},
			Actions: map[core.RiskLevel]Action{
				core.RiskLevelLow:  ActionAllow,
				core.RiskLevelMed:  ActionSanitize,
				core.RiskLevelHigh: ActionBlock,
			},
			AllowlistPatterns: nil,
			allowlistRegex:    nil,
		},
		PerApp:         map[string]Policy{},
		PerAppBundleID: map[string]Policy{},
	}
}

func MinPollInterval() time.Duration {
	return minPollInterval
}

func NormalizePollInterval(interval time.Duration) time.Duration {
	if interval <= 0 {
		return defaultPollInterval
	}
	if interval < minPollInterval {
		return minPollInterval
	}
	return interval
}

func DefaultPath() string {
	configDir, err := os.UserConfigDir()
	if err == nil && strings.TrimSpace(configDir) != "" {
		return filepath.Join(configDir, defaultConfigDirName, defaultConfigFileName)
	}

	home, err := os.UserHomeDir()
	if err == nil && strings.TrimSpace(home) != "" {
		return filepath.Join(home, legacyDefaultConfigDirName, defaultConfigFileName)
	}

	return filepath.Join(defaultConfigDirName, defaultConfigFileName)
}

func DefaultTemplate() string {
	return defaultConfigTemplate
}

func WriteDefault(path string, overwrite bool) (string, error) {
	resolvedPath := strings.TrimSpace(path)
	if resolvedPath == "" {
		resolvedPath = DefaultPath()
	}

	if err := os.MkdirAll(filepath.Dir(resolvedPath), defaultConfigDirMode); err != nil {
		return "", fmt.Errorf("create config directory: %w", err)
	}

	openFlags := os.O_CREATE | os.O_WRONLY
	if overwrite {
		openFlags |= os.O_TRUNC
	} else {
		openFlags |= os.O_EXCL
	}

	file, err := os.OpenFile(resolvedPath, openFlags, defaultConfigFileMode)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return "", fmt.Errorf("config file already exists at %s (use --force to overwrite)", resolvedPath)
		}
		return "", fmt.Errorf("open config file: %w", err)
	}
	defer file.Close()

	if _, err := file.WriteString(defaultConfigTemplate); err != nil {
		return "", fmt.Errorf("write config file: %w", err)
	}

	return resolvedPath, nil
}

func Load(path string) (Config, error) {
	cfg, err := load(path, nil)
	return cfg, err
}

func LoadWithWarnings(path string) (Config, []string, error) {
	warnings := make([]string, 0)
	cfg, err := load(path, func(message string) {
		warnings = append(warnings, message)
	})
	if err != nil {
		return Config{}, warnings, err
	}
	return cfg, warnings, nil
}

func load(path string, warn func(string)) (Config, error) {
	cfg := Defaults()

	resolvedPath := strings.TrimSpace(path)
	usingDefaultPath := resolvedPath == ""
	if usingDefaultPath {
		resolvedPath = DefaultPath()
	}

	data, err := os.ReadFile(resolvedPath)
	if err != nil {
		if usingDefaultPath && errors.Is(err, os.ErrNotExist) {
			return cfg, nil
		}
		return Config{}, fmt.Errorf("read config file: %w", err)
	}

	var fromFile fileConfig
	if err := yaml.Unmarshal(data, &fromFile); err != nil {
		return Config{}, fmt.Errorf("parse config file: %w", err)
	}

	if err := applyGlobalConfig(&cfg, fromFile.Global, warn); err != nil {
		return Config{}, err
	}
	if err := finalizePolicy(&cfg.Global, "global", warn); err != nil {
		return Config{}, fmt.Errorf("global policy: %w", err)
	}

	cfg.PerApp = make(map[string]Policy, len(fromFile.PerApp))
	for appName, fromApp := range fromFile.PerApp {
		if strings.TrimSpace(appName) == "" {
			return Config{}, errors.New("per_app contains empty app name")
		}

		policy := clonePolicy(cfg.Global)
		if err := applyPolicyOverride(&policy, fromApp); err != nil {
			return Config{}, fmt.Errorf("per_app %q: %w", appName, err)
		}
		if err := finalizePolicy(&policy, fmt.Sprintf("per_app.%s", appName), warn); err != nil {
			return Config{}, fmt.Errorf("per_app %q: %w", appName, err)
		}
		cfg.PerApp[appName] = policy
	}

	cfg.PerAppBundleID = make(map[string]Policy, len(fromFile.PerAppBundleID))
	for bundleID, fromApp := range fromFile.PerAppBundleID {
		if strings.TrimSpace(bundleID) == "" {
			return Config{}, errors.New("per_app_bundle_id contains empty bundle identifier")
		}

		policy := clonePolicy(cfg.Global)
		if err := applyPolicyOverride(&policy, fromApp); err != nil {
			return Config{}, fmt.Errorf("per_app_bundle_id %q: %w", bundleID, err)
		}
		if err := finalizePolicy(&policy, fmt.Sprintf("per_app_bundle_id.%s", bundleID), warn); err != nil {
			return Config{}, fmt.Errorf("per_app_bundle_id %q: %w", bundleID, err)
		}
		cfg.PerAppBundleID[bundleID] = policy
	}

	return cfg, nil
}

func (c Config) PolicyForApp(appName string) Policy {
	return c.PolicyForAppAndBundleID(appName, "")
}

func (c Config) PolicyForAppAndBundleID(appName, bundleID string) Policy {
	if bundleID != "" {
		if policy, ok := c.PerAppBundleID[bundleID]; ok {
			return policy
		}
	}
	if policy, ok := c.PerApp[appName]; ok {
		return policy
	}
	return c.Global
}

func (p Policy) DetectorEnabled(detectorType string) bool {
	enabled, ok := p.DetectorToggles[detectorType]
	if !ok {
		return true
	}
	return enabled
}

func (p Policy) ActionForRisk(risk core.RiskLevel) Action {
	if action, ok := p.Actions[risk]; ok {
		return action
	}
	return ActionSanitize
}

func (p Policy) IsAllowlisted(value string) bool {
	for _, pattern := range p.allowlistRegex {
		if pattern.MatchString(value) {
			return true
		}
	}
	return false
}

func applyGlobalConfig(cfg *Config, fromFile globalConfig, warn func(string)) error {
	if fromFile.PollIntervalMS != nil {
		if *fromFile.PollIntervalMS < 0 {
			return errors.New("global.poll_interval_ms must be >= 0")
		}
		if *fromFile.PollIntervalMS > 0 {
			pollInterval := time.Duration(*fromFile.PollIntervalMS) * time.Millisecond
			normalizedInterval := NormalizePollInterval(pollInterval)
			if normalizedInterval != pollInterval {
				addWarning(
					warn,
					fmt.Sprintf(
						"global.poll_interval_ms=%dms is below minimum %dms; using %dms",
						*fromFile.PollIntervalMS,
						MinPollInterval().Milliseconds(),
						normalizedInterval.Milliseconds(),
					),
				)
			}
			cfg.PollInterval = normalizedInterval
		}
	}

	return applyPolicyOverride(&cfg.Global, policyFile{
		Thresholds:       fromFile.Thresholds,
		DetectorToggles:  fromFile.DetectorToggles,
		Actions:          fromFile.Actions,
		AllowlistPattern: fromFile.AllowlistPattern,
	})
}

func applyPolicyOverride(policy *Policy, fromFile policyFile) error {
	if med, ok := fromFile.Thresholds.medValue(); ok {
		policy.Thresholds.Med = med
	}
	if high, ok := fromFile.Thresholds.highValue(); ok {
		policy.Thresholds.High = high
	}

	for detectorKey, enabled := range fromFile.DetectorToggles {
		detectorType, err := normalizeDetectorType(detectorKey)
		if err != nil {
			return fmt.Errorf("detector_toggles: %w", err)
		}
		policy.DetectorToggles[detectorType] = enabled
	}

	for riskKey, actionValue := range fromFile.Actions {
		riskLevel, err := normalizeRiskLevel(riskKey)
		if err != nil {
			return fmt.Errorf("actions: %w", err)
		}
		action, err := normalizeAction(actionValue)
		if err != nil {
			return fmt.Errorf("actions[%q]: %w", riskKey, err)
		}
		policy.Actions[riskLevel] = action
	}

	policy.AllowlistPatterns = append(policy.AllowlistPatterns, fromFile.AllowlistPattern...)
	return nil
}

func finalizePolicy(policy *Policy, scope string, warn func(string)) error {
	if policy.Thresholds.Med <= 0 {
		return errors.New("thresholds.med must be > 0")
	}
	if policy.Thresholds.High < policy.Thresholds.Med {
		return errors.New("thresholds.high must be >= thresholds.med")
	}

	regexList := make([]*regexp.Regexp, 0, len(policy.AllowlistPatterns))
	validPatterns := make([]string, 0, len(policy.AllowlistPatterns))
	for _, expression := range policy.AllowlistPatterns {
		pattern := strings.TrimSpace(expression)
		if pattern == "" {
			addWarning(warn, fmt.Sprintf("%s: empty allowlist pattern ignored", scope))
			continue
		}
		compiled, err := regexp.Compile(pattern)
		if err != nil {
			addWarning(
				warn,
				fmt.Sprintf("%s: invalid allowlist regex %q ignored (%v)", scope, pattern, err),
			)
			continue
		}
		regexList = append(regexList, compiled)
		validPatterns = append(validPatterns, pattern)
	}

	policy.AllowlistPatterns = validPatterns
	policy.allowlistRegex = regexList
	return nil
}

func addWarning(warn func(string), message string) {
	if warn == nil {
		return
	}
	warn(message)
}

func clonePolicy(policy Policy) Policy {
	clonedToggles := make(map[string]bool, len(policy.DetectorToggles))
	for detectorType, enabled := range policy.DetectorToggles {
		clonedToggles[detectorType] = enabled
	}

	clonedActions := make(map[core.RiskLevel]Action, len(policy.Actions))
	for riskLevel, action := range policy.Actions {
		clonedActions[riskLevel] = action
	}

	clonedPatterns := append([]string(nil), policy.AllowlistPatterns...)

	return Policy{
		Thresholds:        policy.Thresholds,
		DetectorToggles:   clonedToggles,
		Actions:           clonedActions,
		AllowlistPatterns: clonedPatterns,
		allowlistRegex:    append([]*regexp.Regexp(nil), policy.allowlistRegex...),
	}
}

func (t thresholdsFile) medValue() (int, bool) {
	if t.Med != nil {
		return *t.Med, true
	}
	if t.Medium != nil {
		return *t.Medium, true
	}
	return 0, false
}

func (t thresholdsFile) highValue() (int, bool) {
	if t.High == nil {
		return 0, false
	}
	return *t.High, true
}

func normalizeDetectorType(value string) (string, error) {
	normalized := normalizeToken(value)

	switch normalized {
	case normalizeToken(core.FindingTypePEMPrivateKey):
		return core.FindingTypePEMPrivateKey, nil
	case normalizeToken(core.FindingTypeJWT):
		return core.FindingTypeJWT, nil
	case normalizeToken(core.FindingTypeEnvSecret):
		return core.FindingTypeEnvSecret, nil
	case normalizeToken(core.FindingTypeHighEntropyToken):
		return core.FindingTypeHighEntropyToken, nil
	case normalizeToken(core.FindingTypeAWSAccessKeyID):
		return core.FindingTypeAWSAccessKeyID, nil
	case normalizeToken(core.FindingTypeGitHubPATClassic):
		return core.FindingTypeGitHubPATClassic, nil
	case normalizeToken(core.FindingTypeGitHubPATFine):
		return core.FindingTypeGitHubPATFine, nil
	case normalizeToken(core.FindingTypeSlackToken):
		return core.FindingTypeSlackToken, nil
	case normalizeToken(core.FindingTypeSlackWebhook):
		return core.FindingTypeSlackWebhook, nil
	case normalizeToken(core.FindingTypeStripeSecretKey):
		return core.FindingTypeStripeSecretKey, nil
	default:
		return "", fmt.Errorf("unsupported detector %q", value)
	}
}

func normalizeRiskLevel(value string) (core.RiskLevel, error) {
	normalized := strings.ToLower(strings.TrimSpace(value))

	switch normalized {
	case string(core.RiskLevelLow):
		return core.RiskLevelLow, nil
	case string(core.RiskLevelMed), "medium":
		return core.RiskLevelMed, nil
	case string(core.RiskLevelHigh):
		return core.RiskLevelHigh, nil
	default:
		return "", fmt.Errorf("unsupported risk level %q", value)
	}
}

func normalizeAction(value string) (Action, error) {
	normalized := Action(strings.ToLower(strings.TrimSpace(value)))

	switch normalized {
	case ActionAllow, ActionWarn, ActionSanitize, ActionBlock:
		return normalized, nil
	default:
		return "", fmt.Errorf("unsupported action %q", value)
	}
}

func normalizeToken(value string) string {
	normalized := strings.ToLower(strings.TrimSpace(value))
	normalized = strings.ReplaceAll(normalized, "-", "_")
	normalized = strings.ReplaceAll(normalized, " ", "_")
	return normalized
}
