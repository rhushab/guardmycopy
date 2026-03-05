package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rhushabhbontapalle/guardmycopy/internal/core"
)

func TestLoadDefaultsWhenDefaultFileMissing(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if cfg.PollInterval != 500*time.Millisecond {
		t.Fatalf("unexpected default interval: %v", cfg.PollInterval)
	}
	if len(cfg.PerAppBundleID) != 0 {
		t.Fatalf("expected empty per_app_bundle_id defaults, got %d entries", len(cfg.PerAppBundleID))
	}
	if !cfg.Global.DetectorEnabled(core.FindingTypeJWT) {
		t.Fatal("expected jwt detector enabled by default")
	}
	if !cfg.Global.DetectorEnabled(core.FindingTypeStripeSecretKey) {
		t.Fatal("expected stripe secret key detector enabled by default")
	}
	if cfg.Global.ActionForRisk(core.RiskLevelHigh) != ActionBlock {
		t.Fatalf("unexpected default action: %q", cfg.Global.ActionForRisk(core.RiskLevelHigh))
	}
}

func TestLoadFromYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "guardmycopy.yaml")

	content := `global:
  poll_interval_ms: 1250
  thresholds:
    med: 5
    high: 20
  detector_toggles:
    jwt: false
    aws_access_key_id: false
  actions:
    low: allow
    med: warn
    high: block
  allowlist_patterns:
    - '^public_[A-Z0-9]+$'
per_app:
  "Google Chrome":
    thresholds:
      med: 10
    detector_toggles:
      env_secret: false
      github_pat_classic: false
    actions:
      high: sanitize
    allowlist_patterns:
      - '^chrome_safe_.*$'
per_app_bundle_id:
  "com.google.Chrome":
    thresholds:
      med: 3
    actions:
      med: block
`

	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if cfg.PollInterval != 1250*time.Millisecond {
		t.Fatalf("unexpected interval: %v", cfg.PollInterval)
	}

	if got := cfg.Global.Thresholds.Med; got != 5 {
		t.Fatalf("unexpected global med threshold: %d", got)
	}
	if got := cfg.Global.Thresholds.High; got != 20 {
		t.Fatalf("unexpected global high threshold: %d", got)
	}
	if cfg.Global.DetectorEnabled(core.FindingTypeJWT) {
		t.Fatal("expected jwt detector disabled in global policy")
	}
	if cfg.Global.DetectorEnabled(core.FindingTypeAWSAccessKeyID) {
		t.Fatal("expected aws_access_key_id detector disabled in global policy")
	}
	if cfg.Global.ActionForRisk(core.RiskLevelMed) != ActionWarn {
		t.Fatalf("unexpected global medium action: %q", cfg.Global.ActionForRisk(core.RiskLevelMed))
	}
	if cfg.Global.ActionForRisk(core.RiskLevelHigh) != ActionBlock {
		t.Fatalf("unexpected global high action: %q", cfg.Global.ActionForRisk(core.RiskLevelHigh))
	}
	if !cfg.Global.IsAllowlisted("public_TOKEN") {
		t.Fatal("expected global allowlist pattern to match")
	}

	chromePolicy := cfg.PolicyForApp("Google Chrome")
	if chromePolicy.Thresholds.Med != 10 {
		t.Fatalf("unexpected per-app med threshold: %d", chromePolicy.Thresholds.Med)
	}
	if chromePolicy.Thresholds.High != 20 {
		t.Fatalf("unexpected per-app high threshold inheritance: %d", chromePolicy.Thresholds.High)
	}
	if chromePolicy.DetectorEnabled(core.FindingTypeEnvSecret) {
		t.Fatal("expected env_secret detector disabled in per-app policy")
	}
	if chromePolicy.DetectorEnabled(core.FindingTypeGitHubPATClassic) {
		t.Fatal("expected github_pat_classic detector disabled in per-app policy")
	}
	if chromePolicy.ActionForRisk(core.RiskLevelHigh) != ActionSanitize {
		t.Fatalf("unexpected per-app high action: %q", chromePolicy.ActionForRisk(core.RiskLevelHigh))
	}
	if !chromePolicy.IsAllowlisted("public_TOKEN") {
		t.Fatal("expected per-app allowlist to include global regex")
	}
	if !chromePolicy.IsAllowlisted("chrome_safe_123") {
		t.Fatal("expected per-app allowlist pattern to match")
	}

	chromeBundlePolicy := cfg.PolicyForAppAndBundleID("Google Chrome", "com.google.Chrome")
	if chromeBundlePolicy.Thresholds.Med != 3 {
		t.Fatalf("unexpected per-app-bundle-id med threshold: %d", chromeBundlePolicy.Thresholds.Med)
	}
	if chromeBundlePolicy.ActionForRisk(core.RiskLevelMed) != ActionBlock {
		t.Fatalf("unexpected per-app-bundle-id medium action: %q", chromeBundlePolicy.ActionForRisk(core.RiskLevelMed))
	}
	if chromeBundlePolicy.ActionForRisk(core.RiskLevelHigh) != ActionBlock {
		t.Fatalf(
			"unexpected per-app-bundle-id high action inheritance: %q",
			chromeBundlePolicy.ActionForRisk(core.RiskLevelHigh),
		)
	}
	if !chromeBundlePolicy.IsAllowlisted("public_TOKEN") {
		t.Fatal("expected per-app-bundle-id allowlist to include global regex")
	}

	chromeWithoutBundle := cfg.PolicyForAppAndBundleID("Google Chrome", "com.google.ChromeBeta")
	if chromeWithoutBundle.Thresholds.Med != 10 {
		t.Fatalf("expected app-name fallback med threshold 10, got %d", chromeWithoutBundle.Thresholds.Med)
	}
	if chromeWithoutBundle.ActionForRisk(core.RiskLevelMed) != ActionWarn {
		t.Fatalf("expected app-name fallback medium action warn, got %q", chromeWithoutBundle.ActionForRisk(core.RiskLevelMed))
	}

	fallback := cfg.PolicyForApp("Unknown App")
	if fallback.ActionForRisk(core.RiskLevelHigh) != ActionBlock {
		t.Fatalf("unexpected fallback action: %q", fallback.ActionForRisk(core.RiskLevelHigh))
	}

	legacyLookup := cfg.PolicyForApp("Google Chrome")
	if legacyLookup.Thresholds.Med != chromePolicy.Thresholds.Med {
		t.Fatalf("PolicyForApp should preserve per_app semantics, got med=%d", legacyLookup.Thresholds.Med)
	}
}

func TestLoadRejectsNegativeInterval(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "guardmycopy.yaml")

	if err := os.WriteFile(path, []byte("global:\n  poll_interval_ms: -1\n"), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	if _, err := Load(path); err == nil {
		t.Fatal("expected error for negative global.poll_interval_ms")
	}
}

func TestLoadRejectsEmptyPerAppBundleIDKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "guardmycopy.yaml")

	content := `per_app_bundle_id:
  "":
    actions:
      high: block
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	if _, err := Load(path); err == nil {
		t.Fatal("expected error for empty per_app_bundle_id key")
	}
}

func TestLoadWithWarningsSkipsInvalidAllowlistRegex(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "guardmycopy.yaml")

	if err := os.WriteFile(path, []byte("global:\n  allowlist_patterns:\n    - \"[invalid\"\n"), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, warnings, err := LoadWithWarnings(path)
	if err != nil {
		t.Fatalf("LoadWithWarnings returned error: %v", err)
	}
	if len(warnings) == 0 {
		t.Fatal("expected warning for invalid allowlist regex")
	}
	if cfg.Global.IsAllowlisted("anything") {
		t.Fatal("expected invalid allowlist regex to be ignored")
	}
}

func TestLoadWithWarningsClampsLowPollInterval(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "guardmycopy.yaml")

	if err := os.WriteFile(path, []byte("global:\n  poll_interval_ms: 1\n"), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, warnings, err := LoadWithWarnings(path)
	if err != nil {
		t.Fatalf("LoadWithWarnings returned error: %v", err)
	}
	if cfg.PollInterval != MinPollInterval() {
		t.Fatalf("expected poll interval to be clamped to %s, got %s", MinPollInterval(), cfg.PollInterval)
	}
	if len(warnings) == 0 {
		t.Fatal("expected warning for low poll interval")
	}
}

func TestLoadRejectsUnsupportedAction(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "guardmycopy.yaml")

	if err := os.WriteFile(path, []byte("global:\n  actions:\n    high: panic\n"), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	_, err := Load(path)
	if err == nil {
		t.Fatal("expected unsupported action error")
	}
	if !strings.Contains(err.Error(), "unsupported action") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLoadNormalizesCommonTokenPackDetectorToggles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "guardmycopy.yaml")

	content := `global:
  detector_toggles:
    aws-access-key-id: false
    github pat classic: false
    github-pat-fine-grained: false
    slack token: false
    slack-webhook: false
    stripe secret key: false
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}

	if cfg.Global.DetectorEnabled(core.FindingTypeAWSAccessKeyID) {
		t.Fatal("expected aws_access_key_id detector disabled after normalization")
	}
	if cfg.Global.DetectorEnabled(core.FindingTypeGitHubPATClassic) {
		t.Fatal("expected github_pat_classic detector disabled after normalization")
	}
	if cfg.Global.DetectorEnabled(core.FindingTypeGitHubPATFine) {
		t.Fatal("expected github_pat_fine_grained detector disabled after normalization")
	}
	if cfg.Global.DetectorEnabled(core.FindingTypeSlackToken) {
		t.Fatal("expected slack_token detector disabled after normalization")
	}
	if cfg.Global.DetectorEnabled(core.FindingTypeSlackWebhook) {
		t.Fatal("expected slack_webhook detector disabled after normalization")
	}
	if cfg.Global.DetectorEnabled(core.FindingTypeStripeSecretKey) {
		t.Fatal("expected stripe_secret_key detector disabled after normalization")
	}
}

func TestWriteDefaultCreatesConfigFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "config.yaml")

	writtenPath, err := WriteDefault(path, false)
	if err != nil {
		t.Fatalf("WriteDefault returned error: %v", err)
	}
	if writtenPath != path {
		t.Fatalf("unexpected written path: got %q want %q", writtenPath, path)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	if string(data) != DefaultTemplate() {
		t.Fatal("written config did not match default template")
	}

	dirInfo, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatalf("stat config directory: %v", err)
	}
	if got := dirInfo.Mode().Perm(); got&0o077 != 0 {
		t.Fatalf("expected private config directory permissions, got %o", got)
	}

	fileInfo, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat config file: %v", err)
	}
	if got := fileInfo.Mode().Perm(); got&0o077 != 0 {
		t.Fatalf("expected private config file permissions, got %o", got)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if cfg.Global.ActionForRisk(core.RiskLevelHigh) != ActionBlock {
		t.Fatalf("unexpected high risk action: %q", cfg.Global.ActionForRisk(core.RiskLevelHigh))
	}
}

func TestWriteDefaultRejectsExistingWithoutForce(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")

	if err := os.WriteFile(path, []byte("global:\n  poll_interval_ms: 100\n"), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	if _, err := WriteDefault(path, false); err == nil {
		t.Fatal("expected WriteDefault to fail when file exists without force")
	}

	writtenPath, err := WriteDefault(path, true)
	if err != nil {
		t.Fatalf("WriteDefault with force returned error: %v", err)
	}
	if writtenPath != path {
		t.Fatalf("unexpected written path: got %q want %q", writtenPath, path)
	}
}

func TestWriteDefaultUsesDefaultPathWhenEmpty(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))

	path, err := WriteDefault("", false)
	if err != nil {
		t.Fatalf("WriteDefault returned error: %v", err)
	}
	if path != DefaultPath() {
		t.Fatalf("unexpected default path: got %q want %q", path, DefaultPath())
	}

	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if cfg.PollInterval != 500*time.Millisecond {
		t.Fatalf("unexpected poll interval: %v", cfg.PollInterval)
	}
}
