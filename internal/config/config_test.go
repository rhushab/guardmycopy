package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rhushabhbontapalle/clipguard/internal/core"
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
	if !cfg.Global.DetectorEnabled(core.FindingTypeJWT) {
		t.Fatal("expected jwt detector enabled by default")
	}
	if cfg.Global.ActionForRisk(core.RiskLevelHigh) != ActionSanitize {
		t.Fatalf("unexpected default action: %q", cfg.Global.ActionForRisk(core.RiskLevelHigh))
	}
}

func TestLoadFromYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "clipguard.yaml")

	content := `global:
  poll_interval_ms: 1250
  thresholds:
    med: 5
    high: 20
  detector_toggles:
    jwt: false
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
    actions:
      high: sanitize
    allowlist_patterns:
      - '^chrome_safe_.*$'
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
	if chromePolicy.ActionForRisk(core.RiskLevelHigh) != ActionSanitize {
		t.Fatalf("unexpected per-app high action: %q", chromePolicy.ActionForRisk(core.RiskLevelHigh))
	}
	if !chromePolicy.IsAllowlisted("public_TOKEN") {
		t.Fatal("expected per-app allowlist to include global regex")
	}
	if !chromePolicy.IsAllowlisted("chrome_safe_123") {
		t.Fatal("expected per-app allowlist pattern to match")
	}

	fallback := cfg.PolicyForApp("Unknown App")
	if fallback.ActionForRisk(core.RiskLevelHigh) != ActionBlock {
		t.Fatalf("unexpected fallback action: %q", fallback.ActionForRisk(core.RiskLevelHigh))
	}
}

func TestLoadRejectsNegativeInterval(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "clipguard.yaml")

	if err := os.WriteFile(path, []byte("global:\n  poll_interval_ms: -1\n"), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	if _, err := Load(path); err == nil {
		t.Fatal("expected error for negative global.poll_interval_ms")
	}
}

func TestLoadRejectsInvalidAllowlistRegex(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "clipguard.yaml")

	if err := os.WriteFile(path, []byte("global:\n  allowlist_patterns:\n    - \"[invalid\"\n"), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	if _, err := Load(path); err == nil {
		t.Fatal("expected regex validation error")
	}
}

func TestLoadRejectsUnsupportedAction(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "clipguard.yaml")

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
