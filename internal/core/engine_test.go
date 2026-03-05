package core

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEngineScan(t *testing.T) {
	engine := New()
	input := fixture(t, "pem_single_input.txt")

	result := engine.Scan(input)

	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result.Findings))
	}
	finding := result.Findings[0]
	if finding.Type != FindingTypePEMPrivateKey {
		t.Fatalf("unexpected finding type: %q", finding.Type)
	}
	if finding.Severity != SeverityHigh {
		t.Fatalf("unexpected finding severity: %q", finding.Severity)
	}

	expectedStart := strings.Index(input, "-----BEGIN")
	if finding.Start != expectedStart {
		t.Fatalf("unexpected finding start: got %d want %d", finding.Start, expectedStart)
	}
	if finding.End <= finding.Start {
		t.Fatalf("invalid finding range: start=%d end=%d", finding.Start, finding.End)
	}

	if result.Score != DefaultScoreWeights().High {
		t.Fatalf("unexpected score: got %d want %d", result.Score, DefaultScoreWeights().High)
	}
	if result.RiskLevel != RiskLevelHigh {
		t.Fatalf("unexpected risk level: got %q want %q", result.RiskLevel, RiskLevelHigh)
	}
}

func TestEngineSanitizeSingleKey(t *testing.T) {
	engine := New()

	input := fixture(t, "pem_single_input.txt")
	want := fixture(t, "pem_single_sanitized.txt")
	result := engine.Sanitize(input)

	if result.SanitizedText != want {
		t.Fatalf("unexpected sanitized output: got %q want %q", result.SanitizedText, want)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result.Findings))
	}
	if result.RiskLevel != RiskLevelHigh {
		t.Fatalf("unexpected risk level: got %q want %q", result.RiskLevel, RiskLevelHigh)
	}
}

func TestEngineSanitizeMultipleKeys(t *testing.T) {
	engine := New()

	input := fixture(t, "pem_multiple_input.txt")
	want := fixture(t, "pem_multiple_sanitized.txt")
	result := engine.Sanitize(input)

	if result.SanitizedText != want {
		t.Fatalf("unexpected sanitized output: got %q want %q", result.SanitizedText, want)
	}
	if len(result.Findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(result.Findings))
	}
	if result.Score != 2*DefaultScoreWeights().High {
		t.Fatalf("unexpected score: got %d want %d", result.Score, 2*DefaultScoreWeights().High)
	}
	if result.RiskLevel != RiskLevelHigh {
		t.Fatalf("unexpected risk level: got %q want %q", result.RiskLevel, RiskLevelHigh)
	}
}

func TestEngineSanitizeNoFindings(t *testing.T) {
	engine := New()

	input := "hello world"
	result := engine.Sanitize(input)

	if result.SanitizedText != input {
		t.Fatalf("unexpected sanitized output: got %q want %q", result.SanitizedText, input)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(result.Findings))
	}
	if result.Score != 0 {
		t.Fatalf("unexpected score: got %d want 0", result.Score)
	}
	if result.RiskLevel != RiskLevelLow {
		t.Fatalf("unexpected risk level: got %q want %q", result.RiskLevel, RiskLevelLow)
	}
}

func TestEngineScanDetectsCommonTokenPack(t *testing.T) {
	engine := New()

	input := "Stripe key: sk_test_51NqkI2abcdefghijklmnopqrstuvwxABCD"
	result := engine.Scan(input)

	if len(result.Findings) == 0 {
		t.Fatal("expected at least one finding")
	}

	foundStripe := false
	for _, finding := range result.Findings {
		if finding.Type == FindingTypeStripeSecretKey {
			foundStripe = true
			break
		}
	}
	if !foundStripe {
		t.Fatalf("expected finding type %q, got %#v", FindingTypeStripeSecretKey, result.Findings)
	}
}

func TestEngineScanPrefersNamedTokenFindingOverGenericOverlap(t *testing.T) {
	engine := New()

	input := "GITHUB_TOKEN=ghp_abcdefghijklmnopqrstuvwxyzABCDEF1234"
	result := engine.Scan(input)

	if len(result.Findings) != 1 {
		t.Fatalf("expected one deduped finding, got %#v", result.Findings)
	}
	if result.Findings[0].Type != FindingTypeGitHubPATClassic {
		t.Fatalf("unexpected finding type after dedupe: got %q want %q", result.Findings[0].Type, FindingTypeGitHubPATClassic)
	}
}

func fixture(t *testing.T, name string) string {
	t.Helper()

	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read fixture %q: %v", name, err)
	}
	return string(data)
}
