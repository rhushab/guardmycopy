package core

import "testing"

func TestPEMPrivateKeyDetectorDetectsAllBlocks(t *testing.T) {
	detector := NewPEMPrivateKeyDetector()
	input := "prefix\n-----BEGIN PRIVATE KEY-----\na\n-----END PRIVATE KEY-----\nmid\n-----BEGIN OPENSSH PRIVATE KEY-----\nb\n-----END OPENSSH PRIVATE KEY-----\nsuffix"

	findings := detector.Detect(input)

	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}
	for i, finding := range findings {
		if finding.Type != FindingTypePEMPrivateKey {
			t.Fatalf("finding %d has unexpected type %q", i, finding.Type)
		}
		if finding.Severity != SeverityHigh {
			t.Fatalf("finding %d has unexpected severity %q", i, finding.Severity)
		}
		if finding.End <= finding.Start {
			t.Fatalf("finding %d has invalid range start=%d end=%d", i, finding.Start, finding.End)
		}
	}
}
