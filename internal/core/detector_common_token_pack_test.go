package core

import "testing"

func TestCommonTokenPackDetectorTruePositives(t *testing.T) {
	detector := NewCommonTokenPackDetector()

	tests := []struct {
		name      string
		input     string
		wantType  string
		wantLabel string
		wantToken string
	}{
		{
			name:      "detects aws access key id",
			input:     "aws_access_key_id=AKIAIOSFODNN7EXAMPLE",
			wantType:  FindingTypeAWSAccessKeyID,
			wantLabel: "AWS access key ID",
			wantToken: "AKIAIOSFODNN7EXAMPLE",
		},
		{
			name:      "detects github classic pat",
			input:     "token=ghp_abcdefghijklmnopqrstuvwxyzABCDEF1234",
			wantType:  FindingTypeGitHubPATClassic,
			wantLabel: "GitHub token (classic PAT)",
			wantToken: "ghp_abcdefghijklmnopqrstuvwxyzABCDEF1234",
		},
		{
			name:      "detects github fine grained pat",
			input:     "token=github_pat_11ABCDEFghijklMNOPQR_1234567890abcdefghijklmnopqrst",
			wantType:  FindingTypeGitHubPATFine,
			wantLabel: "GitHub token (fine-grained PAT)",
			wantToken: "github_pat_11ABCDEFghijklMNOPQR_1234567890abcdefghijklmnopqrst",
		},
		{
			name:      "detects slack token",
			input:     "xoxb-123456789012-123456789012-abcdefghijklmnopqrstuvwxABCD",
			wantType:  FindingTypeSlackToken,
			wantLabel: "Slack token",
			wantToken: "xoxb-123456789012-123456789012-abcdefghijklmnopqrstuvwxABCD",
		},
		{
			name:      "detects slack webhook",
			input:     "https://hooks.slack.com/services/T00000000/B00000000/abcdefghijklmnopqrstuvwxABCD",
			wantType:  FindingTypeSlackWebhook,
			wantLabel: "Slack webhook URL",
			wantToken: "https://hooks.slack.com/services/T00000000/B00000000/abcdefghijklmnopqrstuvwxABCD",
		},
		{
			name:      "detects stripe secret key",
			input:     "sk_live_51NqkI2abcdefghijklmnopqrstuvwxABCD",
			wantType:  FindingTypeStripeSecretKey,
			wantLabel: "Stripe secret key",
			wantToken: "sk_live_51NqkI2abcdefghijklmnopqrstuvwxABCD",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			findings := detector.Detect(tc.input)
			if len(findings) != 1 {
				t.Fatalf("unexpected finding count: got %d want 1", len(findings))
			}

			finding := findings[0]
			if finding.Type != tc.wantType {
				t.Fatalf("unexpected finding type: got %q want %q", finding.Type, tc.wantType)
			}
			if finding.Label != tc.wantLabel {
				t.Fatalf("unexpected finding label: got %q want %q", finding.Label, tc.wantLabel)
			}
			if finding.Severity != SeverityHigh {
				t.Fatalf("unexpected finding severity: got %q want %q", finding.Severity, SeverityHigh)
			}

			gotToken := tc.input[finding.Start:finding.End]
			if gotToken != tc.wantToken {
				t.Fatalf("unexpected token match: got %q want %q", gotToken, tc.wantToken)
			}
		})
	}
}

func TestCommonTokenPackDetectorFalsePositiveGuards(t *testing.T) {
	detector := NewCommonTokenPackDetector()

	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "ignores lowercase aws prefix",
			input: "akiaIOSFODNN7EXAMPLE",
		},
		{
			name:  "ignores short github classic prefix",
			input: "ghp_abc123",
		},
		{
			name:  "ignores malformed github fine grained token",
			input: "github_pat_ABCDEFGHIJKLMNOPQRSTUVWX",
		},
		{
			name:  "ignores slack-like token with only one dash section",
			input: "xoxb-abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
		},
		{
			name:  "ignores non slack webhook hostname",
			input: "https://hooks.slack.example.com/services/T00000000/B00000000/abcdefghijklmnopqrstuvwxABCD",
		},
		{
			name:  "ignores stripe publishable key",
			input: "pk_live_51NqkI2abcdefghijklmnopqrstuvwxABCD",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			findings := detector.Detect(tc.input)
			if len(findings) != 0 {
				t.Fatalf("unexpected findings: %+v", findings)
			}
		})
	}
}
