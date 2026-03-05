package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rhushabhbontapalle/guardmycopy/internal/auditlog"
)

func TestParseSinceDuration(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		input string
		want  time.Duration
	}{
		{input: "7d", want: 7 * 24 * time.Hour},
		{input: "12h", want: 12 * time.Hour},
		{input: "30m", want: 30 * time.Minute},
		{input: "1d12h30m", want: (24+12)*time.Hour + 30*time.Minute},
		{input: " 2D4H ", want: (2*24 + 4) * time.Hour},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.input, func(t *testing.T) {
			t.Parallel()

			got, err := parseSinceDuration(tc.input)
			if err != nil {
				t.Fatalf("parseSinceDuration returned error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("unexpected duration: got %s want %s", got, tc.want)
			}
		})
	}
}

func TestParseSinceDurationRejectsInvalidValues(t *testing.T) {
	t.Parallel()

	invalid := []string{
		"",
		"0m",
		"7",
		"d7",
		"1h30",
		"5s",
		"-1h",
		"1w",
	}

	for _, input := range invalid {
		input := input
		t.Run(input, func(t *testing.T) {
			t.Parallel()

			if _, err := parseSinceDuration(input); err == nil {
				t.Fatalf("expected parseSinceDuration(%q) to fail", input)
			}
		})
	}
}

func TestRunLogStatsWithIOAggregatesAndSkipsBadLines(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "audit.jsonl")
	now := time.Unix(1_700_000_000, 0).UTC()

	lines := make([]string, 0, 10)
	appendEntry := func(entry auditlog.Entry) {
		payload, err := json.Marshal(entry)
		if err != nil {
			t.Fatalf("marshal entry: %v", err)
		}
		lines = append(lines, string(payload))
	}

	appendEntry(auditlog.Entry{
		Timestamp:    now.Add(-1 * time.Hour),
		App:          "Slack",
		Score:        15,
		RiskLevel:    "high",
		FindingTypes: []string{"pem_private_key", "jwt"},
		Action:       "block",
		ContentHash:  "hash-1",
	})
	appendEntry(auditlog.Entry{
		Timestamp:    now.Add(-2 * time.Hour),
		App:          "Slack",
		Score:        8,
		RiskLevel:    "med",
		FindingTypes: []string{"jwt"},
		Action:       "warn",
		ContentHash:  "hash-2",
	})
	appendEntry(auditlog.Entry{
		Timestamp:    now.Add(-3 * time.Hour),
		App:          "Google Chrome",
		Score:        12,
		RiskLevel:    "med",
		FindingTypes: []string{"env_secret"},
		Action:       "block",
		ContentHash:  "hash-3",
	})
	appendEntry(auditlog.Entry{
		Timestamp:    now.Add(-4 * time.Hour),
		App:          "Terminal",
		Score:        2,
		RiskLevel:    "low",
		FindingTypes: nil,
		Action:       "allow",
		ContentHash:  "hash-4",
	})
	appendEntry(auditlog.Entry{
		Timestamp:    now.Add(-8 * 24 * time.Hour),
		App:          "Slack",
		Score:        15,
		RiskLevel:    "high",
		FindingTypes: []string{"jwt"},
		Action:       "block",
		ContentHash:  "hash-old",
	})
	lines = append(lines, "")
	lines = append(lines, "{not-json}")
	lines = append(lines, `{"timestamp":"not-a-time","app":"BadTS","riskLevel":"high","findingTypes":["jwt"],"action":"block","contentHash":"bad-ts"}`)
	lines = append(lines, `{"app":"MissingTS","riskLevel":"high","findingTypes":["jwt"],"action":"block","contentHash":"missing-ts"}`)

	if err := os.WriteFile(logPath, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatalf("write audit log fixture: %v", err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := runLogStatsWithIO(
		[]string{"--since", "7d"},
		&stdout,
		&stderr,
		logPath,
		func() time.Time { return now },
	)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (stderr=%q)", code, stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected empty stderr, got %q", stderr.String())
	}

	output := stdout.String()
	if !strings.Contains(output, "entries=4 skipped=4") {
		t.Fatalf("expected entries/skipped summary, got %q", output)
	}
	if !strings.Contains(output, `1. app="Slack" blocked=1 warned=1 total=2`) {
		t.Fatalf("expected Slack app counts, got %q", output)
	}
	if !strings.Contains(output, `2. app="Google Chrome" blocked=1 warned=0 total=1`) {
		t.Fatalf("expected Google Chrome app counts, got %q", output)
	}
	if !strings.Contains(output, "low=1") || !strings.Contains(output, "med=2") || !strings.Contains(output, "high=1") {
		t.Fatalf("expected risk counts, got %q", output)
	}

	expectedLatestReason := now.Add(-1*time.Hour).Format(time.RFC3339) + ` app="Slack" reasons=jwt,pem_private_key`
	if !strings.Contains(output, expectedLatestReason) {
		t.Fatalf("expected latest Slack block reason, got %q", output)
	}
	expectedSecondReason := now.Add(-3*time.Hour).Format(time.RFC3339) + ` app="Google Chrome" reasons=env_secret`
	if !strings.Contains(output, expectedSecondReason) {
		t.Fatalf("expected Google Chrome block reason, got %q", output)
	}
	if strings.Contains(output, "hash-old") {
		t.Fatalf("expected out-of-window entries to be excluded, got %q", output)
	}
}

func TestRunLogWithIOStatsRequiresSince(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := runLogWithIO([]string{"stats"}, &stdout, &stderr, filepath.Join(t.TempDir(), "audit.jsonl"))
	if code != 2 {
		t.Fatalf("expected exit code 2, got %d", code)
	}
	if !strings.Contains(stderr.String(), "requires --since") {
		t.Fatalf("expected missing since message, got %q", stderr.String())
	}
}

func TestRunLogWithIOStatsMissingFile(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := runLogWithIO(
		[]string{"stats", "--since", "7d"},
		&stdout,
		&stderr,
		filepath.Join(t.TempDir(), "does-not-exist.jsonl"),
	)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (stderr=%q)", code, stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected empty stderr, got %q", stderr.String())
	}
	if !strings.Contains(stdout.String(), "entries=0") {
		t.Fatalf("expected empty stats output, got %q", stdout.String())
	}
}
