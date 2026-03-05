package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rhushab/guardmycopy/internal/app"
	"github.com/rhushab/guardmycopy/internal/auditlog"
	"github.com/rhushab/guardmycopy/internal/config"
	"github.com/rhushab/guardmycopy/internal/userstate"
)

type testClipboard struct {
	value string
}

type testForegroundApp struct {
	name     string
	bundleID string
	err      error
}

func (t *testClipboard) ReadText() (string, error) {
	return t.value, nil
}

func (t *testClipboard) WriteText(value string) error {
	t.value = value
	return nil
}

func (t *testForegroundApp) ActiveApp() (string, string, error) {
	if t.err != nil {
		return "", "", t.err
	}
	return t.name, t.bundleID, nil
}

func TestRunSanitizeWithIO(t *testing.T) {
	input := "hello\n-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----\nworld"
	want := "hello\n---******* ******* ********\n***\n******** ******* *****---\nworld"

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := runSanitizeWithIO(nil, strings.NewReader(input), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}
	if stdout.String() != want {
		t.Fatalf("unexpected stdout: got %q want %q", stdout.String(), want)
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected empty stderr, got %q", stderr.String())
	}
}

func TestRunSanitizeWithIODiff(t *testing.T) {
	input := "hello\n-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----\nworld"

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := runSanitizeWithIO([]string{"--diff"}, strings.NewReader(input), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}

	if !strings.Contains(stderr.String(), "findings=1") {
		t.Fatalf("expected findings summary in stderr, got %q", stderr.String())
	}
	if !strings.Contains(stderr.String(), "risk=high") {
		t.Fatalf("expected risk level in stderr, got %q", stderr.String())
	}
	if !strings.Contains(stderr.String(), "score=15") {
		t.Fatalf("expected score in stderr, got %q", stderr.String())
	}
	if !strings.Contains(stderr.String(), "detectors: pem_private_key") {
		t.Fatalf("expected detectors line in stderr, got %q", stderr.String())
	}
	if !strings.Contains(stderr.String(), "before(redacted):") {
		t.Fatalf("expected before block in stderr, got %q", stderr.String())
	}
	if !strings.Contains(stderr.String(), "after(redacted):") {
		t.Fatalf("expected after block in stderr, got %q", stderr.String())
	}
	if !strings.Contains(stderr.String(), "input_hash=") {
		t.Fatalf("expected input hash in stderr, got %q", stderr.String())
	}
	if !strings.Contains(stdout.String(), "---******* ******* ********") {
		t.Fatalf("expected redaction in stdout, got %q", stdout.String())
	}
}

func TestRunSanitizeWithIORejectsPositionalArgs(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := runSanitizeWithIO([]string{"unexpected"}, strings.NewReader("hello"), &stdout, &stderr)
	if code != 2 {
		t.Fatalf("expected exit code 2, got %d", code)
	}
	if !strings.Contains(stderr.String(), "sanitize does not accept positional arguments") {
		t.Fatalf("expected argument error, got %q", stderr.String())
	}
}

func TestRunOnceWithServicePrintsDecision(t *testing.T) {
	clip := &testClipboard{value: "hello\n-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----\nworld"}
	svc := app.New(config.Defaults(), clip)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := runOnceWithService(svc, &stdout, &stderr, false)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected empty stderr, got %q", stderr.String())
	}
	if !strings.Contains(stdout.String(), `action=block`) {
		t.Fatalf("expected block action in output, got %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), `risk=high`) {
		t.Fatalf("expected high risk in output, got %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), `score=15`) {
		t.Fatalf("expected score 15 in output, got %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), `findings=1`) {
		t.Fatalf("expected one finding in output, got %q", stdout.String())
	}
}

func TestRunOnceWithServiceVerbosePrintsReasoning(t *testing.T) {
	clip := &testClipboard{value: "hello"}
	svc := app.New(config.Defaults(), clip)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := runOnceWithService(svc, &stdout, &stderr, true)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}
	if !strings.Contains(stderr.String(), "reason=") {
		t.Fatalf("expected verbose reasoning in stderr, got %q", stderr.String())
	}
}

func TestRunOnceWithServiceForegroundAppFailureIsVisible(t *testing.T) {
	clip := &testClipboard{value: "hello\n-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----\nworld"}
	foreground := &testForegroundApp{err: errors.New("osascript active app failed: accessibility denied")}
	svc := app.NewWithDependencies(config.Defaults(), clip, foreground, nil)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := runOnceWithService(svc, &stdout, &stderr, true)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}
	if !strings.Contains(stdout.String(), "policy_source=global_fallback_app_detection_failed") {
		t.Fatalf("expected global fallback policy source in stdout, got %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), "app_context_status=resolution_failed") {
		t.Fatalf("expected app context failure status in stdout, got %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), "global policy was used because app context could not be resolved; per-app overrides were skipped") {
		t.Fatalf("expected explicit fallback reasoning in stderr, got %q", stderr.String())
	}
}

func TestRunSnoozeWithIOPersistsState(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "state.json")
	now := time.Unix(1_700_000_000, 0).UTC()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := runSnoozeWithIO([]string{"5m"}, &stdout, &stderr, func() time.Time { return now }, statePath)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d, stderr=%q", code, stderr.String())
	}

	store, err := userstate.New(statePath)
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	state, err := store.Load()
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	want := now.Add(5 * time.Minute)
	if !state.SnoozedUntil.Equal(want) {
		t.Fatalf("unexpected snoozed_until: got %s want %s", state.SnoozedUntil, want)
	}
}

func TestRunAllowOnceWithIOPersistsState(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "state.json")

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := runAllowOnceWithIO(nil, &stdout, &stderr, statePath)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d, stderr=%q", code, stderr.String())
	}

	store, err := userstate.New(statePath)
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	state, err := store.Load()
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if !state.AllowOnce {
		t.Fatal("expected allow_once to be true")
	}
}

func TestRunLogWithIOTailsEntries(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "audit.jsonl")
	store, err := auditlog.New(logPath)
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}

	base := time.Unix(1_700_000_000, 0).UTC()
	for i := 0; i < 3; i++ {
		if err := store.Log(auditlog.Entry{
			Timestamp:    base.Add(time.Duration(i) * time.Second),
			App:          "Terminal",
			Score:        i + 1,
			RiskLevel:    "med",
			FindingTypes: []string{"jwt"},
			Action:       "sanitize",
			ContentHash:  "abc123",
		}); err != nil {
			t.Fatalf("Log returned error: %v", err)
		}
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := runLogWithIO([]string{"--tail", "2"}, &stdout, &stderr, logPath)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (stderr=%q)", code, stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected empty stderr, got %q", stderr.String())
	}

	lines := strings.Split(strings.TrimSpace(stdout.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines, got %d (%q)", len(lines), stdout.String())
	}
	if !strings.Contains(lines[0], `"score":2`) {
		t.Fatalf("expected first tailed score to be 2, got %q", lines[0])
	}
	if !strings.Contains(lines[1], `"score":3`) {
		t.Fatalf("expected second tailed score to be 3, got %q", lines[1])
	}
}

func TestRunLogWithIORejectsInvalidTail(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := runLogWithIO([]string{"--tail", "0"}, &stdout, &stderr, filepath.Join(t.TempDir(), "audit.jsonl"))
	if code != 2 {
		t.Fatalf("expected exit code 2, got %d", code)
	}
	if !strings.Contains(stderr.String(), "--tail must be > 0") {
		t.Fatalf("expected invalid tail message, got %q", stderr.String())
	}
}

func TestRunConfigInitWithIOWritesDefaultConfig(t *testing.T) {
	defaultPath := filepath.Join(t.TempDir(), "guardmycopy", "config.yaml")

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := runConfigInitWithIO(nil, &stdout, &stderr, defaultPath)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (stderr=%q)", code, stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected empty stderr, got %q", stderr.String())
	}
	if !strings.Contains(stdout.String(), defaultPath) {
		t.Fatalf("expected output to include written path, got %q", stdout.String())
	}

	data, err := os.ReadFile(defaultPath)
	if err != nil {
		t.Fatalf("read default config: %v", err)
	}
	if string(data) != config.DefaultTemplate() {
		t.Fatal("written config did not match default template")
	}
}

func TestRunConfigInitWithIORejectsPositionalArgs(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := runConfigInitWithIO([]string{"extra"}, &stdout, &stderr, filepath.Join(t.TempDir(), "config.yaml"))
	if code != 2 {
		t.Fatalf("expected exit code 2, got %d", code)
	}
	if !strings.Contains(stderr.String(), "does not accept positional arguments") {
		t.Fatalf("expected positional argument error, got %q", stderr.String())
	}
}

func TestRunConfigInitWithIOExistingFileRequiresForce(t *testing.T) {
	defaultPath := filepath.Join(t.TempDir(), "guardmycopy", "config.yaml")
	if _, err := config.WriteDefault(defaultPath, false); err != nil {
		t.Fatalf("WriteDefault returned error: %v", err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := runConfigInitWithIO(nil, &stdout, &stderr, defaultPath)
	if code != 1 {
		t.Fatalf("expected exit code 1, got %d", code)
	}
	if !strings.Contains(stderr.String(), "already exists") {
		t.Fatalf("expected already exists message, got %q", stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	code = runConfigInitWithIO([]string{"--force"}, &stdout, &stderr, defaultPath)
	if code != 0 {
		t.Fatalf("expected exit code 0 with --force, got %d (stderr=%q)", code, stderr.String())
	}
}

func TestRunHelpConfigInit(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := runHelp([]string{"config", "init"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected empty stderr, got %q", stderr.String())
	}
	if !strings.Contains(stdout.String(), "guardmycopy config init") {
		t.Fatalf("expected config init usage in stdout, got %q", stdout.String())
	}
}
