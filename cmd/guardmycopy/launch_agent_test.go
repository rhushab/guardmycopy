package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rhushabhbontapalle/guardmycopy/internal/userstate"
)

func TestRunInstallWithIOWritesPlistAndBootstraps(t *testing.T) {
	home := t.TempDir()
	templatePath := filepath.Join(t.TempDir(), "guardmycopy.plist")
	template := strings.Join([]string{
		"<?xml version=\"1.0\" encoding=\"UTF-8\"?>",
		"<plist version=\"1.0\">",
		"<dict>",
		"<key>Program</key><string>__GUARDMYCOPY_BIN__</string>",
		"<key>WorkingDirectory</key><string>__WORKDIR__</string>",
		"<key>StandardOutPath</key><string>__LOG_DIR__/guardmycopy.out.log</string>",
		"</dict>",
		"</plist>",
	}, "\n")
	if err := os.WriteFile(templatePath, []byte(template), 0o644); err != nil {
		t.Fatalf("write template: %v", err)
	}

	var launchctlCalls [][]string
	deps := launchAgentDeps{
		runtimeOS:    "darwin",
		templatePath: templatePath,
		executable: func() (string, error) {
			return "/tmp/bin/guardmycopy", nil
		},
		cwd: func() (string, error) {
			return "/tmp/workdir", nil
		},
		homeDir: func() (string, error) {
			return home, nil
		},
		uid: func() int {
			return 501
		},
		runLaunchctl: func(args ...string) (string, error) {
			launchctlCalls = append(launchctlCalls, append([]string(nil), args...))
			return "", nil
		},
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := runInstallWithIO(nil, &stdout, &stderr, deps)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (stderr=%q)", code, stderr.String())
	}

	plistPath := filepath.Join(home, "Library", "LaunchAgents", launchAgentLabel+".plist")
	plistBytes, err := os.ReadFile(plistPath)
	if err != nil {
		t.Fatalf("read installed plist: %v", err)
	}
	plist := string(plistBytes)
	if strings.Contains(plist, "__GUARDMYCOPY_BIN__") || strings.Contains(plist, "__WORKDIR__") || strings.Contains(plist, "__LOG_DIR__") {
		t.Fatalf("expected placeholders to be replaced, got %q", plist)
	}
	if !strings.Contains(plist, "/tmp/bin/guardmycopy") {
		t.Fatalf("expected binary path in plist, got %q", plist)
	}
	if !strings.Contains(plist, "/tmp/workdir") {
		t.Fatalf("expected workdir in plist, got %q", plist)
	}
	logDir := filepath.Join(home, "Library", "Logs", "guardmycopy")
	if _, err := os.Stat(logDir); err != nil {
		t.Fatalf("expected log directory to be created: %v", err)
	}

	if len(launchctlCalls) != 1 {
		t.Fatalf("expected one launchctl call, got %d", len(launchctlCalls))
	}
	expected := []string{"bootstrap", "gui/501", plistPath}
	if got := strings.Join(launchctlCalls[0], " "); strings.Join(expected, " ") != got {
		t.Fatalf("unexpected launchctl args: got %q want %q", got, strings.Join(expected, " "))
	}
}

func TestRunInstallWithIOEscapesXMLSpecialCharacters(t *testing.T) {
	home := t.TempDir()
	templatePath := filepath.Join(t.TempDir(), "guardmycopy.plist")
	template := strings.Join([]string{
		"<?xml version=\"1.0\" encoding=\"UTF-8\"?>",
		"<plist version=\"1.0\">",
		"<dict>",
		"<key>Program</key><string>__GUARDMYCOPY_BIN__</string>",
		"<key>WorkingDirectory</key><string>__WORKDIR__</string>",
		"<key>StandardOutPath</key><string>__LOG_DIR__/guardmycopy.out.log</string>",
		"</dict>",
		"</plist>",
	}, "\n")
	if err := os.WriteFile(templatePath, []byte(template), 0o644); err != nil {
		t.Fatalf("write template: %v", err)
	}

	deps := launchAgentDeps{
		runtimeOS:    "darwin",
		templatePath: templatePath,
		executable: func() (string, error) {
			return "/tmp/bin/guard&my<copy>", nil
		},
		cwd: func() (string, error) {
			return "/tmp/work&dir<prod>", nil
		},
		homeDir: func() (string, error) {
			return home, nil
		},
		uid: func() int {
			return 501
		},
		runLaunchctl: func(args ...string) (string, error) {
			return "", nil
		},
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := runInstallWithIO(nil, &stdout, &stderr, deps)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (stderr=%q)", code, stderr.String())
	}

	plistPath := filepath.Join(home, "Library", "LaunchAgents", launchAgentLabel+".plist")
	plistBytes, err := os.ReadFile(plistPath)
	if err != nil {
		t.Fatalf("read installed plist: %v", err)
	}
	plist := string(plistBytes)
	if !strings.Contains(plist, "/tmp/bin/guard&amp;my&lt;copy&gt;") {
		t.Fatalf("expected XML-escaped binary path in plist, got %q", plist)
	}
	if !strings.Contains(plist, "/tmp/work&amp;dir&lt;prod&gt;") {
		t.Fatalf("expected XML-escaped workdir in plist, got %q", plist)
	}
}

func TestRunInstallWithIONonDarwin(t *testing.T) {
	deps := launchAgentDeps{
		runtimeOS: "linux",
		runLaunchctl: func(args ...string) (string, error) {
			t.Fatal("launchctl should not be called on non-darwin")
			return "", nil
		},
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := runInstallWithIO(nil, &stdout, &stderr, deps)
	if code != 1 {
		t.Fatalf("expected exit code 1, got %d", code)
	}
	if !strings.Contains(stderr.String(), "only supported on macOS") {
		t.Fatalf("expected non-darwin error, got %q", stderr.String())
	}
}

func TestRunUninstallWithIORunsBootoutAndRemovesPlist(t *testing.T) {
	home := t.TempDir()
	plistPath := filepath.Join(home, "Library", "LaunchAgents", launchAgentLabel+".plist")
	if err := os.MkdirAll(filepath.Dir(plistPath), 0o755); err != nil {
		t.Fatalf("mkdir plist dir: %v", err)
	}
	if err := os.WriteFile(plistPath, []byte("plist"), 0o644); err != nil {
		t.Fatalf("write plist: %v", err)
	}

	var launchctlCalls [][]string
	deps := launchAgentDeps{
		runtimeOS: "darwin",
		homeDir: func() (string, error) {
			return home, nil
		},
		uid: func() int {
			return 777
		},
		runLaunchctl: func(args ...string) (string, error) {
			launchctlCalls = append(launchctlCalls, append([]string(nil), args...))
			return "", nil
		},
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := runUninstallWithIO(nil, &stdout, &stderr, deps)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (stderr=%q)", code, stderr.String())
	}
	if _, err := os.Stat(plistPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected plist to be removed, got err=%v", err)
	}
	if len(launchctlCalls) != 1 {
		t.Fatalf("expected one launchctl call, got %d", len(launchctlCalls))
	}
	expected := []string{"bootout", "gui/777", plistPath}
	if got := strings.Join(launchctlCalls[0], " "); strings.Join(expected, " ") != got {
		t.Fatalf("unexpected launchctl args: got %q want %q", got, strings.Join(expected, " "))
	}
}

func TestRunUninstallWithIOMissingPlistSkipsBootout(t *testing.T) {
	home := t.TempDir()
	deps := launchAgentDeps{
		runtimeOS: "darwin",
		homeDir: func() (string, error) {
			return home, nil
		},
		runLaunchctl: func(args ...string) (string, error) {
			t.Fatal("launchctl should not be called when plist is missing")
			return "", nil
		},
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := runUninstallWithIO(nil, &stdout, &stderr, deps)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (stderr=%q)", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "not found") {
		t.Fatalf("expected not found message, got %q", stdout.String())
	}
}

func TestRunStatusWithIOReportsLoadedRunningAndBypass(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "state.json")
	store, err := userstate.New(statePath)
	if err != nil {
		t.Fatalf("new userstate store: %v", err)
	}
	snoozedUntil := time.Unix(1_700_000_000, 0).UTC()
	if err := store.Save(userstate.State{SnoozedUntil: snoozedUntil, AllowOnce: true}); err != nil {
		t.Fatalf("save userstate: %v", err)
	}

	var launchctlCalls [][]string
	deps := launchAgentDeps{
		runtimeOS: "darwin",
		uid: func() int {
			return 501
		},
		runLaunchctl: func(args ...string) (string, error) {
			launchctlCalls = append(launchctlCalls, append([]string(nil), args...))
			return "state = running\npid = 123", nil
		},
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := runStatusWithIO(nil, &stdout, &stderr, deps, statePath)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (stderr=%q)", code, stderr.String())
	}
	if len(launchctlCalls) != 1 {
		t.Fatalf("expected one launchctl call, got %d", len(launchctlCalls))
	}
	if !strings.Contains(stdout.String(), "launch-agent-loaded=true") {
		t.Fatalf("expected loaded=true, got %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), "launch-agent-running=true") {
		t.Fatalf("expected running=true, got %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), "snoozed-until="+snoozedUntil.Format(time.RFC3339)) {
		t.Fatalf("expected snoozed-until in output, got %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), "allow-once=true") {
		t.Fatalf("expected allow-once=true, got %q", stdout.String())
	}
}

func TestRunStatusWithIOMissingService(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "state.json")
	deps := launchAgentDeps{
		runtimeOS: "darwin",
		runLaunchctl: func(args ...string) (string, error) {
			return "Could not find service \"com.guardmycopy.agent\" in domain", errors.New("exit status 113")
		},
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := runStatusWithIO(nil, &stdout, &stderr, deps, statePath)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (stderr=%q)", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "launch-agent-loaded=false") {
		t.Fatalf("expected loaded=false, got %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), "launch-agent-running=false") {
		t.Fatalf("expected running=false, got %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), "snoozed-until=none") {
		t.Fatalf("expected snoozed-until=none, got %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), "allow-once=false") {
		t.Fatalf("expected allow-once=false, got %q", stdout.String())
	}
}

func TestRunStatusWithIONonDarwin(t *testing.T) {
	deps := launchAgentDeps{
		runtimeOS: "linux",
		runLaunchctl: func(args ...string) (string, error) {
			t.Fatal("launchctl should not be called on non-darwin")
			return "", nil
		},
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := runStatusWithIO(nil, &stdout, &stderr, deps, filepath.Join(t.TempDir(), "state.json"))
	if code != 1 {
		t.Fatalf("expected exit code 1, got %d", code)
	}
	if !strings.Contains(stderr.String(), "only supported on macOS") {
		t.Fatalf("expected non-darwin error, got %q", stderr.String())
	}
}

func TestLaunchAgentRunning(t *testing.T) {
	tests := []struct {
		name   string
		output string
		want   bool
	}{
		{
			name:   "running",
			output: "pid = 123\nstate = running",
			want:   true,
		},
		{
			name:   "not running is false",
			output: "state = not running",
			want:   false,
		},
		{
			name:   "running with suffix",
			output: "state = running (throttled)",
			want:   true,
		},
		{
			name:   "missing state",
			output: "pid = 123",
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := launchAgentRunning(tt.output); got != tt.want {
				t.Fatalf("launchAgentRunning() = %t, want %t", got, tt.want)
			}
		})
	}
}

func TestRunHelpInstallUsage(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := runHelp([]string{"install"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}
	if !strings.Contains(stdout.String(), "guardmycopy install") {
		t.Fatalf("expected install usage in stdout, got %q", stdout.String())
	}
}
