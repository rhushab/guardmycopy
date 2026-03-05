package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rhushab/guardmycopy/internal/userstate"
)

func writeLaunchAgentTemplate(t *testing.T) string {
	t.Helper()

	templatePath := filepath.Join(t.TempDir(), "guardmycopy.plist")
	template := strings.Join([]string{
		"<?xml version=\"1.0\" encoding=\"UTF-8\"?>",
		"<plist version=\"1.0\">",
		"<dict>",
		"<key>Program</key><string>__GUARDMYCOPY_BIN__</string>",
		"<key>StandardOutPath</key><string>__LOG_DIR__/guardmycopy.out.log</string>",
		"</dict>",
		"</plist>",
	}, "\n")
	if err := os.WriteFile(templatePath, []byte(template), 0o644); err != nil {
		t.Fatalf("write template: %v", err)
	}
	return templatePath
}

func writeLegacyLaunchAgentTemplate(t *testing.T) string {
	t.Helper()

	templatePath := filepath.Join(t.TempDir(), "guardmycopy-legacy.plist")
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
		t.Fatalf("write legacy template: %v", err)
	}
	return templatePath
}

func installedLaunchAgentPlistPath(home string) string {
	return filepath.Join(home, "Library", "LaunchAgents", launchAgentLabel+".plist")
}

func readInstalledLaunchAgentPlist(t *testing.T, home string) string {
	t.Helper()

	plistBytes, err := os.ReadFile(installedLaunchAgentPlistPath(home))
	if err != nil {
		t.Fatalf("read installed plist: %v", err)
	}
	return string(plistBytes)
}

func launchctlServiceNotFoundError() (string, error) {
	return "Could not find service \"com.guardmycopy.agent\" in domain", errors.New("exit status 113")
}

func TestRunInstallWithIOWritesPlistAndBootstraps(t *testing.T) {
	home := t.TempDir()
	templatePath := writeLaunchAgentTemplate(t)

	var launchctlCalls [][]string
	deps := launchAgentDeps{
		runtimeOS:    "darwin",
		templatePath: templatePath,
		executable: func() (string, error) {
			return "/tmp/bin/guardmycopy", nil
		},
		homeDir: func() (string, error) {
			return home, nil
		},
		uid: func() int {
			return 501
		},
		runLaunchctl: func(args ...string) (string, error) {
			launchctlCalls = append(launchctlCalls, append([]string(nil), args...))
			switch args[0] {
			case "bootout":
				return launchctlServiceNotFoundError()
			case "bootstrap":
				return "", nil
			default:
				t.Fatalf("unexpected launchctl args: %q", args)
				return "", nil
			}
		},
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := runInstallWithIO(nil, &stdout, &stderr, deps)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (stderr=%q)", code, stderr.String())
	}

	plistPath := installedLaunchAgentPlistPath(home)
	plist := readInstalledLaunchAgentPlist(t, home)
	if strings.Contains(plist, "__GUARDMYCOPY_BIN__") || strings.Contains(plist, "__WORKDIR__") || strings.Contains(plist, "__LOG_DIR__") {
		t.Fatalf("expected placeholders to be replaced, got %q", plist)
	}
	if !strings.Contains(plist, "/tmp/bin/guardmycopy") {
		t.Fatalf("expected binary path in plist, got %q", plist)
	}
	if strings.Contains(plist, "WorkingDirectory") {
		t.Fatalf("expected plist to omit working directory, got %q", plist)
	}
	logDir := filepath.Join(home, "Library", "Logs", "guardmycopy")
	if _, err := os.Stat(logDir); err != nil {
		t.Fatalf("expected log directory to be created: %v", err)
	}

	if len(launchctlCalls) != 2 {
		t.Fatalf("expected two launchctl calls, got %d", len(launchctlCalls))
	}
	expected := [][]string{
		{"bootout", launchAgentTarget(501)},
		{"bootstrap", launchAgentDomain(501), plistPath},
	}
	for i := range expected {
		if got := strings.Join(launchctlCalls[i], " "); strings.Join(expected[i], " ") != got {
			t.Fatalf("unexpected launchctl args at call %d: got %q want %q", i, got, strings.Join(expected[i], " "))
		}
	}
}

func TestRunInstallWithIOUsesEmbeddedTemplateWhenTemplatePathUnset(t *testing.T) {
	home := t.TempDir()

	var launchctlCalls [][]string
	deps := launchAgentDeps{
		runtimeOS: "darwin",
		executable: func() (string, error) {
			return "/tmp/bin/guardmycopy", nil
		},
		homeDir: func() (string, error) {
			return home, nil
		},
		uid: func() int {
			return 501
		},
		readFile: func(path string) ([]byte, error) {
			if path == installedLaunchAgentPlistPath(home) {
				return nil, os.ErrNotExist
			}
			t.Fatalf("unexpected readFile call when templatePath is unset (path=%q)", path)
			return nil, os.ErrNotExist
		},
		runLaunchctl: func(args ...string) (string, error) {
			launchctlCalls = append(launchctlCalls, append([]string(nil), args...))
			switch args[0] {
			case "bootout":
				return launchctlServiceNotFoundError()
			case "bootstrap":
				return "", nil
			default:
				t.Fatalf("unexpected launchctl args: %q", args)
				return "", nil
			}
		},
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := runInstallWithIO(nil, &stdout, &stderr, deps)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (stderr=%q)", code, stderr.String())
	}

	plist := readInstalledLaunchAgentPlist(t, home)
	if !strings.Contains(plist, "/tmp/bin/guardmycopy") {
		t.Fatalf("expected binary path in plist, got %q", plist)
	}
	if strings.Contains(plist, "<string>--interval</string>") {
		t.Fatalf("expected embedded template to honor config poll interval, got %q", plist)
	}
	if strings.Contains(plist, "WorkingDirectory") {
		t.Fatalf("expected embedded template to omit working directory, got %q", plist)
	}
	if len(launchctlCalls) != 2 {
		t.Fatalf("expected two launchctl calls, got %d", len(launchctlCalls))
	}
}

func TestShippedLaunchAgentTemplatesDoNotHardcodeInterval(t *testing.T) {
	paths := []string{
		"guardmycopy.plist",
		filepath.Join("..", "..", "scripts", "macos", "guardmycopy.plist"),
	}

	for _, path := range paths {
		templateBytes, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read template %q: %v", path, err)
		}

		template := string(templateBytes)
		if strings.Contains(template, "<string>--interval</string>") {
			t.Fatalf("expected template %q to rely on config poll interval, got %q", path, template)
		}
	}
}

func TestRunInstallWithIOLegacyWorkingDirectoryPlaceholderUsesHomeDir(t *testing.T) {
	home := filepath.Join(t.TempDir(), "stable&home<dir>")
	templatePath := writeLegacyLaunchAgentTemplate(t)

	deps := launchAgentDeps{
		runtimeOS:    "darwin",
		templatePath: templatePath,
		executable: func() (string, error) {
			return "/tmp/bin/guard&my<copy>", nil
		},
		homeDir: func() (string, error) {
			return home, nil
		},
		uid: func() int {
			return 501
		},
		runLaunchctl: func(args ...string) (string, error) {
			switch args[0] {
			case "bootout":
				return launchctlServiceNotFoundError()
			case "bootstrap":
				return "", nil
			default:
				t.Fatalf("unexpected launchctl args: %q", args)
				return "", nil
			}
		},
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := runInstallWithIO(nil, &stdout, &stderr, deps)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (stderr=%q)", code, stderr.String())
	}

	plist := readInstalledLaunchAgentPlist(t, home)
	if !strings.Contains(plist, "/tmp/bin/guard&amp;my&lt;copy&gt;") {
		t.Fatalf("expected XML-escaped binary path in plist, got %q", plist)
	}
	if !strings.Contains(plist, "WorkingDirectory") {
		t.Fatalf("expected legacy template working directory to be preserved, got %q", plist)
	}
	if !strings.Contains(plist, "stable&amp;home&lt;dir&gt;") {
		t.Fatalf("expected legacy workdir placeholder to use XML-escaped home dir, got %q", plist)
	}
	if strings.Contains(plist, "work&amp;dir") {
		t.Fatalf("expected install to avoid caller cwd, got %q", plist)
	}
}

func TestRunInstallWithIOReinstallsLoadedService(t *testing.T) {
	home := t.TempDir()
	templatePath := writeLaunchAgentTemplate(t)
	plistPath := installedLaunchAgentPlistPath(home)
	if err := os.MkdirAll(filepath.Dir(plistPath), 0o755); err != nil {
		t.Fatalf("mkdir plist dir: %v", err)
	}
	if err := os.WriteFile(plistPath, []byte("old plist"), 0o644); err != nil {
		t.Fatalf("write existing plist: %v", err)
	}

	var launchctlCalls [][]string
	deps := launchAgentDeps{
		runtimeOS:    "darwin",
		templatePath: templatePath,
		executable: func() (string, error) {
			return "/tmp/bin/guardmycopy-new", nil
		},
		homeDir: func() (string, error) {
			return home, nil
		},
		uid: func() int {
			return 501
		},
		runLaunchctl: func(args ...string) (string, error) {
			launchctlCalls = append(launchctlCalls, append([]string(nil), args...))
			switch args[0] {
			case "bootout", "bootstrap":
				return "", nil
			default:
				t.Fatalf("unexpected launchctl args: %q", args)
				return "", nil
			}
		},
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := runInstallWithIO(nil, &stdout, &stderr, deps)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (stderr=%q)", code, stderr.String())
	}

	plist := readInstalledLaunchAgentPlist(t, home)
	if !strings.Contains(plist, "/tmp/bin/guardmycopy-new") {
		t.Fatalf("expected updated binary path in plist, got %q", plist)
	}
	if strings.Contains(plist, "WorkingDirectory") {
		t.Fatalf("expected reinstalled plist to omit working directory, got %q", plist)
	}
	if len(launchctlCalls) != 2 {
		t.Fatalf("expected two launchctl calls, got %d", len(launchctlCalls))
	}
	expected := [][]string{
		{"bootout", launchAgentTarget(501)},
		{"bootstrap", launchAgentDomain(501), plistPath},
	}
	for i := range expected {
		if got := strings.Join(launchctlCalls[i], " "); strings.Join(expected[i], " ") != got {
			t.Fatalf("unexpected launchctl args at call %d: got %q want %q", i, got, strings.Join(expected[i], " "))
		}
	}
}

func TestRunInstallWithIORollsBackPlistWhenReloadFails(t *testing.T) {
	home := t.TempDir()
	templatePath := writeLaunchAgentTemplate(t)
	plistPath := installedLaunchAgentPlistPath(home)
	if err := os.MkdirAll(filepath.Dir(plistPath), 0o755); err != nil {
		t.Fatalf("mkdir plist dir: %v", err)
	}
	originalPlist := "original plist"
	if err := os.WriteFile(plistPath, []byte(originalPlist), 0o644); err != nil {
		t.Fatalf("write existing plist: %v", err)
	}

	var launchctlCalls [][]string
	bootstrapCalls := 0
	deps := launchAgentDeps{
		runtimeOS:    "darwin",
		templatePath: templatePath,
		executable: func() (string, error) {
			return "/tmp/bin/guardmycopy-new", nil
		},
		homeDir: func() (string, error) {
			return home, nil
		},
		uid: func() int {
			return 501
		},
		runLaunchctl: func(args ...string) (string, error) {
			launchctlCalls = append(launchctlCalls, append([]string(nil), args...))
			switch args[0] {
			case "bootout":
				return "", nil
			case "bootstrap":
				bootstrapCalls++
				if bootstrapCalls == 1 {
					return "bootstrap failed", errors.New("exit status 5")
				}
				return "", nil
			default:
				t.Fatalf("unexpected launchctl args: %q", args)
				return "", nil
			}
		},
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := runInstallWithIO(nil, &stdout, &stderr, deps)
	if code != 1 {
		t.Fatalf("expected exit code 1, got %d (stderr=%q)", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "launchctl bootstrap gui/501 failed: bootstrap failed") {
		t.Fatalf("expected bootstrap failure in stderr, got %q", stderr.String())
	}
	if got := readInstalledLaunchAgentPlist(t, home); got != originalPlist {
		t.Fatalf("expected plist rollback to preserve original content, got %q", got)
	}
	if len(launchctlCalls) != 3 {
		t.Fatalf("expected three launchctl calls, got %d", len(launchctlCalls))
	}
	expected := [][]string{
		{"bootout", launchAgentTarget(501)},
		{"bootstrap", launchAgentDomain(501), plistPath},
		{"bootstrap", launchAgentDomain(501), plistPath},
	}
	for i := range expected {
		if got := strings.Join(launchctlCalls[i], " "); strings.Join(expected[i], " ") != got {
			t.Fatalf("unexpected launchctl args at call %d: got %q want %q", i, got, strings.Join(expected[i], " "))
		}
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
	expected := []string{"bootout", launchAgentTarget(777)}
	if got := strings.Join(launchctlCalls[0], " "); strings.Join(expected, " ") != got {
		t.Fatalf("unexpected launchctl args: got %q want %q", got, strings.Join(expected, " "))
	}
}

func TestRunUninstallWithIOMissingPlistStillBootsOutService(t *testing.T) {
	home := t.TempDir()
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
	if len(launchctlCalls) != 1 {
		t.Fatalf("expected one launchctl call, got %d", len(launchctlCalls))
	}
	expected := []string{"bootout", launchAgentTarget(777)}
	if got := strings.Join(launchctlCalls[0], " "); strings.Join(expected, " ") != got {
		t.Fatalf("unexpected launchctl args: got %q want %q", got, strings.Join(expected, " "))
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
		timeNow: func() time.Time {
			return snoozedUntil.Add(-time.Minute)
		},
		uid: func() int {
			return 501
		},
		runLaunchctl: func(args ...string) (string, error) {
			launchctlCalls = append(launchctlCalls, append([]string(nil), args...))
			return "state = running\npid = 123", nil
		},
		activeApp: func() (string, string, error) {
			return "Google Chrome", "com.google.Chrome", nil
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
	if !strings.Contains(stdout.String(), "foreground-app-context=resolved") {
		t.Fatalf("expected resolved foreground app context, got %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), `foreground-app="Google Chrome"`) {
		t.Fatalf("expected foreground app name, got %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), `foreground-app-bundle-id="com.google.Chrome"`) {
		t.Fatalf("expected foreground bundle id, got %q", stdout.String())
	}
}

func TestRunStatusWithIOIgnoresExpiredSnooze(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "state.json")
	store, err := userstate.New(statePath)
	if err != nil {
		t.Fatalf("new userstate store: %v", err)
	}
	now := time.Unix(1_700_000_000, 0).UTC()
	if err := store.Save(userstate.State{
		SnoozedUntil: now.Add(-time.Minute),
		AllowOnce:    true,
	}); err != nil {
		t.Fatalf("save userstate: %v", err)
	}

	deps := launchAgentDeps{
		runtimeOS: "darwin",
		timeNow: func() time.Time {
			return now
		},
		runLaunchctl: func(args ...string) (string, error) {
			return "state = running\npid = 123", nil
		},
		activeApp: func() (string, string, error) {
			return "Google Chrome", "com.google.Chrome", nil
		},
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := runStatusWithIO(nil, &stdout, &stderr, deps, statePath)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (stderr=%q)", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "snoozed-until=none") {
		t.Fatalf("expected expired snooze to report as none, got %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), "allow-once=true") {
		t.Fatalf("expected allow-once=true to remain visible, got %q", stdout.String())
	}
}

func TestRunStatusWithIOMissingService(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "state.json")
	deps := launchAgentDeps{
		runtimeOS: "darwin",
		runLaunchctl: func(args ...string) (string, error) {
			return "Could not find service \"com.guardmycopy.agent\" in domain", errors.New("exit status 113")
		},
		activeApp: func() (string, string, error) {
			return "", "", nil
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
	if !strings.Contains(stdout.String(), "foreground-app-context=unavailable") {
		t.Fatalf("expected unavailable foreground app context, got %q", stdout.String())
	}
}

func TestRunStatusWithIOReportsForegroundAppFailure(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "state.json")
	deps := launchAgentDeps{
		runtimeOS: "darwin",
		runLaunchctl: func(args ...string) (string, error) {
			return "state = running\npid = 123", nil
		},
		activeApp: func() (string, string, error) {
			return "", "", errors.New("osascript active app failed: accessibility denied")
		},
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := runStatusWithIO(nil, &stdout, &stderr, deps, statePath)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (stderr=%q)", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "foreground-app-context=resolution_failed") {
		t.Fatalf("expected failed foreground app context, got %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), `foreground-app-error="osascript active app failed: accessibility denied"`) {
		t.Fatalf("expected foreground app error, got %q", stdout.String())
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

func TestRunStatusWithIOReportsHealthyEnforcement(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "state.json")
	store, err := userstate.New(statePath)
	if err != nil {
		t.Fatalf("new userstate store: %v", err)
	}
	if err := store.Save(userstate.State{}); err != nil {
		t.Fatalf("save userstate: %v", err)
	}

	deps := launchAgentDeps{
		runtimeOS: "darwin",
		runLaunchctl: func(args ...string) (string, error) {
			return "state = running\npid = 123", nil
		},
		activeApp: func() (string, string, error) {
			return "Google Chrome", "com.google.Chrome", nil
		},
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := runStatusWithIO(nil, &stdout, &stderr, deps, statePath)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (stderr=%q)", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "enforcement-status=healthy") {
		t.Fatalf("expected enforcement-status=healthy, got %q", stdout.String())
	}
}

func TestRunStatusWithIOReportsDegradedEnforcement(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "state.json")
	store, err := userstate.New(statePath)
	if err != nil {
		t.Fatalf("new userstate store: %v", err)
	}
	errorTime := time.Unix(1_700_000_000, 0).UTC()
	if err := store.Save(userstate.State{
		LastEnforcementError:   "write clipboard: pasteboard temporarily unavailable",
		LastEnforcementErrorAt: errorTime,
		ConsecutiveErrors:      3,
	}); err != nil {
		t.Fatalf("save userstate: %v", err)
	}

	deps := launchAgentDeps{
		runtimeOS: "darwin",
		runLaunchctl: func(args ...string) (string, error) {
			return "state = running\npid = 123", nil
		},
		activeApp: func() (string, string, error) {
			return "Google Chrome", "com.google.Chrome", nil
		},
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := runStatusWithIO(nil, &stdout, &stderr, deps, statePath)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (stderr=%q)", code, stderr.String())
	}
	out := stdout.String()
	if !strings.Contains(out, "enforcement-status=degraded") {
		t.Fatalf("expected enforcement-status=degraded, got %q", out)
	}
	if !strings.Contains(out, `last-enforcement-error="write clipboard: pasteboard temporarily unavailable"`) {
		t.Fatalf("expected last-enforcement-error, got %q", out)
	}
	if !strings.Contains(out, "last-enforcement-error-at="+errorTime.Format(time.RFC3339)) {
		t.Fatalf("expected last-enforcement-error-at, got %q", out)
	}
	if !strings.Contains(out, "consecutive-enforcement-errors=3") {
		t.Fatalf("expected consecutive-enforcement-errors=3, got %q", out)
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
