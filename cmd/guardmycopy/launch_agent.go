package main

import (
	_ "embed"
	"encoding/xml"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/rhushab/guardmycopy/internal/app"
	"github.com/rhushab/guardmycopy/internal/platform"
	"github.com/rhushab/guardmycopy/internal/userstate"
)

const (
	launchAgentLabel = "com.guardmycopy.agent"
)

//go:embed guardmycopy.plist
var embeddedLaunchAgentTemplate []byte

type launchAgentDeps struct {
	runtimeOS    string
	templatePath string
	templateData []byte
	timeNow      func() time.Time
	executable   func() (string, error)
	homeDir      func() (string, error)
	uid          func() int
	readFile     func(string) ([]byte, error)
	writeFile    func(string, []byte, os.FileMode) error
	mkdirAll     func(string, os.FileMode) error
	stat         func(string) (os.FileInfo, error)
	rename       func(string, string) error
	remove       func(string) error
	runLaunchctl func(args ...string) (string, error)
	activeApp    func() (string, string, error)
}

func defaultLaunchAgentDeps() launchAgentDeps {
	return (launchAgentDeps{}).withDefaults()
}

func (d launchAgentDeps) withDefaults() launchAgentDeps {
	if strings.TrimSpace(d.runtimeOS) == "" {
		d.runtimeOS = runtime.GOOS
	}
	if len(d.templateData) == 0 {
		d.templateData = embeddedLaunchAgentTemplate
	}
	if d.timeNow == nil {
		d.timeNow = time.Now
	}
	if d.executable == nil {
		d.executable = os.Executable
	}
	if d.homeDir == nil {
		d.homeDir = os.UserHomeDir
	}
	if d.uid == nil {
		d.uid = os.Getuid
	}
	if d.readFile == nil {
		d.readFile = os.ReadFile
	}
	if d.writeFile == nil {
		d.writeFile = os.WriteFile
	}
	if d.mkdirAll == nil {
		d.mkdirAll = os.MkdirAll
	}
	if d.stat == nil {
		d.stat = os.Stat
	}
	if d.rename == nil {
		d.rename = os.Rename
	}
	if d.remove == nil {
		d.remove = os.Remove
	}
	if d.runLaunchctl == nil {
		d.runLaunchctl = runLaunchctlCommand
	}
	if d.activeApp == nil {
		d.activeApp = func() (string, string, error) {
			adapters, err := platform.Select()
			if err != nil {
				return "", "", err
			}
			if adapters.ForegroundApp == nil {
				return "", "", errors.New("foreground app adapter unavailable")
			}
			return adapters.ForegroundApp.ActiveApp()
		}
	}
	return d
}

func runLaunchctlCommand(args ...string) (string, error) {
	out, err := exec.Command("launchctl", args...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

func runInstall(args []string) int {
	return runInstallWithIO(args, os.Stdout, os.Stderr, defaultLaunchAgentDeps())
}

func runInstallWithIO(args []string, stdout, stderr io.Writer, deps launchAgentDeps) int {
	fs := flag.NewFlagSet("install", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { printInstallUsage(fs.Output()) }

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(stderr, "error: install does not accept positional arguments")
		printInstallUsage(stderr)
		return 2
	}

	deps = deps.withDefaults()
	if err := requireDarwinCommand("install", deps.runtimeOS); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}

	if err := installLaunchAgent(stdout, deps); err != nil {
		fmt.Fprintf(stderr, "install launch agent: %v\n", err)
		return 1
	}
	return 0
}

func runUninstall(args []string) int {
	return runUninstallWithIO(args, os.Stdout, os.Stderr, defaultLaunchAgentDeps())
}

func runUninstallWithIO(args []string, stdout, stderr io.Writer, deps launchAgentDeps) int {
	fs := flag.NewFlagSet("uninstall", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { printUninstallUsage(fs.Output()) }

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(stderr, "error: uninstall does not accept positional arguments")
		printUninstallUsage(stderr)
		return 2
	}

	deps = deps.withDefaults()
	if err := requireDarwinCommand("uninstall", deps.runtimeOS); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}

	if err := uninstallLaunchAgent(stdout, deps); err != nil {
		fmt.Fprintf(stderr, "uninstall launch agent: %v\n", err)
		return 1
	}
	return 0
}

func runStatus(args []string) int {
	return runStatusWithIO(args, os.Stdout, os.Stderr, defaultLaunchAgentDeps(), "")
}

func runStatusWithIO(args []string, stdout, stderr io.Writer, deps launchAgentDeps, statePath string) int {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { printStatusUsage(fs.Output()) }

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(stderr, "error: status does not accept positional arguments")
		printStatusUsage(stderr)
		return 2
	}

	deps = deps.withDefaults()
	if err := requireDarwinCommand("status", deps.runtimeOS); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}

	loaded, running, err := launchAgentStatus(deps)
	if err != nil {
		fmt.Fprintf(stderr, "query launch agent status: %v\n", err)
		return 1
	}

	store, err := userstate.New(statePath)
	if err != nil {
		fmt.Fprintf(stderr, "open runtime state: %v\n", err)
		return 1
	}
	state, err := store.Load()
	if err != nil {
		fmt.Fprintf(stderr, "load runtime state: %v\n", err)
		return 1
	}

	snoozedUntil := formatActiveSnoozedUntil(state, deps.timeNow())

	fmt.Fprintf(stdout, "launch-agent-loaded=%t\n", loaded)
	fmt.Fprintf(stdout, "launch-agent-running=%t\n", running)
	fmt.Fprintf(stdout, "snoozed-until=%s\n", snoozedUntil)
	fmt.Fprintf(stdout, "allow-once=%t\n", state.AllowOnce)

	foregroundStatus, appName, bundleID, appErr := detectForegroundAppHealth(deps.activeApp)
	fmt.Fprintf(stdout, "foreground-app-context=%s\n", foregroundStatus)
	if appName != "" {
		fmt.Fprintf(stdout, "foreground-app=%q\n", appName)
	}
	if bundleID != "" {
		fmt.Fprintf(stdout, "foreground-app-bundle-id=%q\n", bundleID)
	}
	if appErr != nil {
		fmt.Fprintf(stdout, "foreground-app-error=%q\n", appErr.Error())
	}
	return 0
}

func formatActiveSnoozedUntil(state userstate.State, now time.Time) string {
	snoozedUntil, ok := state.ActiveSnoozedUntil(now)
	if !ok {
		return "none"
	}
	return snoozedUntil.Format(time.RFC3339)
}

func installLaunchAgent(stdout io.Writer, deps launchAgentDeps) error {
	plistPath, err := deps.launchAgentPlistPath()
	if err != nil {
		return err
	}
	logDir, err := deps.launchAgentLogDir()
	if err != nil {
		return err
	}

	templateBytes, err := deps.loadLaunchAgentTemplate()
	if err != nil {
		return err
	}

	binPath, err := deps.executable()
	if err != nil {
		return fmt.Errorf("resolve executable path: %w", err)
	}
	binPath, err = filepath.Abs(binPath)
	if err != nil {
		return fmt.Errorf("make executable path absolute: %w", err)
	}
	xmlBinPath, err := escapeXMLText(binPath)
	if err != nil {
		return fmt.Errorf("escape executable path for plist: %w", err)
	}
	xmlLogDir, err := escapeXMLText(logDir)
	if err != nil {
		return fmt.Errorf("escape log directory for plist: %w", err)
	}

	if err := deps.mkdirAll(filepath.Dir(plistPath), 0o755); err != nil {
		return fmt.Errorf("create launch agents directory: %w", err)
	}
	if err := deps.mkdirAll(logDir, 0o755); err != nil {
		return fmt.Errorf("create log directory: %w", err)
	}

	replacements := []string{
		"__GUARDMYCOPY_BIN__", xmlBinPath,
		"__LOG_DIR__", xmlLogDir,
	}
	if strings.Contains(string(templateBytes), "__WORKDIR__") {
		stableWorkDir, err := deps.homeDir()
		if err != nil {
			return fmt.Errorf("resolve stable working directory: %w", err)
		}
		stableWorkDir = strings.TrimSpace(stableWorkDir)
		if stableWorkDir == "" {
			return errors.New("resolve stable working directory: empty path")
		}
		stableWorkDir, err = filepath.Abs(stableWorkDir)
		if err != nil {
			return fmt.Errorf("make stable working directory absolute: %w", err)
		}
		xmlWorkDir, err := escapeXMLText(stableWorkDir)
		if err != nil {
			return fmt.Errorf("escape stable working directory for plist: %w", err)
		}
		replacements = append(replacements, "__WORKDIR__", xmlWorkDir)
	}

	rendered := strings.NewReplacer(replacements...).Replace(string(templateBytes))

	if unresolved := unresolvedTemplatePlaceholders(rendered); len(unresolved) > 0 {
		return fmt.Errorf("plist template still contains placeholders: %s", strings.Join(unresolved, ", "))
	}

	previousPlist, previousExists, err := readLaunchAgentPlist(deps, plistPath)
	if err != nil {
		return err
	}

	wasLoaded, err := unloadLaunchAgent(deps)
	if err != nil {
		return err
	}

	if err := writeLaunchAgentPlist(plistPath, []byte(rendered), 0o644, deps); err != nil {
		installErr := fmt.Errorf("write launch agent plist: %w", err)
		if rollbackErr := rollbackLaunchAgentInstall(plistPath, previousPlist, previousExists, wasLoaded, deps); rollbackErr != nil {
			return combineLaunchAgentInstallErrors(installErr, rollbackErr)
		}
		return installErr
	}

	domain := launchAgentDomain(deps.uid())
	out, err := deps.runLaunchctl("bootstrap", domain, plistPath)
	if err != nil {
		installErr := launchctlFailure("bootstrap", domain, out, err)
		if rollbackErr := rollbackLaunchAgentInstall(plistPath, previousPlist, previousExists, wasLoaded, deps); rollbackErr != nil {
			return combineLaunchAgentInstallErrors(installErr, rollbackErr)
		}
		return installErr
	}

	fmt.Fprintf(stdout, "installed launch agent %q at %s\n", launchAgentLabel, plistPath)
	return nil
}

func readLaunchAgentPlist(deps launchAgentDeps, plistPath string) ([]byte, bool, error) {
	plistBytes, err := deps.readFile(plistPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("read existing launch agent plist: %w", err)
	}
	return plistBytes, true, nil
}

func unloadLaunchAgent(deps launchAgentDeps) (bool, error) {
	target := launchAgentTarget(deps.uid())
	out, err := deps.runLaunchctl("bootout", target)
	if err != nil {
		if isLaunchctlNotFound(out) {
			return false, nil
		}
		return false, launchctlFailure("bootout", target, out, err)
	}
	return true, nil
}

func rollbackLaunchAgentInstall(plistPath string, previousPlist []byte, previousExists, wasLoaded bool, deps launchAgentDeps) error {
	if err := restoreLaunchAgentPlist(plistPath, previousPlist, previousExists, deps); err != nil {
		return err
	}
	if !wasLoaded {
		return nil
	}
	if !previousExists {
		return errors.New("restore previously loaded launch agent: previous plist was missing")
	}

	domain := launchAgentDomain(deps.uid())
	out, err := deps.runLaunchctl("bootstrap", domain, plistPath)
	if err != nil {
		return launchctlFailure("bootstrap", domain, out, err)
	}
	return nil
}

func restoreLaunchAgentPlist(plistPath string, previousPlist []byte, previousExists bool, deps launchAgentDeps) error {
	if !previousExists {
		if err := deps.remove(plistPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove launch agent plist during rollback: %w", err)
		}
		return nil
	}

	if err := writeLaunchAgentPlist(plistPath, previousPlist, 0o644, deps); err != nil {
		return fmt.Errorf("restore launch agent plist: %w", err)
	}
	return nil
}

func writeLaunchAgentPlist(path string, content []byte, perm os.FileMode, deps launchAgentDeps) error {
	tempFile, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tempPath := tempFile.Name()
	cleanupTemp := true
	defer func() {
		if cleanupTemp {
			_ = deps.remove(tempPath)
		}
	}()

	if _, err := tempFile.Write(content); err != nil {
		_ = tempFile.Close()
		return err
	}
	if err := tempFile.Chmod(perm); err != nil {
		_ = tempFile.Close()
		return err
	}
	if err := tempFile.Close(); err != nil {
		return err
	}
	if err := deps.rename(tempPath, path); err != nil {
		return err
	}

	cleanupTemp = false
	return nil
}

func combineLaunchAgentInstallErrors(installErr, rollbackErr error) error {
	return fmt.Errorf("%w; rollback failed: %v", installErr, rollbackErr)
}

func (d launchAgentDeps) loadLaunchAgentTemplate() ([]byte, error) {
	if templatePath := strings.TrimSpace(d.templatePath); templatePath != "" {
		templateBytes, err := d.readFile(templatePath)
		if err != nil {
			return nil, fmt.Errorf("read plist template %q: %w", templatePath, err)
		}
		return templateBytes, nil
	}
	if len(d.templateData) == 0 {
		return nil, errors.New("embedded plist template is empty")
	}
	return d.templateData, nil
}

func uninstallLaunchAgent(stdout io.Writer, deps launchAgentDeps) error {
	plistPath, err := deps.launchAgentPlistPath()
	if err != nil {
		return err
	}

	target := launchAgentTarget(deps.uid())
	out, err := deps.runLaunchctl("bootout", target)
	if err != nil && !isLaunchctlNotFound(out) {
		return launchctlFailure("bootout", target, out, err)
	}

	if _, err := deps.stat(plistPath); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			fmt.Fprintf(stdout, "launch agent plist not found at %s\n", plistPath)
			return nil
		}
		return fmt.Errorf("stat launch agent plist: %w", err)
	}

	if err := deps.remove(plistPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove launch agent plist: %w", err)
	}

	fmt.Fprintf(stdout, "removed launch agent plist %s\n", plistPath)
	return nil
}

func launchAgentStatus(deps launchAgentDeps) (bool, bool, error) {
	target := launchAgentTarget(deps.uid())
	out, err := deps.runLaunchctl("print", target)
	if err != nil {
		if isLaunchctlNotFound(out) {
			return false, false, nil
		}
		return false, false, launchctlFailure("print", target, out, err)
	}
	return true, launchAgentRunning(out), nil
}

func launchctlFailure(command, target, output string, err error) error {
	if strings.TrimSpace(output) != "" {
		return fmt.Errorf("launchctl %s %s failed: %s (%w)", command, target, output, err)
	}
	return fmt.Errorf("launchctl %s %s failed: %w", command, target, err)
}

func launchAgentRunning(output string) bool {
	for _, line := range strings.Split(output, "\n") {
		trimmed := strings.TrimSpace(strings.ToLower(line))
		if strings.HasPrefix(trimmed, "state =") {
			state := strings.TrimSpace(strings.TrimPrefix(trimmed, "state ="))
			state = strings.Trim(state, "\"")
			stateFields := strings.Fields(state)
			if len(stateFields) == 0 {
				return false
			}
			return stateFields[0] == "running"
		}
	}
	return false
}

func escapeXMLText(value string) (string, error) {
	var builder strings.Builder
	if err := xml.EscapeText(&builder, []byte(value)); err != nil {
		return "", err
	}
	return builder.String(), nil
}

func unresolvedTemplatePlaceholders(value string) []string {
	placeholders := []string{"__GUARDMYCOPY_BIN__", "__WORKDIR__", "__LOG_DIR__"}
	var unresolved []string
	for _, placeholder := range placeholders {
		if strings.Contains(value, placeholder) {
			unresolved = append(unresolved, placeholder)
		}
	}
	return unresolved
}

func isLaunchctlNotFound(output string) bool {
	normalized := strings.ToLower(strings.TrimSpace(output))
	if normalized == "" {
		return false
	}
	phrases := []string{
		"could not find service",
		"could not find specified service",
		"could not find requested service",
		"service does not exist",
		"no such process",
		"not loaded",
	}
	for _, phrase := range phrases {
		if strings.Contains(normalized, phrase) {
			return true
		}
	}
	return false
}

func launchAgentDomain(uid int) string {
	return fmt.Sprintf("gui/%d", uid)
}

func launchAgentTarget(uid int) string {
	return fmt.Sprintf("%s/%s", launchAgentDomain(uid), launchAgentLabel)
}

func requireDarwinCommand(commandName, runtimeOS string) error {
	if runtimeOS == "darwin" {
		return nil
	}
	return fmt.Errorf("error: %s is only supported on macOS (darwin); current OS: %s", commandName, runtimeOS)
}

func (d launchAgentDeps) launchAgentPlistPath() (string, error) {
	home, err := d.homeDir()
	if err != nil {
		return "", fmt.Errorf("resolve user home directory: %w", err)
	}
	home = strings.TrimSpace(home)
	if home == "" {
		return "", errors.New("resolve user home directory: empty path")
	}
	return filepath.Join(home, "Library", "LaunchAgents", launchAgentLabel+".plist"), nil
}

func (d launchAgentDeps) launchAgentLogDir() (string, error) {
	home, err := d.homeDir()
	if err != nil {
		return "", fmt.Errorf("resolve user home directory: %w", err)
	}
	home = strings.TrimSpace(home)
	if home == "" {
		return "", errors.New("resolve user home directory: empty path")
	}
	return filepath.Join(home, "Library", "Logs", "guardmycopy"), nil
}

func printInstallUsage(w io.Writer) {
	_, _ = fmt.Fprintln(w, `Usage:
  guardmycopy install`)
}

func printUninstallUsage(w io.Writer) {
	_, _ = fmt.Fprintln(w, `Usage:
  guardmycopy uninstall`)
}

func printStatusUsage(w io.Writer) {
	_, _ = fmt.Fprintln(w, `Usage:
  guardmycopy status`)
}

func detectForegroundAppHealth(activeApp func() (string, string, error)) (app.AppContextStatus, string, string, error) {
	if activeApp == nil {
		return app.AppContextStatusUnavailable, "", "", nil
	}

	appName, bundleID, err := activeApp()
	if err != nil {
		return app.AppContextStatusResolutionFailed, "", "", err
	}

	appName = strings.TrimSpace(appName)
	bundleID = strings.TrimSpace(bundleID)
	if appName == "" && bundleID == "" {
		return app.AppContextStatusUnavailable, "", "", nil
	}
	return app.AppContextStatusResolved, appName, bundleID, nil
}
