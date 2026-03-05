package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/rhushab/guardmycopy/internal/app"
	"github.com/rhushab/guardmycopy/internal/auditlog"
	"github.com/rhushab/guardmycopy/internal/config"
	"github.com/rhushab/guardmycopy/internal/core"
	"github.com/rhushab/guardmycopy/internal/platform"
	"github.com/rhushab/guardmycopy/internal/userstate"
)

const version = "1.0.0-rc2-dev"

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "error: missing command")
		printUsage(os.Stderr)
		return 2
	}

	switch args[0] {
	case "--version", "-version", "version":
		fmt.Println(version)
		return 0
	case "sanitize":
		return runSanitize(args[1:])
	case "once":
		return runOnce(args[1:])
	case "run":
		return runLoop(args[1:])
	case "install":
		return runInstall(args[1:])
	case "uninstall":
		return runUninstall(args[1:])
	case "status":
		return runStatus(args[1:])
	case "snooze":
		return runSnooze(args[1:])
	case "allow-once":
		return runAllowOnce(args[1:])
	case "log":
		return runLog(args[1:])
	case "config":
		return runConfig(args[1:])
	case "--help", "-h", "help":
		return runHelp(args[1:], os.Stdout, os.Stderr)
	default:
		fmt.Fprintf(os.Stderr, "error: unknown command %q\n", args[0])
		printUsage(os.Stderr)
		return 2
	}
}

func runHelp(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		printUsage(stdout)
		return 0
	}

	switch args[0] {
	case "sanitize":
		printSanitizeUsage(stdout)
		return 0
	case "once":
		printOnceUsage(stdout)
		return 0
	case "run":
		printRunUsage(stdout)
		return 0
	case "install":
		printInstallUsage(stdout)
		return 0
	case "uninstall":
		printUninstallUsage(stdout)
		return 0
	case "status":
		printStatusUsage(stdout)
		return 0
	case "snooze":
		printSnoozeUsage(stdout)
		return 0
	case "allow-once":
		printAllowOnceUsage(stdout)
		return 0
	case "log":
		printLogUsage(stdout)
		return 0
	case "config":
		if len(args) == 1 {
			printConfigUsage(stdout)
			return 0
		}
		if len(args) == 2 && args[1] == "init" {
			printConfigInitUsage(stdout)
			return 0
		}
	}

	fmt.Fprintf(stderr, "error: unknown help topic %q\n", strings.Join(args, " "))
	printUsage(stderr)
	return 2
}

func runSanitize(args []string) int {
	return runSanitizeWithIO(args, os.Stdin, os.Stdout, os.Stderr)
}

func runSanitizeWithIO(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("sanitize", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { printSanitizeUsage(fs.Output()) }

	showDiff := fs.Bool("diff", false, "print findings summary and before/after to stderr")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(stderr, "error: sanitize does not accept positional arguments")
		printSanitizeUsage(stderr)
		return 2
	}

	input, err := io.ReadAll(stdin)
	if err != nil {
		fmt.Fprintf(stderr, "read stdin: %v\n", err)
		return 1
	}

	text := string(input)
	result := core.New().Sanitize(text)

	if *showDiff {
		fmt.Fprintf(stderr, "risk=%s score=%d findings=%d\n", result.RiskLevel, result.Score, len(result.Findings))
		fmt.Fprintf(stderr, "detectors: %s\n", strings.Join(detectorsTriggered(result.Findings), ", "))
		for i, finding := range result.Findings {
			fmt.Fprintf(
				stderr,
				"%d. %s [%s] %d:%d %s\n",
				i+1,
				finding.Type,
				finding.Severity,
				finding.Start,
				finding.End,
				finding.Label,
			)
		}
		safeBefore := core.NewFormatPreservingRedactor().Redact(text, result.Findings)
		fmt.Fprintf(stderr, "input_hash=%s sanitized_hash=%s\n", hashString(text), hashString(result.SanitizedText))
		fmt.Fprintf(stderr, "before(redacted):\n%s\n", safeBefore)
		fmt.Fprintf(stderr, "after(redacted):\n%s\n", result.SanitizedText)
	}

	if _, err := io.WriteString(stdout, result.SanitizedText); err != nil {
		fmt.Fprintf(stderr, "write stdout: %v\n", err)
		return 1
	}

	return 0
}

func detectorsTriggered(findings []core.Finding) []string {
	if len(findings) == 0 {
		return []string{"none"}
	}

	unique := make(map[string]struct{}, len(findings))
	for _, finding := range findings {
		unique[finding.Type] = struct{}{}
	}

	out := make([]string, 0, len(unique))
	for findingType := range unique {
		out = append(out, findingType)
	}
	sort.Strings(out)
	return out
}

func runLoop(args []string) int {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() { printRunUsage(fs.Output()) }

	intervalMS := fs.Int("interval", 0, "poll interval in milliseconds (defaults to config)")
	configPath := fs.String("config", "", "path to YAML config file (optional)")
	once := fs.Bool("once", false, "scan current clipboard once and print decision")
	verbose := fs.Bool("verbose", false, "print reasoning for decisions")
	auditLogEnabled := fs.Bool("audit-log", false, "append JSONL audit entries under user config directory")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "error: run does not accept positional arguments")
		printRunUsage(os.Stderr)
		return 2
	}
	if *intervalMS < 0 {
		fmt.Fprintln(os.Stderr, "error: --interval must be >= 0")
		return 2
	}

	cfg, warnings, err := config.LoadWithWarnings(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load config: %v\n", err)
		return 1
	}
	printWarnings(os.Stderr, warnings)

	interval := cfg.PollInterval
	if *intervalMS > 0 {
		interval = time.Duration(*intervalMS) * time.Millisecond
	}
	normalizedInterval := config.NormalizePollInterval(interval)
	if normalizedInterval != interval {
		fmt.Fprintf(
			os.Stderr,
			"warning: --interval %dms is below minimum %dms; using %dms\n",
			interval.Milliseconds(),
			config.MinPollInterval().Milliseconds(),
			normalizedInterval.Milliseconds(),
		)
	}
	interval = normalizedInterval

	adapters, err := platform.Select()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}

	svc := app.NewWithDependencies(cfg, adapters.Clipboard, adapters.ForegroundApp, adapters.Notifier)
	stateStore, err := userstate.New("")
	if err != nil {
		fmt.Fprintf(os.Stderr, "open runtime state: %v\n", err)
		return 1
	}
	svc.SetRuntimeStateStore(stateStore)
	if *auditLogEnabled {
		auditStore, err := auditlog.New("")
		if err != nil {
			fmt.Fprintf(os.Stderr, "open audit log: %v\n", err)
			return 1
		}
		svc.SetAuditLogStore(auditStore)
	}
	if *verbose {
		svc.SetVerboseOutput(os.Stderr)
	}
	if *once {
		return runOnceWithService(svc, os.Stdout, os.Stderr, *verbose)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := svc.Run(ctx, interval); err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintf(os.Stderr, "run loop: %v\n", err)
		return 1
	}

	return 0
}

func runOnce(args []string) int {
	fs := flag.NewFlagSet("once", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() { printOnceUsage(fs.Output()) }

	configPath := fs.String("config", "", "path to YAML config file (optional)")
	verbose := fs.Bool("verbose", false, "print reasoning for decisions")
	auditLogEnabled := fs.Bool("audit-log", false, "append JSONL audit entries under user config directory")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "error: once does not accept positional arguments")
		printOnceUsage(os.Stderr)
		return 2
	}

	cfg, warnings, err := config.LoadWithWarnings(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load config: %v\n", err)
		return 1
	}
	printWarnings(os.Stderr, warnings)

	adapters, err := platform.Select()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}

	svc := app.NewWithDependencies(cfg, adapters.Clipboard, adapters.ForegroundApp, adapters.Notifier)
	if *auditLogEnabled {
		auditStore, err := auditlog.New("")
		if err != nil {
			fmt.Fprintf(os.Stderr, "open audit log: %v\n", err)
			return 1
		}
		svc.SetAuditLogStore(auditStore)
	}
	return runOnceWithService(svc, os.Stdout, os.Stderr, *verbose)
}

func runOnceWithService(svc *app.Service, stdout, stderr io.Writer, verbose bool) int {
	decision, reasoning, err := svc.ScanCurrentDetailed()
	if err != nil {
		fmt.Fprintf(stderr, "scan clipboard: %v\n", err)
		return 1
	}

	fmt.Fprintf(
		stdout,
		"app=%q bundle_id=%q action=%s risk=%s score=%d findings=%d\n",
		decision.ActiveAppName,
		decision.ActiveAppBundleID,
		decision.Action,
		decision.RiskLevel,
		decision.Score,
		decision.Findings,
	)
	if verbose {
		for _, line := range reasoning {
			fmt.Fprintf(stderr, "reason=%s\n", line)
		}
	}
	return 0
}

func runSnooze(args []string) int {
	return runSnoozeWithIO(args, os.Stdout, os.Stderr, time.Now, "")
}

func runSnoozeWithIO(args []string, stdout, stderr io.Writer, now func() time.Time, statePath string) int {
	fs := flag.NewFlagSet("snooze", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { printSnoozeUsage(fs.Output()) }

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(stderr, "error: snooze requires exactly one duration argument (example: 5m)")
		printSnoozeUsage(stderr)
		return 2
	}

	duration, err := time.ParseDuration(fs.Arg(0))
	if err != nil {
		fmt.Fprintf(stderr, "error: invalid snooze duration: %v\n", err)
		return 2
	}
	if duration <= 0 {
		fmt.Fprintln(stderr, "error: snooze duration must be > 0")
		return 2
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
	state.SnoozedUntil = now().Add(duration)
	if err := store.Save(state); err != nil {
		fmt.Fprintf(stderr, "save runtime state: %v\n", err)
		return 1
	}

	fmt.Fprintf(stdout, "enforcement snoozed until %s\n", state.SnoozedUntil.Local().Format(time.RFC3339))
	return 0
}

func runAllowOnce(args []string) int {
	return runAllowOnceWithIO(args, os.Stdout, os.Stderr, "")
}

func runAllowOnceWithIO(args []string, stdout, stderr io.Writer, statePath string) int {
	fs := flag.NewFlagSet("allow-once", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { printAllowOnceUsage(fs.Output()) }

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(stderr, "error: allow-once does not accept positional arguments")
		printAllowOnceUsage(stderr)
		return 2
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
	state.AllowOnce = true
	if err := store.Save(state); err != nil {
		fmt.Fprintf(stderr, "save runtime state: %v\n", err)
		return 1
	}

	fmt.Fprintln(stdout, "next clipboard event will bypass enforcement once")
	return 0
}

func runLog(args []string) int {
	return runLogWithIO(args, os.Stdout, os.Stderr, "")
}

func runLogWithIO(args []string, stdout, stderr io.Writer, logPath string) int {
	if len(args) > 0 && args[0] == "stats" {
		return runLogStatsWithIO(args[1:], stdout, stderr, logPath, time.Now)
	}

	fs := flag.NewFlagSet("log", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { printLogUsage(fs.Output()) }

	tailLines := fs.Int("tail", 50, "print the last N audit log entries")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(stderr, "error: log does not accept positional arguments")
		printLogUsage(stderr)
		return 2
	}
	if *tailLines <= 0 {
		fmt.Fprintln(stderr, "error: --tail must be > 0")
		return 2
	}

	store, err := auditlog.New(logPath)
	if err != nil {
		fmt.Fprintf(stderr, "open audit log: %v\n", err)
		return 1
	}
	lines, err := store.Tail(*tailLines)
	if err != nil {
		fmt.Fprintf(stderr, "read audit log: %v\n", err)
		return 1
	}

	for _, line := range lines {
		fmt.Fprintln(stdout, line)
	}
	return 0
}

func runConfig(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "error: missing config subcommand")
		printConfigUsage(os.Stderr)
		return 2
	}

	switch args[0] {
	case "init":
		return runConfigInit(args[1:])
	case "--help", "-h", "help":
		printConfigUsage(os.Stdout)
		return 0
	default:
		fmt.Fprintf(os.Stderr, "error: unknown config subcommand %q\n", args[0])
		printConfigUsage(os.Stderr)
		return 2
	}
}

func runConfigInit(args []string) int {
	return runConfigInitWithIO(args, os.Stdout, os.Stderr, "")
}

func runConfigInitWithIO(args []string, stdout, stderr io.Writer, defaultPathOverride string) int {
	fs := flag.NewFlagSet("config init", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { printConfigInitUsage(fs.Output()) }

	force := fs.Bool("force", false, "overwrite an existing config file")
	path := fs.String("path", "", "write config to a specific file path")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(stderr, "error: config init does not accept positional arguments")
		printConfigInitUsage(stderr)
		return 2
	}

	targetPath := strings.TrimSpace(*path)
	if targetPath == "" {
		targetPath = strings.TrimSpace(defaultPathOverride)
	}

	writtenPath, err := config.WriteDefault(targetPath, *force)
	if err != nil {
		fmt.Fprintf(stderr, "initialize config: %v\n", err)
		return 1
	}

	fmt.Fprintf(stdout, "wrote default config to %s\n", writtenPath)
	return 0
}

func printUsage(w io.Writer) {
	_, _ = fmt.Fprintf(w, `Usage:
  guardmycopy <command> [options]

Commands:
  sanitize    redact sensitive spans from stdin
  once        scan clipboard once and print the decision
  run         run continuous clipboard scanning
  install     install and bootstrap the macOS launch agent
  uninstall   boot out and remove the macOS launch agent
  status      print launch agent and runtime bypass status
  snooze      disable enforcement for a duration (for example: 5m)
  allow-once  bypass enforcement for the next clipboard event
  log         print recent audit log entries or stats
  config      manage guardmycopy config files
  version     print CLI version

Run "guardmycopy help <command>" for command-specific usage.

Default config path:
  %s
`, config.DefaultPath())
}

func printSanitizeUsage(w io.Writer) {
	_, _ = fmt.Fprintln(w, `Usage:
  guardmycopy sanitize [--diff] < input.txt

Options:
  --diff  print findings summary and before/after to stderr`)
}

func printOnceUsage(w io.Writer) {
	_, _ = fmt.Fprintln(w, `Usage:
  guardmycopy once [--config path] [--verbose] [--audit-log]

Options:
  --config path  path to YAML config file (optional)
  --verbose      print reasoning for decisions
  --audit-log    append JSONL audit entries under user config directory`)
}

func printRunUsage(w io.Writer) {
	_, _ = fmt.Fprintln(w, `Usage:
  guardmycopy run [--interval ms] [--config path] [--once] [--verbose] [--audit-log]

Options:
  --interval ms  poll interval in milliseconds (defaults to config, minimum 100)
  --config path  path to YAML config file (optional)
  --once         scan current clipboard once and print the decision
  --verbose      print reasoning for decisions
  --audit-log    append JSONL audit entries under user config directory`)
}

func printSnoozeUsage(w io.Writer) {
	_, _ = fmt.Fprintln(w, `Usage:
  guardmycopy snooze <duration>

Example:
  guardmycopy snooze 5m`)
}

func printAllowOnceUsage(w io.Writer) {
	_, _ = fmt.Fprintln(w, `Usage:
  guardmycopy allow-once`)
}

func printLogUsage(w io.Writer) {
	_, _ = fmt.Fprintln(w, `Usage:
  guardmycopy log [--tail N]
  guardmycopy log stats --since duration

Options:
  --tail N  print the last N audit log entries (default: 50)

Stats Options:
  --since duration  required window (supports d/h/m, example: 7d, 12h, 30m)`)
}

func printConfigUsage(w io.Writer) {
	_, _ = fmt.Fprintln(w, `Usage:
  guardmycopy config <subcommand> [options]

Subcommands:
  init  write a default config file`)
}

func printConfigInitUsage(w io.Writer) {
	_, _ = fmt.Fprintf(w, `Usage:
  guardmycopy config init [--force] [--path file]

Options:
  --force      overwrite an existing config file
  --path file  write to a specific path instead of the default

Default path:
  %s
`, config.DefaultPath())
}

func printWarnings(w io.Writer, warnings []string) {
	for _, warning := range warnings {
		_, _ = fmt.Fprintf(w, "warning: %s\n", warning)
	}
}

func hashString(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}
