package main

import (
	"context"
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

	"github.com/rhushabhbontapalle/clipguard/internal/app"
	"github.com/rhushabhbontapalle/clipguard/internal/config"
	"github.com/rhushabhbontapalle/clipguard/internal/core"
	"github.com/rhushabhbontapalle/clipguard/internal/platform"
	"github.com/rhushabhbontapalle/clipguard/internal/userstate"
)

const version = "0.1.0"

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 0 {
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
	case "snooze":
		return runSnooze(args[1:])
	case "allow-once":
		return runAllowOnce(args[1:])
	case "--help", "-h", "help":
		printUsage(os.Stdout)
		return 0
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", args[0])
		printUsage(os.Stderr)
		return 2
	}
}

func runSanitize(args []string) int {
	return runSanitizeWithIO(args, os.Stdin, os.Stdout, os.Stderr)
}

func runSanitizeWithIO(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("sanitize", flag.ContinueOnError)
	fs.SetOutput(stderr)

	showDiff := fs.Bool("diff", false, "print findings summary and before/after to stderr")

	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(stderr, "sanitize does not accept positional arguments")
		printUsage(stderr)
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
		fmt.Fprintf(stderr, "before:\n%s\n", text)
		fmt.Fprintf(stderr, "after:\n%s\n", result.SanitizedText)
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

	intervalMS := fs.Int("interval", 0, "poll interval in milliseconds (defaults to config)")
	configPath := fs.String("config", "", "path to YAML config file (optional)")
	once := fs.Bool("once", false, "scan current clipboard once and print decision")
	verbose := fs.Bool("verbose", false, "print reasoning for decisions")

	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "run does not accept positional arguments")
		printUsage(os.Stderr)
		return 2
	}
	if *intervalMS < 0 {
		fmt.Fprintln(os.Stderr, "--interval must be >= 0")
		return 2
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load config: %v\n", err)
		return 1
	}

	interval := cfg.PollInterval
	if *intervalMS > 0 {
		interval = time.Duration(*intervalMS) * time.Millisecond
	}

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

	configPath := fs.String("config", "", "path to YAML config file (optional)")
	verbose := fs.Bool("verbose", false, "print reasoning for decisions")

	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "once does not accept positional arguments")
		printUsage(os.Stderr)
		return 2
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load config: %v\n", err)
		return 1
	}

	adapters, err := platform.Select()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}

	svc := app.NewWithDependencies(cfg, adapters.Clipboard, adapters.ForegroundApp, adapters.Notifier)
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
		"app=%q action=%s risk=%s score=%d findings=%d\n",
		decision.ActiveAppName,
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

	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(stderr, "snooze requires exactly one duration argument (example: 5m)")
		printUsage(stderr)
		return 2
	}

	duration, err := time.ParseDuration(fs.Arg(0))
	if err != nil {
		fmt.Fprintf(stderr, "invalid snooze duration: %v\n", err)
		return 2
	}
	if duration <= 0 {
		fmt.Fprintln(stderr, "snooze duration must be > 0")
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

	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(stderr, "allow-once does not accept positional arguments")
		printUsage(stderr)
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

func printUsage(w io.Writer) {
	_, _ = fmt.Fprintf(w, `Usage:
  clipguard sanitize [--diff] < input.txt
  clipguard once [--config path] [--verbose]
  clipguard run [--interval ms] [--config path] [--once] [--verbose]
  clipguard snooze <duration>
  clipguard allow-once
  clipguard --version

When --config is not set, clipguard loads defaults and then attempts:
  %s
`, config.DefaultPath())
}
