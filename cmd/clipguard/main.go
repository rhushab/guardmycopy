package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rhushabhbontapalle/clipguard/internal/app"
	"github.com/rhushabhbontapalle/clipguard/internal/config"
	"github.com/rhushabhbontapalle/clipguard/internal/core"
	"github.com/rhushabhbontapalle/clipguard/internal/platform/darwin"
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
	case "run":
		return runLoop(args[1:])
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
		fmt.Fprintf(stderr, "findings: %d score=%d risk=%s\n", len(result.Findings), result.Score, result.RiskLevel)
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

func runLoop(args []string) int {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	intervalMS := fs.Int("interval", 0, "poll interval in milliseconds (defaults to config)")
	configPath := fs.String("config", "", "path to JSON config file")

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

	svc := app.New(cfg, darwin.NewClipboard())
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := svc.Run(ctx, interval); err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintf(os.Stderr, "run loop: %v\n", err)
		return 1
	}

	return 0
}

func printUsage(w io.Writer) {
	_, _ = fmt.Fprintln(w, `Usage:
  clipguard sanitize [--diff] < input.txt
  clipguard run [--interval ms] [--config path]
  clipguard --version`)
}
