package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/rhushab/guardmycopy/internal/auditlog"
)

type appActionCounts struct {
	App     string
	Blocked int
	Warned  int
}

type blockReasonEvent struct {
	Timestamp time.Time
	App       string
	Reason    string
}

type logStatsSummary struct {
	WindowStart time.Time
	WindowEnd   time.Time
	Entries     int
	Skipped     int
	AppCounts   []appActionCounts
	RiskCounts  map[string]int
	BlockEvents []blockReasonEvent
}

func runLogStatsWithIO(args []string, stdout, stderr io.Writer, logPath string, now func() time.Time) int {
	fs := flag.NewFlagSet("log stats", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { printLogUsage(fs.Output()) }

	sinceValue := fs.String("since", "", "required window (supports d/h/m, example: 7d, 12h, 30m)")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(stderr, "error: log stats does not accept positional arguments")
		printLogUsage(stderr)
		return 2
	}
	if strings.TrimSpace(*sinceValue) == "" {
		fmt.Fprintln(stderr, "error: log stats requires --since")
		printLogUsage(stderr)
		return 2
	}

	sinceDuration, err := parseSinceDuration(*sinceValue)
	if err != nil {
		fmt.Fprintf(stderr, "error: invalid --since: %v\n", err)
		return 2
	}

	store, err := auditlog.New(logPath)
	if err != nil {
		fmt.Fprintf(stderr, "open audit log: %v\n", err)
		return 1
	}

	summary, err := summarizeAuditLog(store.Path(), sinceDuration, now().UTC())
	if err != nil {
		fmt.Fprintf(stderr, "read audit log: %v\n", err)
		return 1
	}

	printLogStats(stdout, summary, strings.ToLower(strings.TrimSpace(*sinceValue)))
	return 0
}

func parseSinceDuration(value string) (time.Duration, error) {
	input := strings.ToLower(strings.TrimSpace(value))
	if input == "" {
		return 0, errors.New("duration is empty")
	}

	total := time.Duration(0)
	for i := 0; i < len(input); {
		if input[i] < '0' || input[i] > '9' {
			return 0, fmt.Errorf("expected number at position %d", i+1)
		}

		j := i
		for j < len(input) && input[j] >= '0' && input[j] <= '9' {
			j++
		}

		amount, err := strconv.Atoi(input[i:j])
		if err != nil {
			return 0, fmt.Errorf("invalid number at position %d: %w", i+1, err)
		}
		if amount <= 0 {
			return 0, errors.New("duration must be > 0")
		}
		if j >= len(input) {
			return 0, errors.New("missing unit suffix (supported: d/h/m)")
		}

		var unitDuration time.Duration
		switch input[j] {
		case 'd':
			unitDuration = 24 * time.Hour
		case 'h':
			unitDuration = time.Hour
		case 'm':
			unitDuration = time.Minute
		default:
			return 0, fmt.Errorf("unsupported unit %q (supported: d/h/m)", string(input[j]))
		}

		total += time.Duration(amount) * unitDuration
		i = j + 1
	}

	if total <= 0 {
		return 0, errors.New("duration must be > 0")
	}
	return total, nil
}

func summarizeAuditLog(path string, since time.Duration, now time.Time) (logStatsSummary, error) {
	summary := logStatsSummary{
		WindowStart: now.Add(-since),
		WindowEnd:   now,
		RiskCounts: map[string]int{
			"low":  0,
			"med":  0,
			"high": 0,
		},
	}

	file, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return summary, nil
		}
		return summary, fmt.Errorf("open audit log: %w", err)
	}
	defer file.Close()

	appCountByName := make(map[string]*appActionCounts)
	blockEvents := make([]blockReasonEvent, 0)

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		raw := strings.TrimSpace(scanner.Text())
		if raw == "" {
			summary.Skipped++
			continue
		}

		var entry auditlog.Entry
		if err := json.Unmarshal([]byte(raw), &entry); err != nil {
			summary.Skipped++
			continue
		}
		if entry.Timestamp.IsZero() {
			summary.Skipped++
			continue
		}

		timestamp := entry.Timestamp.UTC()
		if timestamp.Before(summary.WindowStart) || timestamp.After(summary.WindowEnd) {
			continue
		}

		summary.Entries++
		riskLevel := normalizeRiskLevel(entry.RiskLevel)
		summary.RiskCounts[riskLevel]++

		action := strings.ToLower(strings.TrimSpace(entry.Action))
		if action != "block" && action != "warn" {
			continue
		}

		appName := strings.TrimSpace(entry.App)
		if appName == "" {
			appName = "(unknown app)"
		}

		counts, ok := appCountByName[appName]
		if !ok {
			counts = &appActionCounts{App: appName}
			appCountByName[appName] = counts
		}
		if action == "block" {
			counts.Blocked++
			blockEvents = append(blockEvents, blockReasonEvent{
				Timestamp: timestamp,
				App:       appName,
				Reason:    normalizeBlockReason(entry.FindingTypes),
			})
		} else {
			counts.Warned++
		}
	}
	if err := scanner.Err(); err != nil {
		return summary, fmt.Errorf("scan audit log: %w", err)
	}

	summary.AppCounts = make([]appActionCounts, 0, len(appCountByName))
	for _, counts := range appCountByName {
		summary.AppCounts = append(summary.AppCounts, *counts)
	}
	sort.Slice(summary.AppCounts, func(i, j int) bool {
		leftTotal := summary.AppCounts[i].Blocked + summary.AppCounts[i].Warned
		rightTotal := summary.AppCounts[j].Blocked + summary.AppCounts[j].Warned
		if leftTotal != rightTotal {
			return leftTotal > rightTotal
		}
		if summary.AppCounts[i].Blocked != summary.AppCounts[j].Blocked {
			return summary.AppCounts[i].Blocked > summary.AppCounts[j].Blocked
		}
		if summary.AppCounts[i].Warned != summary.AppCounts[j].Warned {
			return summary.AppCounts[i].Warned > summary.AppCounts[j].Warned
		}
		return summary.AppCounts[i].App < summary.AppCounts[j].App
	})

	sort.Slice(blockEvents, func(i, j int) bool {
		if !blockEvents[i].Timestamp.Equal(blockEvents[j].Timestamp) {
			return blockEvents[i].Timestamp.After(blockEvents[j].Timestamp)
		}
		if blockEvents[i].App != blockEvents[j].App {
			return blockEvents[i].App < blockEvents[j].App
		}
		return blockEvents[i].Reason < blockEvents[j].Reason
	})

	if len(blockEvents) > 5 {
		summary.BlockEvents = append([]blockReasonEvent(nil), blockEvents[:5]...)
	} else {
		summary.BlockEvents = append([]blockReasonEvent(nil), blockEvents...)
	}

	return summary, nil
}

func normalizeRiskLevel(value string) string {
	normalized := strings.ToLower(strings.TrimSpace(value))
	switch normalized {
	case "low":
		return "low"
	case "med", "medium":
		return "med"
	case "high":
		return "high"
	case "":
		return "unknown"
	default:
		return normalized
	}
}

func normalizeBlockReason(findingTypes []string) string {
	if len(findingTypes) == 0 {
		return "unknown"
	}

	unique := make(map[string]struct{}, len(findingTypes))
	for _, findingType := range findingTypes {
		normalized := strings.ToLower(strings.TrimSpace(findingType))
		if normalized == "" {
			continue
		}
		unique[normalized] = struct{}{}
	}
	if len(unique) == 0 {
		return "unknown"
	}

	out := make([]string, 0, len(unique))
	for findingType := range unique {
		out = append(out, findingType)
	}
	sort.Strings(out)
	return strings.Join(out, ",")
}

func printLogStats(w io.Writer, summary logStatsSummary, sinceValue string) {
	_, _ = fmt.Fprintf(
		w,
		"window=%s start=%s end=%s entries=%d skipped=%d\n",
		sinceValue,
		summary.WindowStart.Format(time.RFC3339),
		summary.WindowEnd.Format(time.RFC3339),
		summary.Entries,
		summary.Skipped,
	)

	_, _ = fmt.Fprintln(w, "top apps by blocked/warned count:")
	if len(summary.AppCounts) == 0 {
		_, _ = fmt.Fprintln(w, "none")
	} else {
		for i, counts := range summary.AppCounts {
			_, _ = fmt.Fprintf(
				w,
				"%d. app=%q blocked=%d warned=%d total=%d\n",
				i+1,
				counts.App,
				counts.Blocked,
				counts.Warned,
				counts.Blocked+counts.Warned,
			)
		}
	}

	_, _ = fmt.Fprintln(w, "counts by risk level:")
	_, _ = fmt.Fprintf(w, "low=%d\n", summary.RiskCounts["low"])
	_, _ = fmt.Fprintf(w, "med=%d\n", summary.RiskCounts["med"])
	_, _ = fmt.Fprintf(w, "high=%d\n", summary.RiskCounts["high"])

	extraLevels := make([]string, 0, len(summary.RiskCounts))
	for riskLevel := range summary.RiskCounts {
		if riskLevel == "low" || riskLevel == "med" || riskLevel == "high" {
			continue
		}
		extraLevels = append(extraLevels, riskLevel)
	}
	sort.Strings(extraLevels)
	for _, riskLevel := range extraLevels {
		_, _ = fmt.Fprintf(w, "%s=%d\n", riskLevel, summary.RiskCounts[riskLevel])
	}

	_, _ = fmt.Fprintln(w, "last 5 block reasons:")
	if len(summary.BlockEvents) == 0 {
		_, _ = fmt.Fprintln(w, "none")
		return
	}
	for i, event := range summary.BlockEvents {
		_, _ = fmt.Fprintf(
			w,
			"%d. %s app=%q reasons=%s\n",
			i+1,
			event.Timestamp.Format(time.RFC3339),
			event.App,
			event.Reason,
		)
	}
}
