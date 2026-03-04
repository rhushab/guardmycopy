package app

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/rhushabhbontapalle/clipguard/internal/config"
	"github.com/rhushabhbontapalle/clipguard/internal/core"
)

type Clipboard interface {
	Read() (string, error)
	Write(value string) error
}

type Service struct {
	cfg       config.Config
	clipboard Clipboard
	engine    *core.Engine
}

func New(cfg config.Config, clipboard Clipboard) *Service {
	defaults := config.Defaults()
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = defaults.PollInterval
	}

	return &Service{
		cfg:       cfg,
		clipboard: clipboard,
		engine:    core.New(),
	}
}

func (s *Service) Sanitize(showDiff bool) (bool, error) {
	current, err := s.clipboard.Read()
	if err != nil {
		return false, fmt.Errorf("read clipboard: %w", err)
	}

	result := s.engine.Sanitize(current)
	if result.SanitizedText == current {
		return false, nil
	}

	if showDiff {
		fmt.Printf("risk=%s score=%d findings=%d\n", result.RiskLevel, result.Score, len(result.Findings))
		fmt.Printf("detectors: %s\n", strings.Join(detectorsTriggered(result.Findings), ", "))
		fmt.Printf("before: %q\n", current)
		fmt.Printf("after:  %q\n", result.SanitizedText)
	}

	if err := s.clipboard.Write(result.SanitizedText); err != nil {
		return false, fmt.Errorf("write clipboard: %w", err)
	}

	return true, nil
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

func (s *Service) Run(ctx context.Context, interval time.Duration) error {
	if interval <= 0 {
		interval = s.cfg.PollInterval
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	var lastSeen string
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			current, err := s.clipboard.Read()
			if err != nil {
				return fmt.Errorf("read clipboard: %w", err)
			}
			if current == lastSeen {
				continue
			}
			lastSeen = current

			result := s.engine.Sanitize(current)
			if result.SanitizedText == current {
				continue
			}

			if err := s.clipboard.Write(result.SanitizedText); err != nil {
				return fmt.Errorf("write clipboard: %w", err)
			}
			lastSeen = result.SanitizedText
		}
	}
}
