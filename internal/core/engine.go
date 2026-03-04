package core

import "sort"

// ScoreWeights controls how much each finding severity contributes to the score.
type ScoreWeights struct {
	Low    int
	Medium int
	High   int
}

// Engine runs detectors and applies redaction rules.
type Engine struct {
	detectors []Detector
	redactor  Redactor
	weights   ScoreWeights
}

func New() *Engine {
	return NewEngine(
		[]Detector{
			NewPEMPrivateKeyDetector(),
		},
		NewReplacementRedactor(map[string]string{
			FindingTypePEMPrivateKey: "[REDACTED_PRIVATE_KEY]",
		}),
		DefaultScoreWeights(),
	)
}

func NewEngine(detectors []Detector, redactor Redactor, weights ScoreWeights) *Engine {
	defaults := DefaultScoreWeights()
	if weights.Low <= 0 {
		weights.Low = defaults.Low
	}
	if weights.Medium <= 0 {
		weights.Medium = defaults.Medium
	}
	if weights.High <= 0 {
		weights.High = defaults.High
	}
	if redactor == nil {
		redactor = noopRedactor{}
	}

	clonedDetectors := make([]Detector, 0, len(detectors))
	clonedDetectors = append(clonedDetectors, detectors...)

	return &Engine{
		detectors: clonedDetectors,
		redactor:  redactor,
		weights:   weights,
	}
}

func DefaultScoreWeights() ScoreWeights {
	return ScoreWeights{
		Low:    1,
		Medium: 5,
		High:   10,
	}
}

func (e *Engine) Scan(text string) ScanResult {
	findings := e.detect(text)
	score := e.score(findings)

	return ScanResult{
		Findings:  findings,
		Score:     score,
		RiskLevel: e.riskLevel(score),
	}
}

func (e *Engine) Sanitize(text string) SanitizeResult {
	scan := e.Scan(text)

	sanitized := text
	if len(scan.Findings) > 0 {
		sanitized = e.redactor.Redact(text, scan.Findings)
	}

	return SanitizeResult{
		SanitizedText: sanitized,
		Findings:      scan.Findings,
		Score:         scan.Score,
		RiskLevel:     scan.RiskLevel,
	}
}

func (e *Engine) detect(text string) []Finding {
	findings := make([]Finding, 0)
	for _, detector := range e.detectors {
		findings = append(findings, detector.Detect(text)...)
	}

	validFindings := findings[:0]
	for _, finding := range findings {
		if finding.Start < 0 || finding.End <= finding.Start || finding.End > len(text) {
			continue
		}
		validFindings = append(validFindings, finding)
	}

	sort.Slice(validFindings, func(i, j int) bool {
		if validFindings[i].Start != validFindings[j].Start {
			return validFindings[i].Start < validFindings[j].Start
		}
		return validFindings[i].End < validFindings[j].End
	})

	return append([]Finding(nil), validFindings...)
}

func (e *Engine) score(findings []Finding) int {
	total := 0
	for _, finding := range findings {
		switch finding.Severity {
		case SeverityHigh:
			total += e.weights.High
		case SeverityMedium:
			total += e.weights.Medium
		default:
			total += e.weights.Low
		}
	}
	return total
}

func (e *Engine) riskLevel(score int) RiskLevel {
	if score >= e.weights.High {
		return RiskLevelHigh
	}
	if score >= e.weights.Medium {
		return RiskLevelMed
	}
	return RiskLevelLow
}

type noopRedactor struct{}

func (noopRedactor) Redact(text string, findings []Finding) string {
	return text
}
