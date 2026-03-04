package core

import (
	"math"
	"regexp"
)

const (
	defaultHighEntropyMinLength   = 24
	defaultHighEntropyThreshold   = 3.6
	defaultHighEntropyMinCharSets = 3
)

var highEntropyTokenPattern = regexp.MustCompile(`[A-Za-z0-9][A-Za-z0-9_-]{23,}`)

type HighEntropyTokenDetector struct {
	pattern      *regexp.Regexp
	minLength    int
	minCharSets  int
	minEntropy   float64
	excludeRange *regexp.Regexp
}

func NewHighEntropyTokenDetector() *HighEntropyTokenDetector {
	return &HighEntropyTokenDetector{
		pattern:      highEntropyTokenPattern,
		minLength:    defaultHighEntropyMinLength,
		minCharSets:  defaultHighEntropyMinCharSets,
		minEntropy:   defaultHighEntropyThreshold,
		excludeRange: pemPrivateKeyPattern,
	}
}

func (d *HighEntropyTokenDetector) Detect(text string) []Finding {
	candidates := d.pattern.FindAllStringIndex(text, -1)
	findings := make([]Finding, 0, len(candidates))
	excludedRanges := d.excludeRange.FindAllStringIndex(text, -1)
	for _, finding := range NewJWTDetector().Detect(text) {
		excludedRanges = append(excludedRanges, []int{finding.Start, finding.End})
	}
	for _, finding := range NewEnvSecretDetector().Detect(text) {
		excludedRanges = append(excludedRanges, []int{finding.Start, finding.End})
	}

	for _, candidate := range candidates {
		start := candidate[0]
		end := candidate[1]
		if end-start < d.minLength {
			continue
		}
		if overlapsAny(start, end, excludedRanges) {
			continue
		}

		value := text[start:end]
		if charSetCount(value) < d.minCharSets {
			continue
		}
		if shannonEntropy(value) < d.minEntropy {
			continue
		}

		findings = append(findings, Finding{
			Type:     FindingTypeHighEntropyToken,
			Severity: SeverityMedium,
			Start:    start,
			End:      end,
			Label:    "High-entropy token",
		})
	}

	return findings
}

func overlapsAny(start, end int, ranges [][]int) bool {
	for _, r := range ranges {
		if start < r[1] && end > r[0] {
			return true
		}
	}
	return false
}

func charSetCount(value string) int {
	hasLower := false
	hasUpper := false
	hasDigit := false
	hasSymbol := false

	for i := 0; i < len(value); i++ {
		b := value[i]
		switch {
		case b >= 'a' && b <= 'z':
			hasLower = true
		case b >= 'A' && b <= 'Z':
			hasUpper = true
		case b >= '0' && b <= '9':
			hasDigit = true
		case b == '-' || b == '_':
			hasSymbol = true
		}
	}

	total := 0
	if hasLower {
		total++
	}
	if hasUpper {
		total++
	}
	if hasDigit {
		total++
	}
	if hasSymbol {
		total++
	}
	return total
}

func shannonEntropy(value string) float64 {
	if len(value) == 0 {
		return 0
	}

	counts := make(map[byte]int)
	for i := 0; i < len(value); i++ {
		counts[value[i]]++
	}

	entropy := 0.0
	total := float64(len(value))
	for _, count := range counts {
		p := float64(count) / total
		entropy -= p * math.Log2(p)
	}
	return entropy
}
