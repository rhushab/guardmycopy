package core

import (
	"sort"
	"strings"
)

type FormatPreservingRedactor struct{}

func NewFormatPreservingRedactor() *FormatPreservingRedactor {
	return &FormatPreservingRedactor{}
}

func (r *FormatPreservingRedactor) Redact(text string, findings []Finding) string {
	if len(findings) == 0 {
		return text
	}

	sortedFindings := append([]Finding(nil), findings...)
	sort.Slice(sortedFindings, func(i, j int) bool {
		if sortedFindings[i].Start != sortedFindings[j].Start {
			return sortedFindings[i].Start < sortedFindings[j].Start
		}
		return sortedFindings[i].End > sortedFindings[j].End
	})

	var out strings.Builder
	out.Grow(len(text))

	cursor := 0
	for _, finding := range sortedFindings {
		if finding.Start < cursor || finding.Start < 0 || finding.End > len(text) || finding.End <= finding.Start {
			continue
		}

		out.WriteString(text[cursor:finding.Start])
		out.WriteString(r.mask(text[finding.Start:finding.End]))
		cursor = finding.End
	}

	out.WriteString(text[cursor:])
	return out.String()
}

func (r *FormatPreservingRedactor) mask(secret string) string {
	if len(secret) == 0 {
		return secret
	}

	keep := visibleEdge(secret)
	if len(secret) <= keep*2 {
		return strings.Repeat("*", len(secret))
	}

	var middle strings.Builder
	middle.Grow(len(secret) - (keep * 2))

	for i := keep; i < len(secret)-keep; i++ {
		switch secret[i] {
		case '\n', '\r', '\t', ' ':
			middle.WriteByte(secret[i])
		default:
			middle.WriteByte('*')
		}
	}

	return secret[:keep] + middle.String() + secret[len(secret)-keep:]
}

func visibleEdge(secret string) int {
	switch {
	case len(secret) >= 64:
		return 4
	case len(secret) >= 24:
		return 3
	case len(secret) >= 12:
		return 2
	default:
		return 1
	}
}
