package core

import (
	"sort"
	"strings"
)

type ReplacementRedactor struct {
	byType             map[string]string
	defaultReplacement string
}

func NewReplacementRedactor(byType map[string]string) *ReplacementRedactor {
	clonedByType := make(map[string]string, len(byType))
	for findingType, replacement := range byType {
		clonedByType[findingType] = replacement
	}

	return &ReplacementRedactor{
		byType:             clonedByType,
		defaultReplacement: "[REDACTED]",
	}
}

func (r *ReplacementRedactor) Redact(text string, findings []Finding) string {
	if len(findings) == 0 {
		return text
	}

	sortedFindings := append([]Finding(nil), findings...)
	sort.Slice(sortedFindings, func(i, j int) bool {
		if sortedFindings[i].Start != sortedFindings[j].Start {
			return sortedFindings[i].Start < sortedFindings[j].Start
		}
		return sortedFindings[i].End < sortedFindings[j].End
	})

	var out strings.Builder
	out.Grow(len(text))

	cursor := 0
	for _, finding := range sortedFindings {
		if finding.Start < cursor || finding.Start < 0 || finding.End > len(text) || finding.End <= finding.Start {
			continue
		}

		out.WriteString(text[cursor:finding.Start])
		out.WriteString(r.replacementFor(finding))
		cursor = finding.End
	}

	out.WriteString(text[cursor:])
	return out.String()
}

func (r *ReplacementRedactor) replacementFor(finding Finding) string {
	if replacement, ok := r.byType[finding.Type]; ok {
		return replacement
	}
	return r.defaultReplacement
}
