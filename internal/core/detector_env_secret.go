package core

import (
	"fmt"
	"regexp"
)

const defaultEnvSecretMinValueLength = 12

var envAssignmentPattern = regexp.MustCompile(`(?m)([A-Za-z_][A-Za-z0-9_-]{0,63})=("[^"\n]*"|'[^'\n]*'|[^\s;]+)`)
var secretEnvKeyPattern = regexp.MustCompile(`(?i)(TOKEN|SECRET|API[_-]?KEY|PASSWORD)`)

type EnvSecretDetector struct {
	pattern        *regexp.Regexp
	secretKey      *regexp.Regexp
	minValueLength int
}

func NewEnvSecretDetector() *EnvSecretDetector {
	return &EnvSecretDetector{
		pattern:        envAssignmentPattern,
		secretKey:      secretEnvKeyPattern,
		minValueLength: defaultEnvSecretMinValueLength,
	}
}

func (d *EnvSecretDetector) Detect(text string) []Finding {
	matches := d.pattern.FindAllStringSubmatchIndex(text, -1)
	findings := make([]Finding, 0, len(matches))

	for _, m := range matches {
		if len(m) < 6 {
			continue
		}

		key := text[m[2]:m[3]]
		if !d.secretKey.MatchString(key) {
			continue
		}

		valueStart := m[4]
		valueEnd := m[5]
		value := text[valueStart:valueEnd]

		if len(value) >= 2 && ((value[0] == '"' && value[len(value)-1] == '"') || (value[0] == '\'' && value[len(value)-1] == '\'')) {
			valueStart++
			valueEnd--
			value = value[1 : len(value)-1]
		}

		if len(value) <= d.minValueLength {
			continue
		}
		if valueEnd <= valueStart {
			continue
		}

		findings = append(findings, Finding{
			Type:     FindingTypeEnvSecret,
			Severity: SeverityHigh,
			Start:    valueStart,
			End:      valueEnd,
			Label:    fmt.Sprintf("Environment secret value (%s)", key),
		})
	}

	return findings
}
