package core

import "regexp"

var jwtPattern = regexp.MustCompile(`(?m)(^|[^A-Za-z0-9_-])([A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{16,})([^A-Za-z0-9_-]|$)`)

type JWTDetector struct {
	pattern *regexp.Regexp
}

func NewJWTDetector() *JWTDetector {
	return &JWTDetector{
		pattern: jwtPattern,
	}
}

func (d *JWTDetector) Detect(text string) []Finding {
	matches := d.pattern.FindAllStringSubmatchIndex(text, -1)
	findings := make([]Finding, 0, len(matches))

	for _, m := range matches {
		if len(m) < 6 {
			continue
		}

		start := m[4]
		end := m[5]
		findings = append(findings, Finding{
			Type:     FindingTypeJWT,
			Severity: SeverityMedium,
			Start:    start,
			End:      end,
			Label:    "JWT token",
		})
	}

	return findings
}
