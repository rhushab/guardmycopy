package core

import "regexp"

const FindingTypePEMPrivateKey = "pem_private_key"

var pemPrivateKeyPattern = regexp.MustCompile(`(?is)-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----`)

type PEMPrivateKeyDetector struct {
	pattern *regexp.Regexp
}

func NewPEMPrivateKeyDetector() *PEMPrivateKeyDetector {
	return &PEMPrivateKeyDetector{
		pattern: pemPrivateKeyPattern,
	}
}

func (d *PEMPrivateKeyDetector) Detect(text string) []Finding {
	ranges := d.pattern.FindAllStringIndex(text, -1)
	findings := make([]Finding, 0, len(ranges))

	for _, r := range ranges {
		findings = append(findings, Finding{
			Type:     FindingTypePEMPrivateKey,
			Severity: SeverityHigh,
			Start:    r[0],
			End:      r[1],
			Label:    "PEM private key block",
		})
	}

	return findings
}
