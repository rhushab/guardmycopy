package core

import (
	"regexp"
	"sort"
	"strings"
)

var awsAccessKeyIDPattern = regexp.MustCompile(`(?m)(^|[^A-Z0-9])((?:AKIA|ASIA)[A-Z0-9]{16})([^A-Z0-9]|$)`)
var gitHubPATClassicPattern = regexp.MustCompile(`(?m)(^|[^A-Za-z0-9_])(ghp_[A-Za-z0-9]{36})([^A-Za-z0-9_]|$)`)
var gitHubPATFinePattern = regexp.MustCompile(`(?m)(^|[^A-Za-z0-9_])(github_pat_[A-Za-z0-9]{20,}_[A-Za-z0-9_]{20,})([^A-Za-z0-9_]|$)`)
var slackTokenPattern = regexp.MustCompile(`(?m)(^|[^A-Za-z0-9-])(xox(?:a-[0-9]+|[abprs])-[A-Za-z0-9-]{20,})([^A-Za-z0-9-]|$)`)
var slackWebhookPattern = regexp.MustCompile(`(?m)(^|[^A-Za-z0-9/:._-])(https://hooks\.slack(?:-gov)?\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{20,})([^A-Za-z0-9/:._-]|$)`)
var stripeSecretKeyPattern = regexp.MustCompile(`(?m)(^|[^A-Za-z0-9_])(sk_(?:live|test)_[A-Za-z0-9]{16,})([^A-Za-z0-9_]|$)`)

type CommonTokenPackDetector struct {
	rules []commonTokenRule
}

type commonTokenRule struct {
	pattern   *regexp.Regexp
	tokenType string
	label     string
	severity  Severity
	validate  func(string) bool
}

func NewCommonTokenPackDetector() *CommonTokenPackDetector {
	return &CommonTokenPackDetector{
		rules: []commonTokenRule{
			{
				pattern:   awsAccessKeyIDPattern,
				tokenType: FindingTypeAWSAccessKeyID,
				label:     "AWS access key ID",
				severity:  SeverityHigh,
			},
			{
				pattern:   gitHubPATClassicPattern,
				tokenType: FindingTypeGitHubPATClassic,
				label:     "GitHub token (classic PAT)",
				severity:  SeverityHigh,
			},
			{
				pattern:   gitHubPATFinePattern,
				tokenType: FindingTypeGitHubPATFine,
				label:     "GitHub token (fine-grained PAT)",
				severity:  SeverityHigh,
			},
			{
				pattern:   slackTokenPattern,
				tokenType: FindingTypeSlackToken,
				label:     "Slack token",
				severity:  SeverityHigh,
				validate:  isLikelySlackToken,
			},
			{
				pattern:   slackWebhookPattern,
				tokenType: FindingTypeSlackWebhook,
				label:     "Slack webhook URL",
				severity:  SeverityHigh,
			},
			{
				pattern:   stripeSecretKeyPattern,
				tokenType: FindingTypeStripeSecretKey,
				label:     "Stripe secret key",
				severity:  SeverityHigh,
			},
		},
	}
}

func (d *CommonTokenPackDetector) Detect(text string) []Finding {
	findings := make([]Finding, 0)
	for _, rule := range d.rules {
		matches := rule.pattern.FindAllStringSubmatchIndex(text, -1)
		for _, match := range matches {
			if len(match) < 6 {
				continue
			}

			start := match[4]
			end := match[5]
			value := text[start:end]
			if rule.validate != nil && !rule.validate(value) {
				continue
			}

			findings = append(findings, Finding{
				Type:     rule.tokenType,
				Severity: rule.severity,
				Start:    start,
				End:      end,
				Label:    rule.label,
			})
		}
	}

	return dedupeFindingsByRangeAndType(findings)
}

func dedupeFindingsByRangeAndType(findings []Finding) []Finding {
	if len(findings) <= 1 {
		return findings
	}

	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Start != findings[j].Start {
			return findings[i].Start < findings[j].Start
		}
		if findings[i].End != findings[j].End {
			return findings[i].End < findings[j].End
		}
		return findings[i].Type < findings[j].Type
	})

	out := findings[:0]
	for _, finding := range findings {
		if len(out) == 0 {
			out = append(out, finding)
			continue
		}

		prev := out[len(out)-1]
		if prev.Start == finding.Start && prev.End == finding.End && prev.Type == finding.Type {
			continue
		}
		out = append(out, finding)
	}

	return append([]Finding(nil), out...)
}

func isLikelySlackToken(value string) bool {
	if strings.Count(value, "-") < 2 {
		return false
	}
	return containsDigit(value)
}

func containsDigit(value string) bool {
	for i := 0; i < len(value); i++ {
		if value[i] >= '0' && value[i] <= '9' {
			return true
		}
	}
	return false
}
