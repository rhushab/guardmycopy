package core

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
)

func FuzzDetectorsFindingRanges(f *testing.F) {
	addCoreFuzzSeeds(f)
	detectors := coreDetectors()

	f.Fuzz(func(t *testing.T, input string) {
		for _, detector := range detectors {
			findings := detectNoPanic(t, detector.name, detector.detector, input)
			assertFindingRanges(t, input, findings, detector.name)
		}
	})
}

func FuzzFormatPreservingRedactorInvariants(f *testing.F) {
	addCoreFuzzSeeds(f)
	detectors := coreDetectors()
	redactor := NewFormatPreservingRedactor()

	f.Fuzz(func(t *testing.T, input string) {
		findings := make([]Finding, 0)
		for _, detector := range detectors {
			detected := detectNoPanic(t, detector.name, detector.detector, input)
			assertFindingRanges(t, input, detected, detector.name)
			findings = append(findings, detected...)
		}
		findings = append(findings, boundaryFindings(len(input))...)

		findingsBefore := append([]Finding(nil), findings...)
		first := redactNoPanic(t, redactor, input, findings)

		if !reflect.DeepEqual(findings, findingsBefore) {
			t.Fatalf("redactor mutated findings input: before=%+v after=%+v", findingsBefore, findings)
		}

		second := redactNoPanic(t, redactor, input, findings)
		if first != second {
			t.Fatalf("redactor output is not deterministic: first=%q second=%q", first, second)
		}
		if len(first) != len(input) {
			t.Fatalf("redactor changed text length: input=%d output=%d", len(input), len(first))
		}

		assertUnmaskedBytesPreserved(t, input, first, effectiveRedactionRanges(len(input), findings))
	})
}

type namedDetector struct {
	name     string
	detector Detector
}

type byteRange struct {
	start int
	end   int
}

func coreDetectors() []namedDetector {
	return []namedDetector{
		{name: FindingTypePEMPrivateKey, detector: NewPEMPrivateKeyDetector()},
		{name: FindingTypeJWT, detector: NewJWTDetector()},
		{name: FindingTypeEnvSecret, detector: NewEnvSecretDetector()},
		{name: "common_token_pack", detector: NewCommonTokenPackDetector()},
		{name: FindingTypeHighEntropyToken, detector: NewHighEntropyTokenDetector()},
	}
}

func addCoreFuzzSeeds(f *testing.F) {
	f.Helper()

	seeds := []string{
		"",
		"plain text without secrets",
		"API_KEY=abcdEFGHijklMNOP123456",
		`DB_PASSWORD="superSecretValue123456"`,
		"Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoiMTIzNDU2Nzg5MCIsInJvbGUiOiJhZG1pbiJ9.ZXlKaGJHY2lPaUpJVXpJMU5pSjkuZXlKMWMyVnlYMmxrSWpvaU1USXpORFUyTnpnNU1DSXNJbk52YkdVaU9pSmhaRzFwYmlKOQ",
		"token=ghp_abcdefghijklmnopqrstuvwxyzABCDEF1234",
		"https://hooks.slack.com/services/T00000000/B00000000/abcdefghijklmnopqrstuvwxABCD",
		"xoxb-123456789012-123456789012-abcdefghijklmnopqrstuvwxABCD",
		"Stripe key: sk_test_51NqkI2abcdefghijklmnopqrstuvwxABCD",
		"token: Ab9d_2Kp-7QxY4mN8sT1vW6zR3cL0hJ",
		"-----BEGIN PRIVATE KEY-----\na9Fz2LmQ7rTy8UoP4nVw6XcD3sKe1JhM\n-----END PRIVATE KEY-----",
	}
	for _, seed := range seeds {
		f.Add(seed)
	}

	testdataFiles, err := filepath.Glob(filepath.Join("testdata", "*.txt"))
	if err != nil {
		f.Fatalf("glob testdata fixtures: %v", err)
	}
	sort.Strings(testdataFiles)
	for _, path := range testdataFiles {
		data, err := os.ReadFile(path)
		if err != nil {
			f.Fatalf("read testdata fixture %q: %v", path, err)
		}
		f.Add(string(data))
	}
}

func detectNoPanic(t *testing.T, detectorName string, detector Detector, input string) (findings []Finding) {
	t.Helper()
	defer func() {
		if recovered := recover(); recovered != nil {
			t.Fatalf("detector %q panicked: %v", detectorName, recovered)
		}
	}()
	return detector.Detect(input)
}

func redactNoPanic(t *testing.T, redactor Redactor, input string, findings []Finding) (output string) {
	t.Helper()
	defer func() {
		if recovered := recover(); recovered != nil {
			t.Fatalf("redactor panicked: %v", recovered)
		}
	}()
	return redactor.Redact(input, findings)
}

func assertFindingRanges(t *testing.T, input string, findings []Finding, source string) {
	t.Helper()
	for i, finding := range findings {
		if finding.Start < 0 || finding.End > len(input) || finding.End <= finding.Start {
			t.Fatalf("%s finding %d has invalid range: start=%d end=%d inputLen=%d finding=%+v", source, i, finding.Start, finding.End, len(input), finding)
		}
	}
}

func boundaryFindings(inputLen int) []Finding {
	findings := []Finding{
		{Type: FindingTypeEnvSecret, Start: -1, End: 1},
		{Type: FindingTypeEnvSecret, Start: 1, End: 1},
		{Type: FindingTypeEnvSecret, Start: inputLen, End: inputLen + 1},
		{Type: FindingTypeEnvSecret, Start: inputLen + 4, End: inputLen + 8},
	}

	if inputLen > 0 {
		findings = append(findings,
			Finding{Type: FindingTypeEnvSecret, Start: 0, End: 1},
			Finding{Type: FindingTypeJWT, Start: 0, End: inputLen},
		)
	}
	if inputLen > 4 {
		findings = append(findings,
			Finding{Type: FindingTypePEMPrivateKey, Start: 1, End: inputLen - 1},
			Finding{Type: FindingTypeHighEntropyToken, Start: 2, End: 4},
		)
	}

	return findings
}

func effectiveRedactionRanges(inputLen int, findings []Finding) []byteRange {
	sortedFindings := append([]Finding(nil), findings...)
	sort.Slice(sortedFindings, func(i, j int) bool {
		if sortedFindings[i].Start != sortedFindings[j].Start {
			return sortedFindings[i].Start < sortedFindings[j].Start
		}
		return sortedFindings[i].End > sortedFindings[j].End
	})

	cursor := 0
	ranges := make([]byteRange, 0, len(sortedFindings))
	for _, finding := range sortedFindings {
		if finding.Start < cursor || finding.Start < 0 || finding.End > inputLen || finding.End <= finding.Start {
			continue
		}

		ranges = append(ranges, byteRange{start: finding.Start, end: finding.End})
		cursor = finding.End
	}

	return ranges
}

func assertUnmaskedBytesPreserved(t *testing.T, input string, output string, ranges []byteRange) {
	t.Helper()
	covered := make([]bool, len(input))
	for _, r := range ranges {
		for i := r.start; i < r.end; i++ {
			covered[i] = true
		}
	}

	for i := 0; i < len(input); i++ {
		if covered[i] {
			continue
		}
		if input[i] != output[i] {
			t.Fatalf("unmasked byte changed at index %d: input=%q output=%q ranges=%v", i, input[i], output[i], summarizeRanges(ranges))
		}
	}
}

func summarizeRanges(ranges []byteRange) string {
	out := make([]string, 0, len(ranges))
	for _, r := range ranges {
		out = append(out, fmt.Sprintf("[%d,%d)", r.start, r.end))
	}
	return fmt.Sprintf("%v", out)
}
