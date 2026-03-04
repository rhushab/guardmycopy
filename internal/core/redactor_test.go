package core

import "testing"

func TestReplacementRedactorRedactsByType(t *testing.T) {
	redactor := NewReplacementRedactor(map[string]string{
		FindingTypePEMPrivateKey: "[REDACTED_PRIVATE_KEY]",
	})
	input := "foo -----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY----- bar"
	start := 4
	end := len(input) - 4

	got := redactor.Redact(input, []Finding{
		{
			Type:  FindingTypePEMPrivateKey,
			Start: start,
			End:   end,
		},
	})

	want := "foo [REDACTED_PRIVATE_KEY] bar"
	if got != want {
		t.Fatalf("unexpected redaction: got %q want %q", got, want)
	}
}
