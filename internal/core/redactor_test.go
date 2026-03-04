package core

import "testing"

func TestFormatPreservingRedactor(t *testing.T) {
	redactor := NewFormatPreservingRedactor()

	tests := []struct {
		name     string
		input    string
		findings []Finding
		want     string
	}{
		{
			name:  "masks middle and keeps prefix/suffix",
			input: "token=abcdefghijklmnop",
			findings: []Finding{
				{
					Type:  FindingTypeEnvSecret,
					Start: len("token="),
					End:   len("token=abcdefghijklmnop"),
				},
			},
			want: "token=ab************op",
		},
		{
			name:  "preserves whitespace in masked section",
			input: "foo abc\ndef\nghi uvw",
			findings: []Finding{
				{
					Type:  FindingTypePEMPrivateKey,
					Start: len("foo "),
					End:   len("foo abc\ndef\nghi"),
				},
			},
			want: "foo a**\n***\n**i uvw",
		},
		{
			name:  "uses larger overlap first",
			input: "KEY=ABCDEF1234567890",
			findings: []Finding{
				{
					Type:  FindingTypeHighEntropyToken,
					Start: len("KEY=AB"),
					End:   len("KEY=ABCDEF12345678"),
				},
				{
					Type:  FindingTypeEnvSecret,
					Start: len("KEY="),
					End:   len("KEY=ABCDEF1234567890"),
				},
			},
			want: "KEY=AB************90",
		},
		{
			name:  "preserves punctuation around secret",
			input: "Authorization: Bearer [abcDEF1234567890xyz]",
			findings: []Finding{
				{
					Type:  FindingTypeHighEntropyToken,
					Start: len("Authorization: Bearer ["),
					End:   len("Authorization: Bearer [abcDEF1234567890xyz]") - 1,
				},
			},
			want: "Authorization: Bearer [ab***************yz]",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := redactor.Redact(tc.input, tc.findings)
			if got != tc.want {
				t.Fatalf("unexpected redaction: got %q want %q", got, tc.want)
			}
		})
	}
}
