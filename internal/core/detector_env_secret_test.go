package core

import "testing"

func TestEnvSecretDetectorDetect(t *testing.T) {
	detector := NewEnvSecretDetector()

	tests := []struct {
		name       string
		input      string
		wantCount  int
		wantValues []string
	}{
		{
			name:       "detects api key assignment",
			input:      "API_KEY=abcdEFGHijklMNOP123456",
			wantCount:  1,
			wantValues: []string{"abcdEFGHijklMNOP123456"},
		},
		{
			name:       "detects case-insensitive key names",
			input:      "service_token=qwertyUIOP1234567890",
			wantCount:  1,
			wantValues: []string{"qwertyUIOP1234567890"},
		},
		{
			name:       "detects quoted values and redacts inner value",
			input:      `DB_PASSWORD="superSecretValue123456"`,
			wantCount:  1,
			wantValues: []string{"superSecretValue123456"},
		},
		{
			name:      "ignores non-secret key names",
			input:     "BUILD_ID=abcdefghijklmnopqrstuvwxyz",
			wantCount: 0,
		},
		{
			name:      "ignores short values",
			input:     "SECRET=tooShort123",
			wantCount: 0,
		},
		{
			name:      "ignores shell placeholder values",
			input:     "API_KEY=$TOKEN",
			wantCount: 0,
		},
		{
			name:       "detects multiple values",
			input:      "TOKEN=AAAAaaaa1111bbbb2222\nPASSWORD=ZzYyXxWwVvUu1122334455",
			wantCount:  2,
			wantValues: []string{"AAAAaaaa1111bbbb2222", "ZzYyXxWwVvUu1122334455"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			findings := detector.Detect(tc.input)
			if len(findings) != tc.wantCount {
				t.Fatalf("unexpected finding count: got %d want %d", len(findings), tc.wantCount)
			}

			for i, wantValue := range tc.wantValues {
				gotValue := tc.input[findings[i].Start:findings[i].End]
				if gotValue != wantValue {
					t.Fatalf("finding %d: unexpected value match: got %q want %q", i, gotValue, wantValue)
				}
				if findings[i].Type != FindingTypeEnvSecret {
					t.Fatalf("finding %d: unexpected type: got %q want %q", i, findings[i].Type, FindingTypeEnvSecret)
				}
				if findings[i].Severity != SeverityHigh {
					t.Fatalf("finding %d: unexpected severity: got %q want %q", i, findings[i].Severity, SeverityHigh)
				}
			}
		})
	}
}
