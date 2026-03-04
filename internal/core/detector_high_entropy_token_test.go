package core

import "testing"

func TestHighEntropyTokenDetectorDetect(t *testing.T) {
	detector := NewHighEntropyTokenDetector()

	tests := []struct {
		name      string
		input     string
		wantCount int
		wantToken string
	}{
		{
			name:      "detects high entropy token",
			input:     "token: a9Fz2LmQ7rTy8UoP4nVw6XcD3sKe1JhM",
			wantCount: 1,
			wantToken: "a9Fz2LmQ7rTy8UoP4nVw6XcD3sKe1JhM",
		},
		{
			name:      "ignores low entropy token",
			input:     "token: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
			wantCount: 0,
		},
		{
			name:      "ignores short token",
			input:     "token: a9Fz2LmQ7rTy8UoP4nVw6Xc",
			wantCount: 0,
		},
		{
			name:      "ignores limited character set",
			input:     "token: abcdefghijklmnopqrstuvwxyzabcd",
			wantCount: 0,
		},
		{
			name:      "detects token with symbol set diversity",
			input:     "token: Ab9d_2Kp-7QxY4mN8sT1vW6zR3cL0hJ",
			wantCount: 1,
			wantToken: "Ab9d_2Kp-7QxY4mN8sT1vW6zR3cL0hJ",
		},
		{
			name:      "skips candidates inside PEM blocks",
			input:     "-----BEGIN PRIVATE KEY-----\na9Fz2LmQ7rTy8UoP4nVw6XcD3sKe1JhM\n-----END PRIVATE KEY-----",
			wantCount: 0,
		},
		{
			name:      "skips candidates inside jwt",
			input:     "eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoiMTIzNDU2Nzg5MCIsInJvbGUiOiJhZG1pbiJ9.ZXlKaGJHY2lPaUpJVXpJMU5pSjkuZXlKMWMyVnlYMmxrSWpvaU1USXpORFUyTnpnNU1DSXNJbk52YkdVaU9pSmhaRzFwYmlKOQ",
			wantCount: 0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			findings := detector.Detect(tc.input)
			if len(findings) != tc.wantCount {
				t.Fatalf("unexpected finding count: got %d want %d", len(findings), tc.wantCount)
			}
			if tc.wantCount == 0 || tc.wantToken == "" {
				return
			}

			gotToken := tc.input[findings[0].Start:findings[0].End]
			if gotToken != tc.wantToken {
				t.Fatalf("unexpected token match: got %q want %q", gotToken, tc.wantToken)
			}
			if findings[0].Type != FindingTypeHighEntropyToken {
				t.Fatalf("unexpected finding type: got %q want %q", findings[0].Type, FindingTypeHighEntropyToken)
			}
			if findings[0].Severity != SeverityMedium {
				t.Fatalf("unexpected finding severity: got %q want %q", findings[0].Severity, SeverityMedium)
			}
		})
	}
}
