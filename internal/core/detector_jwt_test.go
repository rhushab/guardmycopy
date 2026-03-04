package core

import "testing"

func TestJWTDetectorDetect(t *testing.T) {
	detector := NewJWTDetector()

	tests := []struct {
		name      string
		input     string
		wantCount int
		wantToken string
	}{
		{
			name:      "detects jwt-like token",
			input:     "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoiMTIzNDU2Nzg5MCIsInJvbGUiOiJhZG1pbiJ9.ZXlKaGJHY2lPaUpJVXpJMU5pSjkuZXlKMWMyVnlYMmxrSWpvaU1USXpORFUyTnpnNU1DSXNJbk52YkdVaU9pSmhaRzFwYmlKOQ",
			wantCount: 1,
			wantToken: "eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoiMTIzNDU2Nzg5MCIsInJvbGUiOiJhZG1pbiJ9.ZXlKaGJHY2lPaUpJVXpJMU5pSjkuZXlKMWMyVnlYMmxrSWpvaU1USXpORFUyTnpnNU1DSXNJbk52YkdVaU9pSmhaRzFwYmlKOQ",
		},
		{
			name:      "rejects short segments",
			input:     "x abc.def.ghijklmnopq y",
			wantCount: 0,
		},
		{
			name:      "rejects non-base64url characters",
			input:     "x header.payload.sig+withplus y",
			wantCount: 0,
		},
		{
			name:      "detects multiple",
			input:     "a eyJhbGciOiJIUzI1NiJ9.eyJhIjoiYmJiYmJiYmJiYmJiYmJiYiJ9.rJ2Q2e0JxFkrGSxFJpBh7NZhNfDGhysQ b eyJhbGciOiJIUzI1NiJ9.eyJiIjoiY2NjY2NjY2NjY2NjY2NjYyJ9.s2PJv9v0jTz3N8zUUFQGJbWIKsORP1qt z",
			wantCount: 2,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			findings := detector.Detect(tc.input)
			if len(findings) != tc.wantCount {
				t.Fatalf("unexpected finding count: got %d want %d", len(findings), tc.wantCount)
			}
			if tc.wantToken == "" || tc.wantCount == 0 {
				return
			}

			gotToken := tc.input[findings[0].Start:findings[0].End]
			if gotToken != tc.wantToken {
				t.Fatalf("unexpected token match: got %q want %q", gotToken, tc.wantToken)
			}
			if findings[0].Type != FindingTypeJWT {
				t.Fatalf("unexpected finding type: got %q want %q", findings[0].Type, FindingTypeJWT)
			}
			if findings[0].Severity != SeverityMedium {
				t.Fatalf("unexpected finding severity: got %q want %q", findings[0].Severity, SeverityMedium)
			}
		})
	}
}
