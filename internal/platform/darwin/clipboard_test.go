package darwin

import "testing"

func TestParseActiveAppOutputWithBundleID(t *testing.T) {
	name, bundleID := parseActiveAppOutput("Google Chrome\ncom.google.Chrome\n")
	if name != "Google Chrome" {
		t.Fatalf("unexpected app name: %q", name)
	}
	if bundleID != "com.google.Chrome" {
		t.Fatalf("unexpected bundle id: %q", bundleID)
	}
}

func TestParseActiveAppOutputWithoutBundleID(t *testing.T) {
	name, bundleID := parseActiveAppOutput("Terminal")
	if name != "Terminal" {
		t.Fatalf("unexpected app name: %q", name)
	}
	if bundleID != "" {
		t.Fatalf("expected empty bundle id, got %q", bundleID)
	}
}

func TestCleanBundleID(t *testing.T) {
	cleaned := cleanBundleID("  \"com.apple.Terminal\"  ")
	if cleaned != "com.apple.Terminal" {
		t.Fatalf("unexpected cleaned bundle id: %q", cleaned)
	}
}
