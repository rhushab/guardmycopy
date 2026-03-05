package darwin

import "testing"

type stubPasteboardClient struct {
	value       string
	readErr     error
	writeErr    error
	changeCount int64
	changeErr   error
	writes      []string
}

func (s *stubPasteboardClient) ReadText() (string, error) {
	if s.readErr != nil {
		return "", s.readErr
	}
	return s.value, nil
}

func (s *stubPasteboardClient) WriteText(value string) error {
	if s.writeErr != nil {
		return s.writeErr
	}
	s.value = value
	s.writes = append(s.writes, value)
	return nil
}

func (s *stubPasteboardClient) ChangeCount() (int64, error) {
	if s.changeErr != nil {
		return 0, s.changeErr
	}
	return s.changeCount, nil
}

func TestClipboardDelegatesToPasteboardClient(t *testing.T) {
	client := &stubPasteboardClient{
		value:       "line one\nline two\twith symbols []{}",
		changeCount: 7,
	}
	clipboard := newClipboardWithClient(client)

	value, err := clipboard.ReadText()
	if err != nil {
		t.Fatalf("ReadText returned error: %v", err)
	}
	if value != client.value {
		t.Fatalf("unexpected clipboard value: %q", value)
	}

	if err := clipboard.WriteText("updated\nclipboard"); err != nil {
		t.Fatalf("WriteText returned error: %v", err)
	}
	if len(client.writes) != 1 || client.writes[0] != "updated\nclipboard" {
		t.Fatalf("unexpected writes: %#v", client.writes)
	}

	changeCount, err := clipboard.ChangeCount()
	if err != nil {
		t.Fatalf("ChangeCount returned error: %v", err)
	}
	if changeCount != 7 {
		t.Fatalf("unexpected change count: %d", changeCount)
	}
}

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
