//go:build !darwin

package darwin

import "fmt"

func newPasteboardClient() pasteboardClient {
	return unsupportedPasteboardClient{}
}

type unsupportedPasteboardClient struct{}

func (unsupportedPasteboardClient) ReadText() (string, error) {
	return "", fmt.Errorf("native pasteboard clipboard access is unavailable on this OS")
}

func (unsupportedPasteboardClient) WriteText(string) error {
	return fmt.Errorf("native pasteboard clipboard access is unavailable on this OS")
}

func (unsupportedPasteboardClient) ChangeCount() (int64, error) {
	return 0, fmt.Errorf("native pasteboard clipboard access is unavailable on this OS")
}
