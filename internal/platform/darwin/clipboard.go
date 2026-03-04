package darwin

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

type Clipboard struct{}

func NewClipboard() *Clipboard {
	return &Clipboard{}
}

func (c *Clipboard) ReadText() (string, error) {
	out, err := exec.Command("pbpaste").Output()
	if err != nil {
		return "", fmt.Errorf("pbpaste failed: %w", err)
	}
	return string(out), nil
}

func (c *Clipboard) WriteText(value string) error {
	cmd := exec.Command("pbcopy")
	cmd.Stdin = strings.NewReader(value)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("pbcopy failed: %w", err)
	}
	return nil
}

type ForegroundApp struct{}

func NewForegroundApp() *ForegroundApp {
	return &ForegroundApp{}
}

func (f *ForegroundApp) ActiveAppName() (string, error) {
	script := `tell application "System Events" to get name of first application process whose frontmost is true`
	out, err := exec.Command("osascript", "-e", script).Output()
	if err != nil {
		return "", fmt.Errorf("osascript active app failed: %w", err)
	}
	return cleanAppName(string(out)), nil
}

type Notifier struct{}

func NewNotifier() *Notifier {
	return &Notifier{}
}

func (n *Notifier) Notify(title, body string) error {
	displayBody := strings.TrimSpace(body)
	if displayBody == "" {
		displayBody = strings.TrimSpace(title)
	}

	if displayBody == "" {
		displayBody = "Clipboard event detected."
	}

	script := fmt.Sprintf(
		"display notification %s with title %s",
		strconv.Quote(displayBody),
		strconv.Quote("Clipguard"),
	)

	if err := exec.Command("osascript", "-e", script).Run(); err != nil {
		return fmt.Errorf("osascript notification failed: %w", err)
	}
	return nil
}

func cleanAppName(raw string) string {
	appName := strings.TrimSpace(raw)
	appName = strings.Trim(appName, `"`)
	return strings.Join(strings.Fields(appName), " ")
}
