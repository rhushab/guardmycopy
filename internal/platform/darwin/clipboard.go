package darwin

import (
	"fmt"
	"os/exec"
	"strings"
)

type Clipboard struct{}

func NewClipboard() *Clipboard {
	return &Clipboard{}
}

func (c *Clipboard) Read() (string, error) {
	out, err := exec.Command("pbpaste").Output()
	if err != nil {
		return "", fmt.Errorf("pbpaste failed: %w", err)
	}
	return string(out), nil
}

func (c *Clipboard) Write(value string) error {
	cmd := exec.Command("pbcopy")
	cmd.Stdin = strings.NewReader(value)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("pbcopy failed: %w", err)
	}
	return nil
}

func ActiveApp() (string, error) {
	script := `tell application "System Events" to get name of first application process whose frontmost is true`
	out, err := exec.Command("osascript", "-e", script).Output()
	if err != nil {
		return "", fmt.Errorf("osascript active app failed: %w", err)
	}
	return strings.TrimSpace(string(out)), nil
}

func Notify(title, message string) error {
	script := fmt.Sprintf(
		`display notification "%s" with title "%s"`,
		escapeAppleScript(message),
		escapeAppleScript(title),
	)
	if err := exec.Command("osascript", "-e", script).Run(); err != nil {
		return fmt.Errorf("osascript notification failed: %w", err)
	}
	return nil
}

func escapeAppleScript(input string) string {
	escaped := strings.ReplaceAll(input, `\`, `\\`)
	return strings.ReplaceAll(escaped, `"`, `\"`)
}
