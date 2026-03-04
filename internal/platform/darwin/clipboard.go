package darwin

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

const commandTimeout = 2 * time.Second

type Clipboard struct{}

func NewClipboard() *Clipboard {
	return &Clipboard{}
}

func (c *Clipboard) ReadText() (string, error) {
	out, err := commandOutput("pbpaste")
	if err != nil {
		return "", fmt.Errorf("pbpaste failed: %w", err)
	}
	return string(out), nil
}

func (c *Clipboard) WriteText(value string) error {
	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "pbcopy")
	cmd.Stdin = strings.NewReader(value)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("pbcopy failed: %w", commandErr("pbcopy", err, ctx.Err()))
	}
	return nil
}

type ForegroundApp struct{}

func NewForegroundApp() *ForegroundApp {
	return &ForegroundApp{}
}

func (f *ForegroundApp) ActiveAppName() (string, error) {
	script := `tell application "System Events" to get name of first application process whose frontmost is true`
	out, err := commandOutput("osascript", "-e", script)
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

	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()

	if err := exec.CommandContext(ctx, "osascript", "-e", script).Run(); err != nil {
		return fmt.Errorf("osascript notification failed: %w", commandErr("osascript", err, ctx.Err()))
	}
	return nil
}

func cleanAppName(raw string) string {
	appName := strings.TrimSpace(raw)
	appName = strings.Trim(appName, `"`)
	return strings.Join(strings.Fields(appName), " ")
}

func commandOutput(name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()

	out, err := exec.CommandContext(ctx, name, args...).Output()
	if err != nil {
		return nil, commandErr(name, err, ctx.Err())
	}
	return out, nil
}

func commandErr(name string, err error, ctxErr error) error {
	if errors.Is(ctxErr, context.DeadlineExceeded) {
		return fmt.Errorf("%s timed out after %s", name, commandTimeout)
	}
	return err
}
