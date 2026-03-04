package platform

import (
	"fmt"
	"runtime"

	"github.com/rhushabhbontapalle/clipguard/internal/platform/darwin"
)

type Adapters struct {
	Clipboard     Clipboard
	ForegroundApp ForegroundApp
	Notifier      Notifier
}

func Select() (Adapters, error) {
	if runtime.GOOS != "darwin" {
		return Adapters{}, fmt.Errorf(
			"unsupported OS %q: clipguard currently supports macOS (darwin) only",
			runtime.GOOS,
		)
	}

	return Adapters{
		Clipboard:     darwin.NewClipboard(),
		ForegroundApp: darwin.NewForegroundApp(),
		Notifier:      darwin.NewNotifier(),
	}, nil
}
