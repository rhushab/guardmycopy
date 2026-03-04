package platform

import (
	"runtime"
	"strings"
	"testing"
)

func TestSelect(t *testing.T) {
	adapters, err := Select()

	if runtime.GOOS == "darwin" {
		if err != nil {
			t.Fatalf("expected darwin adapters, got error: %v", err)
		}
		if adapters.Clipboard == nil || adapters.ForegroundApp == nil || adapters.Notifier == nil {
			t.Fatal("expected all adapters to be initialized on darwin")
		}
		return
	}

	if err == nil {
		t.Fatalf("expected unsupported OS error on %s", runtime.GOOS)
	}
	if !strings.Contains(err.Error(), "unsupported OS") {
		t.Fatalf("expected unsupported OS message, got: %v", err)
	}
}
