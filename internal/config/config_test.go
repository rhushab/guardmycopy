package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadDefaults(t *testing.T) {
	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if cfg.PollInterval != 500*time.Millisecond {
		t.Fatalf("unexpected default interval: %v", cfg.PollInterval)
	}
}

func TestLoadFromFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "clipguard.json")

	if err := os.WriteFile(path, []byte(`{"poll_interval_ms": 1250}`), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if cfg.PollInterval != 1250*time.Millisecond {
		t.Fatalf("unexpected interval: %v", cfg.PollInterval)
	}
}

func TestLoadRejectsNegativeInterval(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "clipguard.json")

	if err := os.WriteFile(path, []byte(`{"poll_interval_ms": -1}`), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	if _, err := Load(path); err == nil {
		t.Fatal("expected error for negative poll_interval_ms")
	}
}
