package auditlog

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestStoreLogAndTail(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	store, err := New(path)
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}

	baseTime := time.Unix(1_700_000_000, 0).UTC()
	for i := 0; i < 3; i++ {
		if err := store.Log(Entry{
			Timestamp:    baseTime.Add(time.Duration(i) * time.Second),
			App:          "Terminal",
			Score:        i + 1,
			RiskLevel:    "med",
			FindingTypes: []string{"jwt"},
			Action:       "sanitize",
			ContentHash:  "abc123",
		}); err != nil {
			t.Fatalf("Log returned error: %v", err)
		}
	}

	lines, err := store.Tail(2)
	if err != nil {
		t.Fatalf("Tail returned error: %v", err)
	}
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines, got %d", len(lines))
	}

	var first Entry
	if err := json.Unmarshal([]byte(lines[0]), &first); err != nil {
		t.Fatalf("unmarshal first line: %v", err)
	}
	if first.Score != 2 {
		t.Fatalf("expected first tailed score=2, got %d", first.Score)
	}
	if strings.Contains(lines[0], "raw-clipboard-text") || strings.Contains(lines[1], "raw-clipboard-text") {
		t.Fatal("audit log unexpectedly contains raw clipboard text")
	}

	var second Entry
	if err := json.Unmarshal([]byte(lines[1]), &second); err != nil {
		t.Fatalf("unmarshal second line: %v", err)
	}
	if second.Score != 3 {
		t.Fatalf("expected second tailed score=3, got %d", second.Score)
	}
}

func TestStoreTailMissingFileReturnsEmpty(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	store, err := New(path)
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}

	lines, err := store.Tail(50)
	if err != nil {
		t.Fatalf("Tail returned error: %v", err)
	}
	if len(lines) != 0 {
		t.Fatalf("expected no lines, got %d", len(lines))
	}
}

func TestStoreTailRejectsNonPositiveCount(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	store, err := New(path)
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}

	if _, err := store.Tail(0); err == nil {
		t.Fatal("expected error for tail count <= 0")
	}
}

func TestStoreLogSchemaDoesNotIncludeRawClipboardContent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	store, err := New(path)
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}

	if err := store.Log(Entry{
		App:          "Terminal",
		Score:        42,
		RiskLevel:    "high",
		FindingTypes: []string{"pem_private_key"},
		Action:       "block",
		ContentHash:  "hash-value",
	}); err != nil {
		t.Fatalf("Log returned error: %v", err)
	}

	lines, err := store.Tail(1)
	if err != nil {
		t.Fatalf("Tail returned error: %v", err)
	}
	if len(lines) != 1 {
		t.Fatalf("expected one line, got %d", len(lines))
	}

	var payload map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &payload); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}

	for _, disallowed := range []string{"clipboard", "content", "raw", "text", "sanitized"} {
		if _, ok := payload[disallowed]; ok {
			t.Fatalf("unexpected raw clipboard field %q in audit payload", disallowed)
		}
	}
}
