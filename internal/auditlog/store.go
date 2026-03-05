package auditlog

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	defaultAuditDirName  = "guardmycopy"
	defaultAuditFileName = "audit.jsonl"
	defaultAuditDirMode  = 0o700
	defaultAuditFileMode = 0o600
)

type Entry struct {
	Timestamp    time.Time           `json:"timestamp"`
	App          string              `json:"app"`
	Score        int                 `json:"score"`
	RiskLevel    string              `json:"riskLevel"`
	FindingTypes []string            `json:"findingTypes"`
	Action       string              `json:"action"`
	ContentHash  string              `json:"contentHash"`
	AppContext   *AppContextMetadata `json:"appContext,omitempty"`
}

type AppContextMetadata struct {
	Status       string `json:"status"`
	PolicySource string `json:"policySource,omitempty"`
	Error        string `json:"error,omitempty"`
}

type Store struct {
	path string
}

func New(path string) (*Store, error) {
	resolvedPath := strings.TrimSpace(path)
	if resolvedPath == "" {
		defaultPath, err := DefaultPath()
		if err != nil {
			return nil, err
		}
		resolvedPath = defaultPath
	}

	return &Store{path: resolvedPath}, nil
}

func DefaultPath() (string, error) {
	configDir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("resolve user config dir: %w", err)
	}
	if strings.TrimSpace(configDir) == "" {
		return "", errors.New("user config dir is empty")
	}

	return filepath.Join(configDir, defaultAuditDirName, defaultAuditFileName), nil
}

func (s *Store) Path() string {
	return s.path
}

func (s *Store) Log(entry Entry) error {
	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now().UTC()
	} else {
		entry.Timestamp = entry.Timestamp.UTC()
	}

	if err := os.MkdirAll(filepath.Dir(s.path), defaultAuditDirMode); err != nil {
		return fmt.Errorf("create audit log directory: %w", err)
	}

	payload, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("marshal audit entry: %w", err)
	}
	payload = append(payload, '\n')

	file, err := os.OpenFile(s.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, defaultAuditFileMode)
	if err != nil {
		return fmt.Errorf("open audit log: %w", err)
	}
	defer file.Close()

	if _, err := file.Write(payload); err != nil {
		return fmt.Errorf("write audit log: %w", err)
	}

	return nil
}

func (s *Store) Tail(lineCount int) ([]string, error) {
	if lineCount <= 0 {
		return nil, errors.New("tail line count must be > 0")
	}

	file, err := os.Open(s.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("open audit log: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	buffer := make([]string, lineCount)
	total := 0
	for scanner.Scan() {
		buffer[total%lineCount] = scanner.Text()
		total++
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan audit log: %w", err)
	}

	if total == 0 {
		return nil, nil
	}
	if total <= lineCount {
		return append([]string(nil), buffer[:total]...), nil
	}

	start := total % lineCount
	out := make([]string, 0, lineCount)
	out = append(out, buffer[start:]...)
	out = append(out, buffer[:start]...)
	return out, nil
}
