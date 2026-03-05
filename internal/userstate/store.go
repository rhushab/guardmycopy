package userstate

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	defaultStateDirName  = "guardmycopy"
	defaultStateFileName = "state.json"
	defaultStateDirMode  = 0o700
	defaultStateFileMode = 0o600
)

type State struct {
	SnoozedUntil time.Time `json:"snoozed_until,omitempty"`
	AllowOnce    bool      `json:"allow_once"`
}

func (s State) ActiveSnoozedUntil(now time.Time) (time.Time, bool) {
	if s.SnoozedUntil.IsZero() || !s.SnoozedUntil.After(now) {
		return time.Time{}, false
	}
	return s.SnoozedUntil, true
}

func (s State) SnoozeActive(now time.Time) bool {
	_, ok := s.ActiveSnoozedUntil(now)
	return ok
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

	return filepath.Join(configDir, defaultStateDirName, defaultStateFileName), nil
}

func (s *Store) Path() string {
	return s.path
}

func (s *Store) Load() (State, error) {
	data, err := os.ReadFile(s.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return State{}, nil
		}
		return State{}, fmt.Errorf("read state file: %w", err)
	}

	var state State
	if err := json.Unmarshal(data, &state); err != nil {
		return State{}, fmt.Errorf("parse state file: %w", err)
	}

	return state, nil
}

func (s *Store) Save(state State) error {
	if err := os.MkdirAll(filepath.Dir(s.path), defaultStateDirMode); err != nil {
		return fmt.Errorf("create state directory: %w", err)
	}

	payload, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal state: %w", err)
	}
	payload = append(payload, '\n')

	if err := os.WriteFile(s.path, payload, defaultStateFileMode); err != nil {
		return fmt.Errorf("write state file: %w", err)
	}

	return nil
}
