package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"
)

const defaultPollInterval = 500 * time.Millisecond

type Config struct {
	PollInterval time.Duration
}

type fileConfig struct {
	PollIntervalMS int `json:"poll_interval_ms"`
}

func Defaults() Config {
	return Config{
		PollInterval: defaultPollInterval,
	}
}

func Load(path string) (Config, error) {
	cfg := Defaults()
	if path == "" {
		return cfg, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config file: %w", err)
	}

	var fromFile fileConfig
	if err := json.Unmarshal(data, &fromFile); err != nil {
		return Config{}, fmt.Errorf("parse config file: %w", err)
	}

	if fromFile.PollIntervalMS < 0 {
		return Config{}, errors.New("poll_interval_ms must be >= 0")
	}
	if fromFile.PollIntervalMS > 0 {
		cfg.PollInterval = time.Duration(fromFile.PollIntervalMS) * time.Millisecond
	}

	return cfg, nil
}
