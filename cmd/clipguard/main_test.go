package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRunSanitizeWithIO(t *testing.T) {
	input := "hello\n-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----\nworld"
	want := "hello\n---******* ******* ********\n***\n******** ******* *****---\nworld"

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := runSanitizeWithIO(nil, strings.NewReader(input), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}
	if stdout.String() != want {
		t.Fatalf("unexpected stdout: got %q want %q", stdout.String(), want)
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected empty stderr, got %q", stderr.String())
	}
}

func TestRunSanitizeWithIODiff(t *testing.T) {
	input := "hello\n-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----\nworld"

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := runSanitizeWithIO([]string{"--diff"}, strings.NewReader(input), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}

	if !strings.Contains(stderr.String(), "findings=1") {
		t.Fatalf("expected findings summary in stderr, got %q", stderr.String())
	}
	if !strings.Contains(stderr.String(), "risk=high") {
		t.Fatalf("expected risk level in stderr, got %q", stderr.String())
	}
	if !strings.Contains(stderr.String(), "score=15") {
		t.Fatalf("expected score in stderr, got %q", stderr.String())
	}
	if !strings.Contains(stderr.String(), "detectors: pem_private_key") {
		t.Fatalf("expected detectors line in stderr, got %q", stderr.String())
	}
	if !strings.Contains(stderr.String(), "before:") {
		t.Fatalf("expected before block in stderr, got %q", stderr.String())
	}
	if !strings.Contains(stderr.String(), "after:") {
		t.Fatalf("expected after block in stderr, got %q", stderr.String())
	}
	if !strings.Contains(stdout.String(), "---******* ******* ********") {
		t.Fatalf("expected redaction in stdout, got %q", stdout.String())
	}
}

func TestRunSanitizeWithIORejectsPositionalArgs(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := runSanitizeWithIO([]string{"unexpected"}, strings.NewReader("hello"), &stdout, &stderr)
	if code != 2 {
		t.Fatalf("expected exit code 2, got %d", code)
	}
	if !strings.Contains(stderr.String(), "sanitize does not accept positional arguments") {
		t.Fatalf("expected argument error, got %q", stderr.String())
	}
}
