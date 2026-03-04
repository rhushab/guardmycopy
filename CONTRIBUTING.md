# Contributing

Thanks for contributing to guardmycopy.

## Development Requirements

- Go 1.22+
- macOS for full runtime/manual validation (`pbpaste`/`pbcopy`/`osascript` paths)

## Local Setup

```bash
go mod download
make fmt
make vet
make test
```

## Coding Guidelines

- Keep the project local-only: no telemetry, analytics, or network calls.
- Never persist raw clipboard text to disk.
- Keep defaults safe (`high` risk should remain strict by default).
- Prefer small, focused pull requests with tests.

## Detector Changes

When adding or modifying detectors:

1. Add both true-positive and false-positive tests.
2. Ensure redaction still preserves basic text shape (format-preserving behavior).
3. Avoid printing raw secret values in logs, verbose output, or test snapshots.
4. Document detector behavior and tradeoffs in PR notes.

## Test and Validation Checklist

Run before opening a PR:

```bash
make ci
```

This runs formatting checks, unit tests, vetting, optional staticcheck, and build.

## Pull Request Expectations

- Include motivation and security impact summary.
- Include config/behavior changes and migration notes if defaults changed.
- Add docs updates for any user-visible changes.
