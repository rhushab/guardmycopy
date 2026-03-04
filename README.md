# clipguard

`clipguard` is a macOS-only MVP clipboard firewall written in Go. It runs locally and uses:
- `pbpaste` / `pbcopy` for clipboard reads and writes
- `osascript` helpers for active-app lookup and notifications

No server, database, or network calls are used.

Current detectors:
- PEM private key blocks
- JWT-like tokens (`header.payload.signature`)
- Env-style secrets (`KEY=VALUE` for secret-like key names)
- High-entropy long tokens

## Build

```bash
go build ./cmd/clipguard
```

Or via Makefile:

```bash
make build
```

## Run

Sanitize text from stdin:

```bash
cat input.txt | ./clipguard sanitize
```

Show findings summary, risk/score, triggered detectors, and before/after on stderr while writing sanitized text to stdout:

```bash
cat input.txt | ./clipguard sanitize --diff
```

Run polling mode:

```bash
./clipguard run
```

Run polling mode with custom interval (ms):

```bash
./clipguard run --interval 250
```

Print version:

```bash
./clipguard --version
```

Use a JSON config file (optional):

```json
{
  "poll_interval_ms": 500
}
```

Commands accept `--config /path/to/config.json`.

## Test

```bash
go test ./...
```

Or via Makefile:

```bash
make test
```
